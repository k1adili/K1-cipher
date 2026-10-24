package com.k1adili.k1cipher.crypto

import android.util.Base64
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Password-based authenticated encryption.
 *
 *  - KDF   : Argon2id (v1.3), 64 MiB, 3 passes, random 16-byte salt per message
 *  - Cipher: AES-256-GCM, random 12-byte nonce, 128-bit tag
 *  - The whole header (magic, version, KDF params, salt, nonce) is authenticated as AAD
 *  - Plaintext is padded to a multiple of 64 bytes to hide its exact length
 *
 * Container layout (big endian):
 *   "K1C" | version(1) | memKiB(4) | iterations(1) | parallelism(1) | salt(16) | nonce(12) | ciphertext+tag
 */
object K1Crypto {

    class WrongPasswordException : Exception()
    class InvalidFormatException : Exception()

    private val MAGIC = byteArrayOf(0x4B, 0x31, 0x43) // "K1C"
    private const val VERSION: Byte = 1
    private const val SALT_LEN = 16
    private const val NONCE_LEN = 12
    private const val KEY_LEN = 32
    private const val TAG_BITS = 128
    private const val TAG_LEN = 16
    private const val HEADER_LEN = 3 + 1 + 4 + 1 + 1 + SALT_LEN + NONCE_LEN // 38
    private const val PAD_BLOCK = 64

    private const val MEM_KIB = 65_536
    private const val ITERATIONS = 3
    private const val PARALLELISM = 1

    // Accepted bounds when reading a container (protects against malicious headers)
    private val MEM_RANGE = 8_192..262_144
    private val ITER_RANGE = 1..10
    private val PAR_RANGE = 1..4

    const val MAX_PLAIN_CHARS = 1_000_000

    private val rng = SecureRandom()

    fun encrypt(plain: String, password: CharArray): ByteArray {
        val salt = ByteArray(SALT_LEN).also { rng.nextBytes(it) }
        val nonce = ByteArray(NONCE_LEN).also { rng.nextBytes(it) }
        val header = ByteBuffer.allocate(HEADER_LEN)
            .put(MAGIC).put(VERSION)
            .putInt(MEM_KIB).put(ITERATIONS.toByte()).put(PARALLELISM.toByte())
            .put(salt).put(nonce)
            .array()

        val key = deriveKey(password, salt, MEM_KIB, ITERATIONS, PARALLELISM)
        val raw = plain.toByteArray(Charsets.UTF_8)
        val padded = pad(raw)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(header)
            return header + cipher.doFinal(padded)
        } finally {
            key.fill(0); raw.fill(0); padded.fill(0)
        }
    }

    fun decrypt(data: ByteArray, password: CharArray): String {
        if (!isContainer(data)) throw InvalidFormatException()
        val bb = ByteBuffer.wrap(data)
        bb.position(4)
        val mem = bb.int
        val iter = bb.get().toInt() and 0xFF
        val par = bb.get().toInt() and 0xFF
        if (mem !in MEM_RANGE || iter !in ITER_RANGE || par !in PAR_RANGE) throw InvalidFormatException()
        val salt = ByteArray(SALT_LEN).also { bb.get(it) }
        val nonce = ByteArray(NONCE_LEN).also { bb.get(it) }
        val header = data.copyOfRange(0, HEADER_LEN)
        val body = data.copyOfRange(HEADER_LEN, data.size)

        val key = deriveKey(password, salt, mem, iter, par)
        var padded: ByteArray? = null
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(header)
            padded = try {
                cipher.doFinal(body)
            } catch (e: GeneralSecurityException) {
                throw WrongPasswordException() // bad tag: wrong password OR tampered data
            }
            val raw = unpad(padded) ?: throw InvalidFormatException()
            val text = String(raw, Charsets.UTF_8)
            raw.fill(0)
            return text
        } finally {
            key.fill(0); padded?.fill(0)
        }
    }

    // ---- text token (what is shown / shared) ----

    fun toToken(container: ByteArray): String =
        Base64.encodeToString(container, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    /** Returns the container bytes if [text] is a valid K1 Cipher token, else null. */
    fun fromToken(text: String): ByteArray? {
        val s = text.filterNot { it.isWhitespace() || it == '=' }
        if (s.isEmpty()) return null
        val bytes = try {
            Base64.decode(s, Base64.URL_SAFE or Base64.NO_PADDING)
        } catch (e: IllegalArgumentException) {
            return null
        }
        return if (isContainer(bytes)) bytes else null
    }

    fun looksEncrypted(text: String): Boolean = fromToken(text) != null

    fun isContainer(b: ByteArray): Boolean =
        b.size >= HEADER_LEN + TAG_LEN + 1 &&
            b[0] == MAGIC[0] && b[1] == MAGIC[1] && b[2] == MAGIC[2] && b[3] == VERSION

    // ---- internals ----

    private fun deriveKey(password: CharArray, salt: ByteArray, memKib: Int, iter: Int, par: Int): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withMemoryAsKB(memKib)
            .withIterations(iter)
            .withParallelism(par)
            .build()
        val gen = Argon2BytesGenerator()
        gen.init(params)
        val out = ByteArray(KEY_LEN)
        gen.generateBytes(password, out) // UTF-8 encoding of the password
        return out
    }

    private fun pad(b: ByteArray): ByteArray {
        val total = ((b.size + 1 + PAD_BLOCK - 1) / PAD_BLOCK) * PAD_BLOCK
        val out = ByteArray(total)
        b.copyInto(out)
        out[b.size] = 0x80.toByte()
        return out
    }

    private fun unpad(b: ByteArray): ByteArray? {
        var i = b.size - 1
        while (i >= 0 && b[i] == 0.toByte()) i--
        if (i < 0 || b[i] != 0x80.toByte()) return null
        return b.copyOf(i)
    }
}
