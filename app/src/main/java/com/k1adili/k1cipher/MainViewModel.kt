package com.k1adili.k1cipher

import android.app.Application
import android.net.Uri
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.k1adili.k1cipher.crypto.K1Crypto
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.InputStream

enum class PendingOp { ENCRYPT, DECRYPT }

class MainViewModel(app: Application) : AndroidViewModel(app) {

    /** Top box: normal text to encrypt, or the result of a decryption. */
    var plain by mutableStateOf("")

    /** Bottom box: encrypted token (result of encryption, input of decryption). */
    var encrypted by mutableStateOf("")

    var busy by mutableStateOf(false)
        private set
    var pending by mutableStateOf<PendingOp?>(null)
        private set

    private val _messages = MutableSharedFlow<String>(extraBufferCapacity = 8)
    val messages: SharedFlow<String> = _messages

    private fun say(msg: String) {
        _messages.tryEmit(msg)
    }

    // ---------- buttons ----------

    fun requestEncrypt() {
        when {
            plain.isEmpty() -> say("Type or paste some text first")
            plain.length > K1Crypto.MAX_PLAIN_CHARS -> say("Text is too long")
            else -> pending = PendingOp.ENCRYPT
        }
    }

    fun requestDecrypt() {
        if (decryptSource() == null) say("Paste or load encrypted text first") else pending = PendingOp.DECRYPT
    }

    fun cancelPassword() {
        pending = null
    }

    fun clearAll() {
        plain = ""
        encrypted = ""
    }

    /** Called by the password dialog. Takes ownership of [pw] and wipes it when done. */
    fun onPassword(pw: CharArray) {
        val op = pending
        pending = null
        if (op == null || busy) {
            pw.fill('\u0000')
            return
        }
        busy = true
        val textToEncrypt = plain
        val tokenToDecrypt = decryptSource()
        viewModelScope.launch {
            try {
                val result: Result<String> = withContext(Dispatchers.Default) {
                    runCatching {
                        when (op) {
                            PendingOp.ENCRYPT -> K1Crypto.toToken(K1Crypto.encrypt(textToEncrypt, pw))
                            PendingOp.DECRYPT -> {
                                val bytes = K1Crypto.fromToken(tokenToDecrypt.orEmpty())
                                    ?: throw K1Crypto.InvalidFormatException()
                                K1Crypto.decrypt(bytes, pw)
                            }
                        }
                    }
                }
                result.onSuccess { out ->
                    if (op == PendingOp.ENCRYPT) {
                        encrypted = out
                    } else {
                        encrypted = tokenToDecrypt.orEmpty()
                        plain = out
                    }
                }.onFailure { e ->
                    say(
                        when (e) {
                            is K1Crypto.WrongPasswordException -> "Wrong password, or the text was modified"
                            is K1Crypto.InvalidFormatException -> "This is not valid K1 Cipher text"
                            else -> "Operation failed"
                        }
                    )
                }
            } finally {
                pw.fill('\u0000')
                busy = false
            }
        }
    }

    /** The encrypted text may have been pasted into either box. */
    private fun decryptSource(): String? =
        listOf(encrypted, plain).firstOrNull { it.isNotBlank() && K1Crypto.looksEncrypted(it) }

    // ---------- incoming text (Share / "Process text" from other apps) ----------

    fun receive(text: String) {
        val t = text.trim()
        if (t.isEmpty()) return
        if (K1Crypto.looksEncrypted(t)) {
            encrypted = t.filterNot { it.isWhitespace() }
            say("Encrypted text received – press DECRYPT")
        } else {
            plain = t
            say("Text received – press ENCRYPT")
        }
    }

    /** Text scanned from a QR code: accepted only if it is K1 Cipher text. */
    fun receiveQr(text: String) {
        val t = text.filterNot { it.isWhitespace() }
        if (K1Crypto.looksEncrypted(t)) {
            encrypted = t
            say("QR code scanned – press DECRYPT")
        } else {
            say("This QR code is not K1 Cipher text")
        }
    }

    // ---------- share / files ----------

    fun shareText(): String? {
        val t = encrypted.trim()
        return if (t.isEmpty()) {
            say("Nothing to share – encrypt something first")
            null
        } else t
    }

    fun canSave(): Boolean {
        if (K1Crypto.fromToken(encrypted) == null) {
            say("Nothing to save – encrypt something first")
            return false
        }
        return true
    }

    /** Saves the (already encrypted) container as raw bytes. Plain text is never written. */
    fun saveTo(uri: Uri) {
        val bytes = K1Crypto.fromToken(encrypted)
        if (bytes == null) {
            say("Nothing to save – encrypt something first")
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val out = getApplication<Application>().contentResolver.openOutputStream(uri, "wt")
                    ?: throw IllegalStateException("no stream")
                out.use { it.write(bytes) }
                say("File saved")
            } catch (e: Exception) {
                say("Could not save the file")
            }
        }
    }

    fun readFrom(uri: Uri) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val input = getApplication<Application>().contentResolver.openInputStream(uri)
                    ?: throw IllegalStateException("no stream")
                val data = input.use { readLimited(it, MAX_FILE_BYTES) }
                // Binary container, or a text file that contains the token
                val token = if (K1Crypto.isContainer(data)) {
                    K1Crypto.toToken(data)
                } else {
                    val text = String(data, Charsets.UTF_8)
                    if (K1Crypto.looksEncrypted(text)) text.filterNot { it.isWhitespace() } else null
                }
                if (token == null) {
                    say("This is not a K1 Cipher file")
                } else {
                    withContext(Dispatchers.Main) { encrypted = token }
                    say("File loaded – press DECRYPT")
                }
            } catch (e: FileTooLargeException) {
                say("File is too large")
            } catch (e: Exception) {
                say("Could not read the file")
            }
        }
    }

    private class FileTooLargeException : Exception()

    private fun readLimited(input: InputStream, max: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        var total = 0
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            total += n
            if (total > max) throw FileTooLargeException()
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    private companion object {
        const val MAX_FILE_BYTES = 8 * 1024 * 1024
    }
}
