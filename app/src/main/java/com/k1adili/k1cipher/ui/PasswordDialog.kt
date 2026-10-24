package com.k1adili.k1cipher.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy

private const val MIN_PASSWORD = 8

@Composable
fun PasswordDialog(
    confirm: Boolean,
    onDismiss: () -> Unit,
    onOk: (CharArray) -> Unit,
) {
    var pw by remember { mutableStateOf("") }
    var pw2 by remember { mutableStateOf("") }
    var visible by remember { mutableStateOf(false) }

    val tooShort = confirm && pw.isNotEmpty() && pw.length < MIN_PASSWORD
    val mismatch = confirm && pw2.isNotEmpty() && pw != pw2
    val valid = if (confirm) pw.length >= MIN_PASSWORD && pw == pw2 else pw.isNotEmpty()
    val transformation = if (visible) VisualTransformation.None else PasswordVisualTransformation()
    val keyboard = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false)
    val toggle: @Composable () -> Unit = {
        Text(
            if (visible) "HIDE" else "SHOW",
            color = K1.Blue,
            fontSize = 12.sp,
            modifier = Modifier.clickable { visible = !visible }.padding(8.dp),
        )
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
        containerColor = K1.Box,
        title = { Text(if (confirm) "Set password" else "Enter password", color = K1.Blue) },
        text = {
            Column {
                OutlinedTextField(
                    value = pw,
                    onValueChange = { pw = it },
                    label = { Text("Password") },
                    singleLine = true,
                    isError = tooShort,
                    supportingText = if (confirm) {
                        { Text("At least $MIN_PASSWORD characters – a long passphrase is best") }
                    } else null,
                    visualTransformation = transformation,
                    keyboardOptions = keyboard,
                    trailingIcon = toggle,
                )
                if (confirm) {
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = pw2,
                        onValueChange = { pw2 = it },
                        label = { Text("Repeat password") },
                        singleLine = true,
                        isError = mismatch,
                        supportingText = if (mismatch) {
                            { Text("Passwords do not match") }
                        } else null,
                        visualTransformation = transformation,
                        keyboardOptions = keyboard,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(enabled = valid, onClick = { onOk(pw.toCharArray()) }) {
                Text(if (confirm) "ENCRYPT" else "DECRYPT")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("CANCEL") } },
    )
}
