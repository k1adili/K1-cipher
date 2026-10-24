package com.k1adili.k1cipher.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.k1adili.k1cipher.BuildConfig
import com.k1adili.k1cipher.MainViewModel
import com.k1adili.k1cipher.PendingOp
import com.k1adili.k1cipher.R

private val Vazir = FontFamily(Font(R.font.vazirmatn_regular))
private val BoxShape = RoundedCornerShape(15.dp)
private val ButtonShape = RoundedCornerShape(15.dp)

@Composable
fun MainScreen(
    vm: MainViewModel,
    onShare: () -> Unit,
    onSave: () -> Unit,
    onReadFile: () -> Unit,
) {
    // The design is an English, left-to-right layout: keep it identical on every device locale.
    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
        BoxWithConstraints(
            Modifier
                .fillMaxSize()
                .background(K1.Bg)
                .systemBarsPadding()
                .imePadding()
        ) {
            val scale = (maxWidth / 360.dp).coerceIn(0.8f, 1.3f)
            val busy = vm.busy
            val canClear = vm.plain.isNotEmpty() || vm.encrypted.isNotEmpty()

            Column(
                Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 30.dp)
                    .padding(top = 8.dp, bottom = 16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    "K1 Cipher",
                    color = K1.Blue,
                    fontSize = (56f * scale).sp,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    softWrap = false,
                )
                Text(
                    "Encrypt and decrypt your text and share\nto other app or save in file",
                    color = K1.Subtitle,
                    fontSize = 16.sp,
                    lineHeight = 23.sp,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(22.dp))

                CipherField(
                    value = vm.plain,
                    onValueChange = { vm.plain = it },
                    hint = "Normal or Decrypt Text",
                    color = K1.Blue,
                )
                Spacer(Modifier.height(7.dp))
                CipherField(
                    value = vm.encrypted,
                    onValueChange = { vm.encrypted = it },
                    hint = "Encrypt text",
                    color = K1.Teal,
                )
                Spacer(Modifier.height(8.dp))

                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 3.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    K1Button("ENCRYPT", K1.Teal, enabled = !busy, onClick = vm::requestEncrypt)
                    K1Button("DECRYPT", K1.Blue, enabled = !busy, onClick = vm::requestDecrypt)
                    K1Button("Share", K1.Yellow, enabled = !busy, onClick = onShare)
                }
                Spacer(Modifier.height(10.dp))
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 3.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    K1Button("SAVE", K1.Blue, enabled = !busy, onClick = onSave)
                    K1Button("READ FILE", K1.Blue, enabled = !busy, onClick = onReadFile)
                    K1Button(
                        "CLEAR", K1.ClearActive,
                        enabled = canClear && !busy,
                        onClick = vm::clearAll,
                    )
                }

                Spacer(Modifier.height(14.dp))
                Text(
                    "Developer: Keyvan Adili\nversion: ${BuildConfig.VERSION_NAME}",
                    color = K1.Footer,
                    fontSize = 10.sp,
                    lineHeight = 12.sp,
                    textAlign = TextAlign.Center,
                )
            }

            if (busy) {
                Box(
                    Modifier
                        .fillMaxSize()
                        .background(Color(0x66000000))
                        .clickable(enabled = true, onClick = {}),
                    contentAlignment = Alignment.Center,
                ) { CircularProgressIndicator(color = K1.Teal) }
            }
        }

        vm.pending?.let { op ->
            PasswordDialog(
                confirm = op == PendingOp.ENCRYPT,
                onDismiss = vm::cancelPassword,
                onOk = vm::onPassword,
            )
        }
    }
}

@Composable
private fun CipherField(
    value: String,
    onValueChange: (String) -> Unit,
    hint: String,
    color: Color,
) {
    Box(
        Modifier
            .fillMaxWidth()
            .height(122.dp)
            .clip(BoxShape)
            .background(K1.Box)
            .border(1.7.dp, color, BoxShape)
            .padding(horizontal = 15.dp, vertical = 12.dp)
    ) {
        BasicTextField(
            value = value,
            onValueChange = onValueChange,
            modifier = Modifier.fillMaxSize(),
            textStyle = TextStyle(
                color = K1.InputText,
                fontSize = 15.sp,
                lineHeight = 24.sp,
                fontFamily = Vazir,
                textDirection = TextDirection.Content,
                textAlign = TextAlign.Start,
            ),
            cursorBrush = SolidColor(color),
        )
        if (value.isEmpty()) {
            Text(hint, color = color, fontSize = 15.sp, fontFamily = Vazir)
        }
    }
}

@Composable
private fun K1Button(
    text: String,
    color: Color,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    val borderColor = if (enabled) color else K1.Box
    val textColor = if (enabled) color else K1.DisabledText
    // Fixed-size 85dp tiles: ignore the system font scale so labels never wrap.
    CompositionLocalProvider(LocalDensity provides Density(LocalDensity.current.density, 1f)) {
        Box(
            Modifier
                .size(85.dp)
                .clip(ButtonShape)
                .border(3.3.dp, borderColor, ButtonShape)
                .clickable(enabled = enabled, role = Role.Button, onClick = onClick),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text,
                color = textColor,
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold,
                maxLines = 1,
                softWrap = false,
                overflow = TextOverflow.Clip,
            )
        }
    }
}
