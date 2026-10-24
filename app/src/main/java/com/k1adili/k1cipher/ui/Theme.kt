package com.k1adili.k1cipher.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/** Colors sampled directly from the reference design. */
object K1 {
    val Bg = Color(0xFF5E5E5E)
    val Box = Color(0xFF535252)
    val Blue = Color(0xFF0096FF)
    val Teal = Color(0xFF00FFCC)
    val Yellow = Color(0xFFFFFF00)
    val Subtitle = Color(0xFFC2C2C2)
    val Footer = Color(0xFFC2C2C2)
    val DisabledText = Color(0xFF414141)
    val ClearActive = Color(0xFFFF5A5A)
    val InputText = Color(0xFFEAEAEA)
}

@Composable
fun K1Theme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = K1.Blue,
            onPrimary = K1.Bg,
            secondary = K1.Teal,
            background = K1.Bg,
            surface = K1.Box,
            onSurface = K1.InputText,
            onBackground = K1.InputText,
            error = K1.ClearActive,
        ),
        content = content,
    )
}
