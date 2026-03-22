package com.juanma0511.rootdetector.ui

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

enum class ThemeMode { SYSTEM, LIGHT, DARK }

private val LightColors = lightColorScheme(
    primary            = Color(0xFF1565C0),
    onPrimary          = Color.White,
    primaryContainer   = Color(0xFFDCE8FF),
    onPrimaryContainer = Color(0xFF001849),
    secondary          = Color(0xFF555F71),
    secondaryContainer = Color(0xFFD9E3F8),
    tertiary           = Color(0xFFE65100),
    tertiaryContainer  = Color(0xFFFFDBC8),
    error              = Color(0xFFB71C1C),
    errorContainer     = Color(0xFFFFDAD6),
    surface            = Color(0xFFFAFAFF),
    surfaceVariant     = Color(0xFFE1E2EC),
)

private val DarkColors = darkColorScheme(
    primary            = Color(0xFF90CAF9),
    onPrimary          = Color(0xFF003064),
    primaryContainer   = Color(0xFF004494),
    onPrimaryContainer = Color(0xFFD6E3FF),
    secondary          = Color(0xFFBBC7DB),
    secondaryContainer = Color(0xFF3D4758),
    tertiary           = Color(0xFFFFB77C),
    tertiaryContainer  = Color(0xFFB23C00),
    error              = Color(0xFFFF6B6B),
    errorContainer     = Color(0xFF930006),
    surface            = Color(0xFF111318),
    surfaceVariant     = Color(0xFF43474E),
)

@Suppress("DEPRECATION")
@Composable
fun RootDetectorTheme(
    themeMode: ThemeMode = ThemeMode.SYSTEM,
    content: @Composable () -> Unit
) {
    val systemDark = isSystemInDarkTheme()
    val isDark = when (themeMode) {
        ThemeMode.DARK   -> true
        ThemeMode.LIGHT  -> false
        ThemeMode.SYSTEM -> systemDark
    }

    val colorScheme = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val ctx = LocalContext.current
            if (isDark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        }
        isDark -> DarkColors
        else   -> LightColors
    }

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.surface.toArgb()
            WindowCompat.getInsetsController(window, view)
                .isAppearanceLightStatusBars = !isDark
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography  = Typography(),
        content     = content
    )
}
