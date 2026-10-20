package com.keepcrypt.entropy.screens

/**
 * Every screen the app draws (tasks/todo.md, M5 group 6). The capture harness proves each one drawn
 * and then black in every capture; screenId's when is exhaustive, so a screen added here without an
 * id fails to compile. Until the ceremony screens arrive (commits 14-21) the only one is the static
 * development-build screen. In :screens' common code, beside the screens themselves.
 */
enum class Screen { FirstLaunch }

/** The screen's id, the capture harness's name for it. */
fun screenId(screen: Screen): String = when (screen) {
    Screen.FirstLaunch -> "first_launch"
}
