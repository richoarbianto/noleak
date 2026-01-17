/// CyberpunkTheme - Application Theme Definition
/// 
/// Defines the dark cyberpunk theme with neon green accents used
/// throughout the application. The theme is designed for:
/// - High contrast for readability
/// - Neon glow effects for visual appeal
/// - Consistent color palette across all components
/// 
/// Color Palette:
/// - Background: Near-black (#0A0A0A)
/// - Surface: Dark gray (#121212)
/// - Primary accent: Neon green (#00FF9C)
/// - Secondary accent: Cyan (#00D4FF)
/// - Error: Red (#FF4444)
/// - Warning: Orange (#FFAA00)

import 'package:flutter/material.dart';

/// Cyberpunk Green Dark Theme.
/// 
/// High contrast dark theme with neon green accents for a
/// futuristic, security-focused aesthetic.
class CyberpunkTheme {
  // Core Colors
  static const Color background = Color(0xFF0A0A0A);
  static const Color surface = Color(0xFF121212);
  static const Color surfaceLight = Color(0xFF1E1E1E);
  static const Color surfaceBorder = Color(0xFF2A2A2A);

  // Accent Colors
  static const Color neonGreen = Color(0xFF00FF9C);
  static const Color neonGreenDim = Color(0xFF00CC7D);
  static const Color cyan = Color(0xFF00D4FF);

  // Text Colors
  static const Color textPrimary = Color(0xFFFFFFFF);
  static const Color textSecondary = Color(0xFFB0B0B0);
  static const Color textHint = Color(0xFF707070);

  // Status Colors
  static const Color error = Color(0xFFFF4444);
  static const Color errorDim = Color(0xFFCC3333);
  static const Color warning = Color(0xFFFFAA00);
  static const Color success = Color(0xFF00FF9C);

  // Password Strength Colors
  static const Color strengthWeak = Color(0xFFFF4444);
  static const Color strengthFair = Color(0xFFFF8800);
  static const Color strengthGood = Color(0xFFFFDD00);
  static const Color strengthStrong = Color(0xFF00D4FF);
  static const Color strengthPerfect = Color(0xFF00FF9C);

  /// Get the complete ThemeData for the app
  static ThemeData get themeData {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      scaffoldBackgroundColor: background,
      primaryColor: neonGreen,
      colorScheme: const ColorScheme.dark(
        primary: neonGreen,
        secondary: cyan,
        surface: surface,
        error: error,
        onPrimary: background,
        onSecondary: background,
        onSurface: textPrimary,
        onError: textPrimary,
      ),
      // AppBar Theme
      appBarTheme: const AppBarTheme(
        backgroundColor: surface,
        foregroundColor: textPrimary,
        elevation: 0,
        centerTitle: true,
        titleTextStyle: TextStyle(
          color: textPrimary,
          fontSize: 20,
          fontWeight: FontWeight.w600,
          letterSpacing: 0.5,
        ),
        iconTheme: IconThemeData(color: neonGreen),
      ),
      // Card Theme
      cardTheme: CardTheme(
        color: surface,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: const BorderSide(color: surfaceBorder),
        ),
      ),
      // Input Decoration Theme
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: surfaceLight,
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: surfaceBorder),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: surfaceBorder),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: neonGreen, width: 2),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: error),
        ),
        focusedErrorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: error, width: 2),
        ),
        labelStyle: const TextStyle(color: textSecondary),
        hintStyle: const TextStyle(color: textHint),
        errorStyle: const TextStyle(color: error),
      ),
      // Elevated Button Theme
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: neonGreen,
          foregroundColor: background,
          minimumSize: const Size(double.infinity, 56),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          textStyle: const TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.bold,
            letterSpacing: 1.0,
          ),
        ),
      ),
      // Outlined Button Theme
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: neonGreen,
          side: const BorderSide(color: neonGreen, width: 1.5),
          minimumSize: const Size(double.infinity, 56),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          textStyle: const TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
      // Text Button Theme
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          foregroundColor: neonGreen,
        ),
      ),
      // Icon Theme
      iconTheme: const IconThemeData(
        color: textSecondary,
      ),
      // Floating Action Button Theme
      floatingActionButtonTheme: const FloatingActionButtonThemeData(
        backgroundColor: neonGreen,
        foregroundColor: background,
      ),
      // Dialog Theme
      dialogTheme: DialogTheme(
        backgroundColor: surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: surfaceBorder),
        ),
        titleTextStyle: const TextStyle(
          color: textPrimary,
          fontSize: 20,
          fontWeight: FontWeight.w600,
        ),
        contentTextStyle: const TextStyle(
          color: textSecondary,
          fontSize: 16,
        ),
      ),
      // Bottom Sheet Theme
      bottomSheetTheme: const BottomSheetThemeData(
        backgroundColor: surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
        ),
      ),
      // Snackbar Theme
      snackBarTheme: SnackBarThemeData(
        backgroundColor: surfaceLight,
        contentTextStyle: const TextStyle(color: textPrimary),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
        ),
        behavior: SnackBarBehavior.floating,
      ),
      // Divider Theme
      dividerTheme: const DividerThemeData(
        color: surfaceBorder,
        thickness: 1,
      ),
      // Progress Indicator Theme
      progressIndicatorTheme: const ProgressIndicatorThemeData(
        color: neonGreen,
        linearTrackColor: surfaceLight,
        circularTrackColor: surfaceLight,
      ),
      // List Tile Theme
      listTileTheme: const ListTileThemeData(
        iconColor: textSecondary,
        textColor: textPrimary,
        subtitleTextStyle: TextStyle(color: textSecondary),
      ),
      // Checkbox Theme
      checkboxTheme: CheckboxThemeData(
        fillColor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) {
            return neonGreen;
          }
          return Colors.transparent;
        }),
        checkColor: WidgetStateProperty.all(background),
        side: const BorderSide(color: textSecondary),
      ),
      // Switch Theme
      switchTheme: SwitchThemeData(
        thumbColor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) {
            return neonGreen;
          }
          return textSecondary;
        }),
        trackColor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) {
            return neonGreen.withOpacity(0.3);
          }
          return surfaceLight;
        }),
      ),
    );
  }
}
