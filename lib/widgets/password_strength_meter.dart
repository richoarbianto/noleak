/// PasswordStrengthMeter - Visual Password Strength Indicator
/// 
/// Analyzes password strength and displays a visual indicator with:
/// - Animated progress bar with gradient colors
/// - Strength label (Weak/Fair/Good/Strong/Perfect)
/// - Estimated crack time based on entropy calculation
/// 
/// The strength calculation considers:
/// - Password length (minimum 12 characters recommended)
/// - Character variety (lowercase, uppercase, numbers, symbols)
/// - Common patterns and dictionary words (reduces score)
/// 
/// Crack time estimation uses realistic entropy calculation assuming
/// 10^10 attempts per second (modern GPU attack rate).

import 'dart:math';
import 'package:flutter/material.dart';
import '../theme/cyberpunk_theme.dart';

/// Password strength levels from weakest to strongest.
enum PasswordStrength {
  empty,
  weak,
  fair,
  good,
  strong,
  perfect,
}

/// Cyberpunk styled password strength meter with gradient colors
class PasswordStrengthMeter extends StatelessWidget {
  final String password;
  final bool showLabel;
  final int minLength;

  const PasswordStrengthMeter({
    super.key,
    required this.password,
    this.showLabel = true,
    this.minLength = 12,
  });

  @override
  Widget build(BuildContext context) {
    final strength = _calculateStrength(password);
    final strengthValue = _getStrengthValue(strength);
    final strengthColor = _getStrengthColor(strength);
    final strengthLabel = _getStrengthLabel(strength);
    final crackTime = _estimateCrackTime(password);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SizedBox(height: 8),
        // Progress bar with glow
        AnimatedContainer(
          duration: const Duration(milliseconds: 300),
          height: 6,
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(3),
            boxShadow: strength != PasswordStrength.empty
                ? [
                    BoxShadow(
                      color: strengthColor.withOpacity(0.4),
                      blurRadius: 8,
                      spreadRadius: 0,
                    ),
                  ]
                : null,
          ),
          child: ClipRRect(
            borderRadius: BorderRadius.circular(3),
            child: Stack(
              children: [
                // Background track
                Container(
                  width: double.infinity,
                  color: CyberpunkTheme.surfaceLight,
                ),
                // Animated fill
                AnimatedFractionallySizedBox(
                  duration: const Duration(milliseconds: 300),
                  widthFactor: strengthValue,
                  child: Container(
                    decoration: BoxDecoration(
                      gradient: _getGradient(strength),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
        if (showLabel && password.isNotEmpty) ...[
          const SizedBox(height: 8),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                strengthLabel,
                style: TextStyle(
                  color: strengthColor,
                  fontSize: 12,
                  fontWeight: FontWeight.w500,
                ),
              ),
              if (password.length < minLength)
                Text(
                  'Min $minLength characters',
                  style: TextStyle(
                    color: CyberpunkTheme.error.withOpacity(0.8),
                    fontSize: 12,
                  ),
                ),
            ],
          ),
          // Bruteforce time estimate
          if (crackTime != null) ...[
            const SizedBox(height: 6),
            _BruteforceWarning(crackTime: crackTime),
          ],
        ],
      ],
    );
  }

  PasswordStrength _calculateStrength(String password) {
    if (password.isEmpty) return PasswordStrength.empty;
    if (password.length < 8) return PasswordStrength.weak;

    int score = 0;

    // Length scoring
    if (password.length >= 12) {
      score += 2;
    } else if (password.length >= 10) {
      score += 1;
    }

    // Character variety
    if (password.contains(RegExp(r'[a-z]'))) score += 1;
    if (password.contains(RegExp(r'[A-Z]'))) score += 1;
    if (password.contains(RegExp(r'[0-9]'))) score += 1;
    if (password.contains(RegExp(r'[!@#$%^&*(),.?":{}|<>]'))) score += 2;

    // Extra length bonus
    if (password.length >= 16) score += 1;
    if (password.length >= 20) score += 1;

    if (score <= 2) return PasswordStrength.weak;
    if (score <= 4) return PasswordStrength.fair;
    if (score <= 6) return PasswordStrength.good;
    if (score <= 8) return PasswordStrength.strong;
    return PasswordStrength.perfect;
  }

  double _getStrengthValue(PasswordStrength strength) {
    switch (strength) {
      case PasswordStrength.empty:
        return 0.0;
      case PasswordStrength.weak:
        return 0.2;
      case PasswordStrength.fair:
        return 0.4;
      case PasswordStrength.good:
        return 0.6;
      case PasswordStrength.strong:
        return 0.8;
      case PasswordStrength.perfect:
        return 1.0;
    }
  }

  Color _getStrengthColor(PasswordStrength strength) {
    switch (strength) {
      case PasswordStrength.empty:
        return CyberpunkTheme.surfaceLight;
      case PasswordStrength.weak:
        return CyberpunkTheme.strengthWeak;
      case PasswordStrength.fair:
        return CyberpunkTheme.strengthFair;
      case PasswordStrength.good:
        return CyberpunkTheme.strengthGood;
      case PasswordStrength.strong:
        return CyberpunkTheme.strengthStrong;
      case PasswordStrength.perfect:
        return CyberpunkTheme.strengthPerfect;
    }
  }

  String _getStrengthLabel(PasswordStrength strength) {
    switch (strength) {
      case PasswordStrength.empty:
        return '';
      case PasswordStrength.weak:
        return 'Weak';
      case PasswordStrength.fair:
        return 'Fair';
      case PasswordStrength.good:
        return 'Good';
      case PasswordStrength.strong:
        return 'Strong';
      case PasswordStrength.perfect:
        return 'Perfect';
    }
  }

  LinearGradient? _getGradient(PasswordStrength strength) {
    final color = _getStrengthColor(strength);
    if (strength == PasswordStrength.empty) return null;

    return LinearGradient(
      colors: [
        color.withOpacity(0.8),
        color,
      ],
      begin: Alignment.centerLeft,
      end: Alignment.centerRight,
    );
  }

  /// Estimate realistic entropy based on password patterns
  double _estimateRealisticEntropy(String password) {
    // 1. Start with pure entropy
    int poolSize = 0;
    if (password.contains(RegExp(r'[a-z]'))) poolSize += 26;
    if (password.contains(RegExp(r'[A-Z]'))) poolSize += 26;
    if (password.contains(RegExp(r'[0-9]'))) poolSize += 10;
    if (password.contains(RegExp(r"[!@#\$%^&*(),.?:{}|<>\[\]\\;'`~_+=\-/@ ]"))) {
      poolSize += 32;
    }
    if (poolSize == 0) poolSize = 26;

    double entropy = password.length * (log(poolSize) / ln2);

    // 2. Reduce entropy if common patterns are detected
    final lower = password.toLowerCase();

    // Common words
    const commonWords = [
      'admin', 'user', 'password', 'qwerty', 'abc', 'test', 'guest'
    ];
    for (final word in commonWords) {
      if (lower.contains(word)) entropy -= 15;
    }

    // Sequential numeric patterns
    if (RegExp(r'1234|4321|000|111|999').hasMatch(lower)) entropy -= 10;

    // Capital first letter followed by digits at the end → common pattern
    if (RegExp(r'^[A-Z][a-z]+\d{1,4}$').hasMatch(password)) entropy -= 8;

    // Only one character type
    if (poolSize < 20) entropy -= 5;

    // Very short length
    if (password.length < 8) entropy -= 10;

    // Normalize
    if (entropy < 0) entropy = 0;
    return entropy;
  }

  /// Estimate crack time based on entropy
  _CrackTimeInfo? _estimateCrackTime(String password) {
    if (password.isEmpty) return null;

    final entropy = _estimateRealisticEntropy(password);

    // Attack rate: 10^10 attempts per second (GPU)
    final double guessesPerSecond = pow(10, 10).toDouble();
    final double totalGuesses = pow(2, entropy).toDouble();
    final double seconds = totalGuesses / guessesPerSecond;

    return _CrackTimeInfo(seconds);
  }
}

/// Crack time information
class _CrackTimeInfo {
  final String message;
  final Color color;

  _CrackTimeInfo._({
    required this.message,
    required this.color,
  });

  factory _CrackTimeInfo(double seconds) {
    // Time thresholds
    const double minute = 60;
    const double hour = 3600;
    const double day = 86400;
    const double week = 604800;
    const double month = 2592000;
    const double year = 31536000;
    const double decade = year * 10;
    const double century = year * 100;
    const double millennium = year * 1000;
    const double million = year * 1000000;
    const double billion = year * 1000000000;

    if (seconds < 1) {
      return _CrackTimeInfo._(
        message: 'Warning: This password can be cracked in less than 1 second',
        color: CyberpunkTheme.strengthWeak,
      );
    } else if (seconds < minute) {
      return _CrackTimeInfo._(
        message: 'Warning: This password can be cracked in seconds',
        color: CyberpunkTheme.strengthWeak,
      );
    } else if (seconds < hour) {
      return _CrackTimeInfo._(
        message: 'Warning: This password can be cracked in minutes',
        color: CyberpunkTheme.strengthWeak,
      );
    } else if (seconds < day) {
      return _CrackTimeInfo._(
        message: 'Warning: This password can be cracked in hours',
        color: CyberpunkTheme.strengthWeak,
      );
    } else if (seconds < week) {
      return _CrackTimeInfo._(
        message: 'Warning: This password can be cracked in days',
        color: CyberpunkTheme.strengthFair,
      );
    } else if (seconds < month) {
      return _CrackTimeInfo._(
        message: 'Warning: This password can be cracked in weeks',
        color: CyberpunkTheme.strengthFair,
      );
    } else if (seconds < year) {
      return _CrackTimeInfo._(
        message: 'Warning: This password can be cracked in months',
        color: CyberpunkTheme.strengthFair,
      );
    } else if (seconds < decade) {
      return _CrackTimeInfo._(
        message: 'Warning: This password can be cracked in years',
        color: CyberpunkTheme.strengthGood,
      );
    } else if (seconds < century) {
      return _CrackTimeInfo._(
        message: 'Not bad: This password would take decades to crack',
        color: CyberpunkTheme.strengthGood,
      );
    } else if (seconds < millennium) {
      return _CrackTimeInfo._(
        message: 'Good: This password would take centuries to crack',
        color: CyberpunkTheme.strengthStrong,
      );
    } else if (seconds < million) {
      return _CrackTimeInfo._(
        message: 'Great: This password would take thousands of years to crack',
        color: CyberpunkTheme.strengthStrong,
      );
    } else if (seconds < billion) {
      return _CrackTimeInfo._(
        message: 'Excellent: This password would take millions of years to crack',
        color: CyberpunkTheme.strengthPerfect,
      );
    } else {
      return _CrackTimeInfo._(
        message: 'Perfect: This password would take billions of years to crack',
        color: CyberpunkTheme.strengthPerfect,
      );
    }
  }
}

/// Widget to display bruteforce warning
class _BruteforceWarning extends StatelessWidget {
  final _CrackTimeInfo crackTime;

  const _BruteforceWarning({required this.crackTime});

  @override
  Widget build(BuildContext context) {
    return Text(
      crackTime.message,
      style: TextStyle(
        color: crackTime.color,
        fontSize: 11,
        fontStyle: FontStyle.italic,
      ),
    );
  }
}

/// Animated fractionally sized box for smooth transitions
class AnimatedFractionallySizedBox extends StatelessWidget {
  final Duration duration;
  final double widthFactor;
  final Widget child;

  const AnimatedFractionallySizedBox({
    super.key,
    required this.duration,
    required this.widthFactor,
    required this.child,
  });

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        return AnimatedContainer(
          duration: duration,
          width: widthFactor * constraints.maxWidth,
          child: child,
        );
      },
    );
  }
}
