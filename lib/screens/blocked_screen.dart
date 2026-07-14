/// BlockedScreen - Security Violation Display
/// 
/// Shown when the device environment is detected as compromised:
/// - Rooted/jailbroken device
/// - Running in emulator
/// - Debugger attached
/// - App tampering detected
/// 
/// This is a fail-closed security measure - the app refuses to
/// operate in potentially compromised environments to protect
/// user data.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../theme/cyberpunk_theme.dart';

/// Screen displayed when device security check fails.
/// 
/// Shows a security alert and provides only an exit option.
/// The vault cannot be accessed from this screen.
class BlockedScreen extends StatelessWidget {
  const BlockedScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: CyberpunkTheme.background,
      body: SafeArea(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.all(32.0),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                // Glowing warning icon
                Container(
                  padding: const EdgeInsets.all(24),
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    boxShadow: [
                      BoxShadow(
                        color: CyberpunkTheme.error.withOpacity(0.4),
                        blurRadius: 40,
                        spreadRadius: 10,
                      ),
                    ],
                  ),
                  child: const Icon(
                    Icons.shield_outlined,
                    size: 80,
                    color: CyberpunkTheme.error,
                  ),
                ),
                const SizedBox(height: 32),
                const Text(
                  'SECURITY ALERT',
                  style: TextStyle(
                    fontSize: 24,
                    fontWeight: FontWeight.bold,
                    color: CyberpunkTheme.error,
                    letterSpacing: 3,
                  ),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 16),
                const Text(
                  'Environment not supported',
                  style: TextStyle(
                    fontSize: 18,
                    fontWeight: FontWeight.w600,
                    color: CyberpunkTheme.textPrimary,
                  ),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 8),
                const Text(
                  'This app cannot run on this device for security reasons.',
                  style: TextStyle(
                    fontSize: 14,
                    color: CyberpunkTheme.textSecondary,
                  ),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 48),
                Container(
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(12),
                    boxShadow: [
                      BoxShadow(
                        color: CyberpunkTheme.error.withOpacity(0.3),
                        blurRadius: 12,
                      ),
                    ],
                  ),
                  child: ElevatedButton(
                    onPressed: () {
                      SystemNavigator.pop();
                    },
                    style: ElevatedButton.styleFrom(
                      backgroundColor: CyberpunkTheme.error,
                      foregroundColor: CyberpunkTheme.textPrimary,
                      padding: const EdgeInsets.symmetric(
                        horizontal: 48,
                        vertical: 16,
                      ),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                    ),
                    child: const Text(
                      'EXIT',
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                        letterSpacing: 2,
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
