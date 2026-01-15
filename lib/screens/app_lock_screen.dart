/// AppLockScreen - Biometric Authentication Gate
/// 
/// Displayed when app lock is enabled and biometric authentication
/// fails on app launch. Provides a retry button and exit option.
/// 
/// This screen is shown before the user can access any vault data,
/// providing an additional layer of security beyond vault passwords.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../theme/cyberpunk_theme.dart';

/// Screen shown when biometric app lock authentication is required.
/// 
/// The [onRetry] callback should attempt biometric authentication
/// and return true if successful, false otherwise.
class AppLockScreen extends StatefulWidget {
  final Future<bool> Function() onRetry;

  const AppLockScreen({super.key, required this.onRetry});

  @override
  State<AppLockScreen> createState() => _AppLockScreenState();
}

class _AppLockScreenState extends State<AppLockScreen> {
  bool _isLoading = false;

  Future<void> _handleRetry() async {
    if (_isLoading) return;
    setState(() => _isLoading = true);
    final ok = await widget.onRetry();
    if (mounted) {
      setState(() => _isLoading = false);
    }
    if (!ok && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Biometric authentication required'),
          backgroundColor: CyberpunkTheme.error,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: CyberpunkTheme.background,
      body: SafeArea(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Container(
                  padding: const EdgeInsets.all(24),
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    boxShadow: [
                      BoxShadow(
                        color: CyberpunkTheme.neonGreen.withOpacity(0.3),
                        blurRadius: 40,
                        spreadRadius: 10,
                      ),
                    ],
                  ),
                  child: const Icon(
                    Icons.fingerprint,
                    size: 80,
                    color: CyberpunkTheme.neonGreen,
                  ),
                ),
                const SizedBox(height: 32),
                const Text(
                  'APP LOCK',
                  style: TextStyle(
                    fontSize: 24,
                    fontWeight: FontWeight.bold,
                    color: CyberpunkTheme.textPrimary,
                    letterSpacing: 3,
                  ),
                ),
                const SizedBox(height: 12),
                const Text(
                  'Authenticate to continue',
                  style: TextStyle(
                    fontSize: 14,
                    color: CyberpunkTheme.textSecondary,
                  ),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 32),
                ElevatedButton(
                  onPressed: _isLoading ? null : _handleRetry,
                  style: ElevatedButton.styleFrom(
                    backgroundColor: CyberpunkTheme.neonGreen,
                    foregroundColor: CyberpunkTheme.background,
                    padding: const EdgeInsets.symmetric(horizontal: 48, vertical: 14),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                  child: _isLoading
                      ? const SizedBox(
                          height: 20,
                          width: 20,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: CyberpunkTheme.background,
                          ),
                        )
                      : const Text(
                          'RETRY',
                          style: TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                            letterSpacing: 2,
                          ),
                        ),
                ),
                const SizedBox(height: 16),
                TextButton(
                  onPressed: () => SystemNavigator.pop(),
                  child: const Text(
                    'EXIT',
                    style: TextStyle(color: CyberpunkTheme.textSecondary),
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
