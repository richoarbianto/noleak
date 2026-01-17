/// UnlockVaultScreen - Vault Authentication
/// 
/// Handles vault unlock with passphrase entry and biometric verification.
/// Implements brute-force protection with progressive lockout.
/// 
/// AUTHENTICATION FLOW:
/// 1. User enters passphrase
/// 2. Passphrase verified against vault (Argon2id + XChaCha20)
/// 3. Biometric verification required
/// 4. Vault unlocked on success
/// 
/// BRUTE-FORCE PROTECTION:
/// - 5 failed attempts → 30 second lockout
/// - 8 failed attempts → 2 minute lockout
/// - 10 failed attempts → 5 minute lockout
/// - 15 failed attempts → 15 minute lockout
/// - 20 failed attempts → 1 hour lockout
/// 
/// Lockout state persists across app restarts.

import 'dart:async';
import 'package:flutter/material.dart';
import '../services/vault_state_manager.dart';
import '../services/app_settings.dart';
import '../widgets/secure_keyboard.dart';
import '../utils/secure_passphrase.dart';
import '../theme/cyberpunk_theme.dart';

/// Screen for unlocking an existing vault with passphrase + biometric.
/// 
/// FLAG_SECURE is set globally in MainActivity to prevent screenshots.
class UnlockVaultScreen extends StatefulWidget {
  final VaultStateManager stateManager;

  const UnlockVaultScreen({super.key, required this.stateManager});

  @override
  State<UnlockVaultScreen> createState() => _UnlockVaultScreenState();
}

class _UnlockVaultScreenState extends State<UnlockVaultScreen> {
  final _passphraseController = TextEditingController();
  final GlobalKey _buttonKey = GlobalKey();
  bool _obscurePassphrase = true;
  bool _isLoading = false;
  String? _error;
  Timer? _lockoutTimer;

  @override
  void initState() {
    super.initState();
    _startLockoutTimer();
    SecureKeyboard.inset.addListener(_onKeyboardInsetChanged);
  }

  @override
  void dispose() {
    SecureKeyboard.inset.removeListener(_onKeyboardInsetChanged);
    SecurePassphrase.disposeController(_passphraseController);
    _lockoutTimer?.cancel();
    super.dispose();
  }

  void _onKeyboardInsetChanged() {
    if (SecureKeyboard.inset.value > 0) {
      // Delay to ensure keyboard animation and layout update are complete
      Future.delayed(const Duration(milliseconds: 300), () {
        if (mounted && _buttonKey.currentContext != null) {
          Scrollable.ensureVisible(
            _buttonKey.currentContext!,
            duration: const Duration(milliseconds: 300),
            curve: Curves.easeOut,
            alignment: 1.0, // align bottom of item to bottom of viewport
          );
        }
      });
    }
  }

  void _startLockoutTimer() {
    _lockoutTimer?.cancel();
    if (widget.stateManager.isLockedOut) {
      _lockoutTimer = Timer.periodic(const Duration(seconds: 1), (_) {
        if (mounted) {
          setState(() {});
          if (!widget.stateManager.isLockedOut) {
            _lockoutTimer?.cancel();
          }
        }
      });
    }
  }

  Future<void> _unlock() async {
    if (_passphraseController.text.isEmpty) return;

    SecureKeyboard.hide();

    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      await widget.stateManager.unlockVault(_passphraseController.text);
      SecurePassphrase.clearController(_passphraseController);
    } catch (e) {
      setState(() {
        final message = e.toString().replaceFirst('Exception: ', '');
        _error = message.isEmpty ? 'Incorrect passphrase' : message;
        _startLockoutTimer();
      });
    } finally {
      if (mounted) {
        setState(() {
          _isLoading = false;
        });
      }
    }
  }

  String _formatLockoutTime(int seconds) {
    final minutes = seconds ~/ 60;
    final secs = seconds % 60;
    if (minutes > 0) {
      return '$minutes:${secs.toString().padLeft(2, '0')}';
    }
    return '$secs seconds';
  }

  @override
  Widget build(BuildContext context) {
    final isLockedOut = widget.stateManager.isLockedOut;
    final lockoutSeconds = widget.stateManager.lockoutRemainingSeconds;

    return Scaffold(
      backgroundColor: CyberpunkTheme.background,
      body: SafeArea(
        child: ValueListenableBuilder<double>(
          valueListenable: SecureKeyboard.inset,
          builder: (context, keyboardInset, _) {
            return Center(
              child: SingleChildScrollView(
                padding: EdgeInsets.fromLTRB(24, 24, 24, 24 + keyboardInset),
                child: Container(
                  width: MediaQuery.of(context).size.width * 0.92,
                  constraints: const BoxConstraints(maxWidth: 400),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const SizedBox(height: 24),
                      Container(
                        padding: const EdgeInsets.all(20),
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          color: CyberpunkTheme.neonGreen.withOpacity(0.1),
                          border: Border.all(
                            color: CyberpunkTheme.neonGreen.withOpacity(0.3),
                          ),
                        ),
                        child: const Icon(
                          Icons.lock,
                          size: 48,
                          color: CyberpunkTheme.neonGreen,
                        ),
                      ),
                      const SizedBox(height: 24),
                      const Text(
                        'UNLOCK VAULT',
                        style: TextStyle(
                          fontSize: 24,
                          fontWeight: FontWeight.bold,
                          color: CyberpunkTheme.textPrimary,
                          letterSpacing: 2,
                        ),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'Enter your passphrase to access your files',
                        style: TextStyle(
                          fontSize: 14,
                          color: CyberpunkTheme.textSecondary,
                        ),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 32),

                      // Lockout warning
                      if (isLockedOut)
                        Container(
                          padding: const EdgeInsets.all(16),
                          margin: const EdgeInsets.only(bottom: 24),
                          decoration: BoxDecoration(
                            color: CyberpunkTheme.error.withOpacity(0.1),
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(color: CyberpunkTheme.error.withOpacity(0.3)),
                          ),
                          child: Column(
                            children: [
                              const Icon(Icons.timer, color: CyberpunkTheme.error, size: 32),
                              const SizedBox(height: 8),
                              const Text(
                                'Too many failed attempts',
                                style: TextStyle(
                                  color: CyberpunkTheme.error,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                              const SizedBox(height: 4),
                              Text(
                                'Try again in ${_formatLockoutTime(lockoutSeconds)}',
                                style: TextStyle(color: CyberpunkTheme.error.withOpacity(0.8)),
                              ),
                            ],
                          ),
                        ),

                      // Passphrase field
                      Container(
                        decoration: BoxDecoration(
                          color: CyberpunkTheme.surface,
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(
                            color: CyberpunkTheme.neonGreen.withOpacity(0.3),
                          ),
                        ),
                        child: TextField(
                          controller: _passphraseController,
                          obscureText: _obscurePassphrase,
                          enabled: !isLockedOut && !_isLoading,
                          readOnly: AppSettings.instance.secureKeyboardEnabled,
                          showCursor: true,
                          enableInteractiveSelection: !AppSettings.instance.secureKeyboardEnabled,
                          autocorrect: false,
                          enableSuggestions: false,
                          onTap: () {
                            if (AppSettings.instance.secureKeyboardEnabled) {
                              SecureKeyboard.show(
                                context,
                                controller: _passphraseController,
                                onSubmitted: (_) => _unlock(),
                              );
                            }
                          },
                          onSubmitted: (_) => _unlock(),
                          style: const TextStyle(color: CyberpunkTheme.textPrimary),
                          decoration: InputDecoration(
                            labelText: 'Passphrase',
                            labelStyle: const TextStyle(color: CyberpunkTheme.textSecondary),
                            filled: true,
                            fillColor: Colors.transparent,
                            border: InputBorder.none,
                            contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
                            suffixIcon: IconButton(
                              icon: Icon(
                                _obscurePassphrase ? Icons.visibility : Icons.visibility_off,
                                color: CyberpunkTheme.textSecondary,
                              ),
                              onPressed: () {
                                setState(() {
                                  _obscurePassphrase = !_obscurePassphrase;
                                });
                              },
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(height: 16),

                      // Error message
                      if (_error != null && !isLockedOut)
                        Container(
                          padding: const EdgeInsets.all(12),
                          margin: const EdgeInsets.only(bottom: 16),
                          decoration: BoxDecoration(
                            color: CyberpunkTheme.error.withOpacity(0.1),
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(color: CyberpunkTheme.error.withOpacity(0.3)),
                          ),
                          child: Row(
                            children: [
                              const Icon(Icons.error_outline, color: CyberpunkTheme.error, size: 20),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  _error!,
                                  style: const TextStyle(color: CyberpunkTheme.error),
                                ),
                              ),
                            ],
                          ),
                        ),

                      // Failed attempts counter
                      if (widget.stateManager.failedAttempts > 0 && !isLockedOut)
                        Padding(
                          padding: const EdgeInsets.only(bottom: 16),
                          child: Text(
                            'Failed attempts: ${widget.stateManager.failedAttempts}/${VaultStateManager.maxFailedAttempts}',
                            style: const TextStyle(
                              color: CyberpunkTheme.warning,
                              fontSize: 12,
                            ),
                            textAlign: TextAlign.center,
                          ),
                        ),

                      // Unlock button
                      Container(
                        decoration: BoxDecoration(
                          borderRadius: BorderRadius.circular(12),
                          boxShadow: !isLockedOut && !_isLoading
                              ? [
                                  BoxShadow(
                                    color: CyberpunkTheme.neonGreen.withOpacity(0.3),
                                    blurRadius: 12,
                                    spreadRadius: 1,
                                  ),
                                ]
                              : null,
                        ),
                        child: ElevatedButton(
                          key: _buttonKey,
                          onPressed: !isLockedOut && !_isLoading ? _unlock : null,
                          style: ElevatedButton.styleFrom(
                            backgroundColor: CyberpunkTheme.neonGreen,
                            foregroundColor: CyberpunkTheme.background,
                            padding: const EdgeInsets.symmetric(vertical: 16),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(12),
                            ),
                            disabledBackgroundColor: CyberpunkTheme.surface,
                            disabledForegroundColor: CyberpunkTheme.textHint,
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
                                  'UNLOCK',
                                  style: TextStyle(
                                    fontSize: 16,
                                    fontWeight: FontWeight.bold,
                                    letterSpacing: 1,
                                  ),
                                ),
                        ),
                      ),

                      const SizedBox(height: 24),

                      // Info
                      Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(Icons.fingerprint, color: CyberpunkTheme.textHint, size: 18),
                          const SizedBox(width: 8),
                          Text(
                            'Biometric verification required',
                            style: TextStyle(
                              color: CyberpunkTheme.textHint,
                              fontSize: 12,
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            );
          },
        ),
      ),
    );
  }
}
