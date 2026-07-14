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
      backgroundColor: Colors.grey[900],
      body: SafeArea(
        child: ValueListenableBuilder<double>(
          valueListenable: SecureKeyboard.inset,
          builder: (context, keyboardInset, _) {
            return SingleChildScrollView(
              padding: EdgeInsets.fromLTRB(24, 24, 24, 24 + keyboardInset),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
              const SizedBox(height: 48),
              Icon(
                Icons.lock,
                size: 80,
                color: Colors.blue[400],
              ),
              const SizedBox(height: 24),
              Text(
                'Unlock Vault',
                style: TextStyle(
                  fontSize: 28,
                  fontWeight: FontWeight.bold,
                  color: Colors.grey[100],
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 8),
              Text(
                'Enter your passphrase to access your files',
                style: TextStyle(
                  fontSize: 14,
                  color: Colors.grey[400],
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 48),

              // Lockout warning
              if (isLockedOut)
                Container(
                  padding: const EdgeInsets.all(16),
                  margin: const EdgeInsets.only(bottom: 24),
                  decoration: BoxDecoration(
                    color: Colors.red[900]?.withOpacity(0.3),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: Colors.red[700]!.withOpacity(0.5)),
                  ),
                  child: Column(
                    children: [
                      Icon(Icons.timer, color: Colors.red[400], size: 32),
                      const SizedBox(height: 8),
                      Text(
                        'Too many failed attempts',
                        style: TextStyle(
                          color: Colors.red[300],
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Try again in ${_formatLockoutTime(lockoutSeconds)}',
                        style: TextStyle(color: Colors.red[200]),
                      ),
                    ],
                  ),
                ),

              // Passphrase field
              TextField(
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
                style: const TextStyle(color: Colors.white),
                decoration: InputDecoration(
                  labelText: 'Passphrase',
                  labelStyle: TextStyle(color: Colors.grey[400]),
                  filled: true,
                  fillColor: Colors.grey[800],
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: BorderSide.none,
                  ),
                  suffixIcon: IconButton(
                    icon: Icon(
                      _obscurePassphrase ? Icons.visibility : Icons.visibility_off,
                      color: Colors.grey[400],
                    ),
                    onPressed: () {
                      setState(() {
                        _obscurePassphrase = !_obscurePassphrase;
                      });
                    },
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
                    color: Colors.red[900]?.withOpacity(0.3),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(
                    children: [
                      Icon(Icons.error_outline, color: Colors.red[300], size: 20),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          _error!,
                          style: TextStyle(color: Colors.red[300]),
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
                    style: TextStyle(
                      color: Colors.orange[400],
                      fontSize: 12,
                    ),
                    textAlign: TextAlign.center,
                  ),
                ),

              // Unlock button
              ElevatedButton(
                key: _buttonKey,
                onPressed: !isLockedOut && !_isLoading ? _unlock : null,
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.blue[700],
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(vertical: 16),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                  disabledBackgroundColor: Colors.grey[700],
                ),
                child: _isLoading
                    ? const SizedBox(
                        height: 20,
                        width: 20,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: Colors.white,
                        ),
                      )
                    : const Text(
                        'Unlock',
                        style: TextStyle(fontSize: 18),
                      ),
              ),

              const SizedBox(height: 32),

              // Info
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(Icons.fingerprint, color: Colors.grey[500], size: 20),
                  const SizedBox(width: 8),
                  Text(
                    'Biometric verification required after passphrase',
                    style: TextStyle(
                      color: Colors.grey[500],
                      fontSize: 12,
                    ),
                  ),
                ],
              ),
            ],
          ),
        );
        },
      ),
      ),
    );
  }
}
