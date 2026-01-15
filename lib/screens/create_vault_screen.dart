/// CreateVaultScreen - New Vault Creation
/// 
/// Allows users to create a new encrypted vault with a passphrase.
/// Also provides option to import an existing vault file.
/// 
/// PASSPHRASE REQUIREMENTS:
/// - Minimum 12 characters
/// - At least 1 number
/// - At least 1 symbol
/// 
/// The passphrase is used to derive the Key Encryption Key (KEK)
/// via Argon2id, which then encrypts the randomly generated
/// Master Key (MK).
/// 
/// WARNING: There is NO password recovery. If the passphrase is
/// forgotten, all data in the vault is permanently lost.

import 'dart:async';
import 'package:flutter/material.dart';
import '../services/vault_state_manager.dart';
import '../services/vault_channel.dart';
import '../services/app_settings.dart';
import '../widgets/secure_keyboard.dart';
import '../services/transfer_progress_service.dart';
import '../utils/secure_passphrase.dart';

/// Screen for creating a new vault or importing an existing one.
/// 
/// FLAG_SECURE is set globally in MainActivity to prevent screenshots.
class CreateVaultScreen extends StatefulWidget {
  final VaultStateManager stateManager;

  const CreateVaultScreen({super.key, required this.stateManager});

  @override
  State<CreateVaultScreen> createState() => _CreateVaultScreenState();
}

class _CreateVaultScreenState extends State<CreateVaultScreen> {
  final _passphraseController = TextEditingController();
  final _confirmController = TextEditingController();
  final _transferProgressService = TransferProgressService.instance;
  bool _obscurePassphrase = true;
  bool _obscureConfirm = true;
  bool _isLoading = false;
  bool _isImporting = false;
  double? _importProgress;
  StreamSubscription<TransferProgress>? _transferProgressSub;
  String? _error;

  static const int minPassphraseLength = 12;

  @override
  void initState() {
    super.initState();
    _transferProgressService.initialize();
    _transferProgressSub = _transferProgressService.progressStream.listen((progress) {
      if (!_isImporting || progress.operation != 'import_vault') return;
      if (mounted) {
        setState(() {
          _importProgress = progress.normalized;
        });
      }
    });
  }

  @override
  void dispose() {
    _transferProgressSub?.cancel();
    SecurePassphrase.disposeController(_passphraseController);
    SecurePassphrase.disposeController(_confirmController);
    super.dispose();
  }

  double _getStrength() {
    final pass = _passphraseController.text;
    if (pass.isEmpty) return 0;

    double strength = 0;

    // Length contribution
    if (pass.length >= minPassphraseLength) strength += 0.25;
    if (pass.length >= 16) strength += 0.15;
    if (pass.length >= 20) strength += 0.1;

    // Character variety
    if (RegExp(r'[a-z]').hasMatch(pass)) strength += 0.1;
    if (RegExp(r'[A-Z]').hasMatch(pass)) strength += 0.1;
    if (RegExp(r'[0-9]').hasMatch(pass)) strength += 0.15;
    if (RegExp(r'[!@#$%^&*(),.?":{}|<>]').hasMatch(pass)) strength += 0.15;

    return strength.clamp(0, 1);
  }

  Color _getStrengthColor() {
    final strength = _getStrength();
    if (strength < 0.3) return Colors.red;
    if (strength < 0.6) return Colors.orange;
    if (strength < 0.8) return Colors.yellow;
    return Colors.green;
  }

  String _getStrengthText() {
    final strength = _getStrength();
    if (strength < 0.3) return 'Weak';
    if (strength < 0.6) return 'Fair';
    if (strength < 0.8) return 'Good';
    return 'Strong';
  }

  bool _isValid() {
    final pass = _passphraseController.text;
    final confirm = _confirmController.text;
    return _meetsPassphraseRules(pass) && pass == confirm;
  }

  bool _meetsPassphraseRules(String pass) {
    return pass.length >= minPassphraseLength && _hasNumber(pass) && _hasSymbol(pass);
  }

  bool _hasNumber(String pass) {
    return RegExp(r'[0-9]').hasMatch(pass);
  }

  bool _hasSymbol(String pass) {
    return RegExp(r'[^A-Za-z0-9]').hasMatch(pass);
  }

  Future<void> _createVault() async {
    if (!_isValid()) return;

    SecureKeyboard.hide();

    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      await widget.stateManager.createVault(_passphraseController.text);
      SecurePassphrase.clearController(_passphraseController);
      SecurePassphrase.clearController(_confirmController);
    } catch (e) {
      setState(() {
        _error = e.toString();
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  Future<void> _importVault() async {
    setState(() {
      _isImporting = true;
      _importProgress = 0;
      _error = null;
    });

    try {
      final ok = await VaultChannel.importVault();
      if (ok) {
        // Re-initialize to detect new vault
        await widget.stateManager.initialize();
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: const Text('Vault imported! Please unlock with your password.'),
              backgroundColor: Colors.green[700],
            ),
          );
        }
      } else {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: const Text('Import cancelled'),
              backgroundColor: Colors.grey[700],
            ),
          );
        }
      }
    } catch (e) {
      setState(() {
        _error = 'Import failed: $e';
      });
    } finally {
      setState(() {
        _isImporting = false;
        _importProgress = null;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.grey[900],
      appBar: AppBar(
        title: const Text('Create Vault'),
        backgroundColor: Colors.transparent,
        elevation: 0,
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Icon(
                Icons.lock_outline,
                size: 64,
                color: Colors.blue[400],
              ),
              const SizedBox(height: 24),
              Text(
                'Create Your Secure Vault',
                style: TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.bold,
                  color: Colors.grey[100],
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 8),
              Text(
                'Choose a strong passphrase. There is no recovery if you forget it.',
                style: TextStyle(
                  fontSize: 14,
                  color: Colors.grey[400],
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 32),

              // Passphrase field
              TextField(
                controller: _passphraseController,
                obscureText: _obscurePassphrase,
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
                      onChanged: (_) => setState(() {}),
                    );
                  }
                },
                onChanged: (_) => setState(() {}),
                style: const TextStyle(color: Colors.white),
                decoration: InputDecoration(
                  labelText: 'Passphrase',
                  labelStyle: TextStyle(color: Colors.grey[400]),
                  hintText: 'Min $minPassphraseLength chars + 1 number + 1 symbol',
                  hintStyle: TextStyle(color: Colors.grey[600]),
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
              const SizedBox(height: 8),

              if (_passphraseController.text.isNotEmpty &&
                  !_meetsPassphraseRules(_passphraseController.text))
                Padding(
                  padding: const EdgeInsets.only(bottom: 8),
                  child: Text(
                    'Must include at least 1 number and 1 symbol',
                    style: TextStyle(color: Colors.red[300], fontSize: 12),
                    textAlign: TextAlign.left,
                  ),
                ),

              // Strength indicator
              if (_passphraseController.text.isNotEmpty) ...[
                Row(
                  children: [
                    Expanded(
                      child: LinearProgressIndicator(
                        value: _getStrength(),
                        backgroundColor: Colors.grey[700],
                        valueColor: AlwaysStoppedAnimation(_getStrengthColor()),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Text(
                      _getStrengthText(),
                      style: TextStyle(
                        color: _getStrengthColor(),
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
              ],

              // Confirm field
              TextField(
                controller: _confirmController,
                obscureText: _obscureConfirm,
                readOnly: AppSettings.instance.secureKeyboardEnabled,
                showCursor: true,
                enableInteractiveSelection: !AppSettings.instance.secureKeyboardEnabled,
                autocorrect: false,
                enableSuggestions: false,
                onTap: () {
                  if (AppSettings.instance.secureKeyboardEnabled) {
                    SecureKeyboard.show(
                      context,
                      controller: _confirmController,
                      onChanged: (_) => setState(() {}),
                    );
                  }
                },
                onChanged: (_) => setState(() {}),
                style: const TextStyle(color: Colors.white),
                decoration: InputDecoration(
                  labelText: 'Confirm Passphrase',
                  labelStyle: TextStyle(color: Colors.grey[400]),
                  filled: true,
                  fillColor: Colors.grey[800],
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: BorderSide.none,
                  ),
                  suffixIcon: IconButton(
                    icon: Icon(
                      _obscureConfirm ? Icons.visibility : Icons.visibility_off,
                      color: Colors.grey[400],
                    ),
                    onPressed: () {
                      setState(() {
                        _obscureConfirm = !_obscureConfirm;
                      });
                    },
                  ),
                  errorText: _confirmController.text.isNotEmpty &&
                          _passphraseController.text != _confirmController.text
                      ? 'Passphrases do not match'
                      : null,
                ),
              ),
              const SizedBox(height: 24),

              // Error message
              if (_error != null)
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Colors.red[900]?.withOpacity(0.3),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Text(
                    _error!,
                    style: TextStyle(color: Colors.red[300]),
                  ),
                ),

              const SizedBox(height: 24),

              // Create button
              Row(
                children: [
                  Expanded(
                    child: ElevatedButton(
                      onPressed: _isValid() && !_isLoading ? _createVault : null,
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
                              'Create Vault',
                              style: TextStyle(fontSize: 18),
                            ),
                    ),
                  ),
                ],
              ),

              const SizedBox(height: 24),

              // Warning
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.orange[900]?.withOpacity(0.2),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: Colors.orange[700]!.withOpacity(0.5)),
                ),
                child: Row(
                  children: [
                    Icon(Icons.warning_amber, color: Colors.orange[400]),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        'There is NO recovery option. If you forget your passphrase, your data will be permanently lost.',
                        style: TextStyle(
                          color: Colors.orange[200],
                          fontSize: 13,
                        ),
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 32),

              // Divider with "OR"
              Row(
                children: [
                  Expanded(child: Divider(color: Colors.grey[700])),
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 16),
                    child: Text(
                      'OR',
                      style: TextStyle(color: Colors.grey[500], fontSize: 14),
                    ),
                  ),
                  Expanded(child: Divider(color: Colors.grey[700])),
                ],
              ),

              const SizedBox(height: 24),

              // Import existing vault button
              OutlinedButton.icon(
                onPressed: (_isLoading || _isImporting) ? null : _importVault,
                style: OutlinedButton.styleFrom(
                  foregroundColor: Colors.grey[300],
                  side: BorderSide(color: Colors.grey[600]!),
                  padding: const EdgeInsets.symmetric(vertical: 16),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
                icon: _isImporting
                    ? const SizedBox(
                        height: 18,
                        width: 18,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: Colors.grey,
                        ),
                      )
                    : const Icon(Icons.file_download),
                label: Text(
                  _isImporting
                      ? 'Importing ${((_importProgress ?? 0) * 100).round()}%'
                      : 'Import Existing Vault',
                  style: const TextStyle(fontSize: 16),
                ),
              ),

              if (_isImporting && _importProgress != null) ...[
                const SizedBox(height: 12),
                LinearProgressIndicator(
                  value: _importProgress,
                  backgroundColor: Colors.grey[800],
                  valueColor: AlwaysStoppedAnimation(Colors.blue[400]),
                ),
              ],

              const SizedBox(height: 12),

              Text(
                'Import a .dat vault file from another device',
                style: TextStyle(
                  color: Colors.grey[600],
                  fontSize: 12,
                ),
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
