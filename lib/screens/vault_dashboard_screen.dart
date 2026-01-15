/// VaultDashboardScreen - Multi-Vault Management
/// 
/// Main screen showing the list of all vaults on the device.
/// Supports up to 25 independent vaults, each with its own
/// password and encrypted title.
/// 
/// FEATURES:
/// - Create new vaults
/// - Import existing vault files
/// - Reveal vault details (requires password)
/// - Edit vault titles
/// - Export vaults for backup
/// - Delete vaults
/// 
/// SECURITY:
/// - Vault titles are encrypted and require password to reveal
/// - Details auto-hide after 30 seconds
/// - All operations require authentication

import 'dart:async';
import 'package:flutter/material.dart';
import '../models/vault_info.dart';
import '../services/vault_registry.dart';
import '../services/vault_channel.dart';
import '../services/app_settings.dart';
import '../services/transfer_progress_service.dart';
import '../theme/cyberpunk_theme.dart';
import '../widgets/cyber_button.dart';
import '../widgets/cyber_text_field.dart';
import '../widgets/password_strength_meter.dart';
import '../widgets/loading_overlay.dart';
import '../widgets/secure_keyboard.dart';
import 'vault_info_screen.dart';
import '../utils/secure_logger.dart';
import '../utils/secure_passphrase.dart';

/// Main dashboard screen showing list of vaults with Cyberpunk theme.
/// 
/// The [onUnlockVault] callback is called when user taps a vault
/// to unlock it, passing the vault ID.
class VaultDashboardScreen extends StatefulWidget {
  final VaultRegistry registry;
  final void Function(String vaultId) onUnlockVault;

  const VaultDashboardScreen({
    super.key,
    required this.registry,
    required this.onUnlockVault,
  });

  @override
  State<VaultDashboardScreen> createState() => _VaultDashboardScreenState();
}

class _VaultDashboardScreenState extends State<VaultDashboardScreen> {
  final _transferProgressService = TransferProgressService.instance;
  final Map<String, String> _revealedDetails = {};
  final Map<String, DateTime> _revealTimers = {};
  final Set<String> _revealingVaults = {};
  bool _isCreating = false;
  bool _isImporting = false;
  bool _isExporting = false;
  double? _importProgress;
  double? _exportProgress;
  StreamSubscription<TransferProgress>? _transferProgressSub;

  @override
  void initState() {
    super.initState();
    widget.registry.load();
    _transferProgressService.initialize();
    _transferProgressSub = _transferProgressService.progressStream.listen((progress) {
      if (_isImporting && progress.operation == 'import_vault') {
        if (mounted) {
          setState(() {
            _importProgress = progress.normalized;
          });
        }
      } else if (_isExporting && progress.operation == 'export_vault') {
        if (mounted) {
          setState(() {
            _exportProgress = progress.normalized;
          });
        }
      }
    });
  }

  @override
  void dispose() {
    _transferProgressSub?.cancel();
    _wipeAllRevealedDetails();
    super.dispose();
  }

  void _wipeRevealedDetail(String vaultId) {
    if (_revealedDetails.containsKey(vaultId)) {
      _revealedDetails[vaultId] = '';
      _revealedDetails.remove(vaultId);
      _revealTimers.remove(vaultId);
    }
  }

  void _wipeAllRevealedDetails() {
    for (final key in _revealedDetails.keys.toList()) {
      _revealedDetails[key] = '';
    }
    _revealedDetails.clear();
    _revealTimers.clear();
  }

  bool _isRevealed(String vaultId) => _revealedDetails.containsKey(vaultId);
  
  bool get _hasRevealedDetails => _revealedDetails.isNotEmpty;
  
  void _hideAllDetails() {
    setState(() {
      _wipeAllRevealedDetails();
    });
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: const Text('All details hidden'),
        backgroundColor: CyberpunkTheme.surface,
        duration: const Duration(seconds: 1),
      ),
    );
  }
  
  void _showSettings() {
    showModalBottomSheet(
      context: context,
      backgroundColor: CyberpunkTheme.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (context) => const _SettingsSheet(),
    );
  }

  void _openInfoPage() {
    Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => const VaultInfoScreen()),
    );
  }

  Future<void> _createVault() async {
    final result = await showDialog<Map<String, String>>(
      context: context,
      barrierDismissible: false,
      builder: (context) => const _CreateVaultDialog(),
    );

    if (result == null) return;

    setState(() => _isCreating = true);
    
    try {
      final success = await widget.registry.createVault(
        title: result['title']!,
        password: result['password']!,
      );
      
      if (mounted) {
        if (success) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: const Text('Vault created successfully'),
              backgroundColor: CyberpunkTheme.neonGreen.withOpacity(0.9),
            ),
          );
        } else {
          final errorMsg = widget.registry.error ?? 'Failed to create vault';
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(errorMsg),
              backgroundColor: CyberpunkTheme.error,
              duration: const Duration(seconds: 4),
            ),
          );
          widget.registry.clearError();
        }
      }
    } finally {
      if (mounted) setState(() => _isCreating = false);
    }
  }

  Future<void> _importVault() async {
    // Step 1: Pick file first (quick, no loading indicator)
    final uri = await VaultChannel.pickVaultFile();
    if (uri == null) {
      // User cancelled picker
      return;
    }

    // Step 2: NOW show loading indicator after file is selected
    setState(() {
      _isImporting = true;
      _importProgress = 0;
    });

    try {
      // Import from URI with progress tracking
      final result = await VaultChannel.importVaultFromUri(uri);
      final success = result != null;
      
      if (success) {
        // Reload registry to get updated vault list
        await widget.registry.load();
      }
      
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(success ? 'Vault imported successfully' : 'Import failed'),
            backgroundColor: success ? CyberpunkTheme.neonGreen.withOpacity(0.9) : CyberpunkTheme.error,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Import failed: $e'),
            backgroundColor: CyberpunkTheme.error,
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          _isImporting = false;
          _importProgress = null;
        });
      }
    }
  }

  Future<void> _revealDetail(VaultInfo vault) async {
    final password = await _askPassword('Reveal Details', 'Enter password to reveal vault details:');
    if (password == null) return;

    setState(() => _revealingVaults.add(vault.id));
    try {
      SecureLogger.d('VaultDashboard', 'Revealing details for vault ${vault.id}');
      await VaultChannel.openVaultById(vaultId: vault.id, password: password);
      final title = await widget.registry.revealTitle(vault.id, password);
      await VaultChannel.closeVault();
      
      if (mounted) {
        setState(() {
          _revealedDetails[vault.id] = title ?? '';
          _revealTimers[vault.id] = DateTime.now();
        });
        
        Future.delayed(const Duration(seconds: 30), () {
          if (mounted) {
            setState(() => _wipeRevealedDetail(vault.id));
          }
        });
        
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: const Text('Details revealed for 30 seconds'),
            backgroundColor: CyberpunkTheme.neonGreen.withOpacity(0.9),
            duration: const Duration(seconds: 2),
          ),
        );
      }
    } catch (e) {
      SecureLogger.e('VaultDashboard', 'Reveal failed', e);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Incorrect password'),
            backgroundColor: CyberpunkTheme.error,
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _revealingVaults.remove(vault.id));
      }
    }
  }

  void _hideDetail(String vaultId) {
    setState(() => _wipeRevealedDetail(vaultId));
  }

  Future<void> _editTitle(VaultInfo vault) async {
    final password = await _askPassword('Edit Title', 'Enter password to edit vault title:');
    if (password == null) return;

    String currentTitle;
    try {
      await VaultChannel.openVaultById(vaultId: vault.id, password: password);
      final result = await widget.registry.revealTitle(vault.id, password);
      currentTitle = result ?? '';
      await VaultChannel.closeVault();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Incorrect password'),
            backgroundColor: CyberpunkTheme.error,
          ),
        );
      }
      return;
    }

    if (!mounted) return;

    final newTitle = await showDialog<String>(
      context: context,
      builder: (context) => _EditTitleDialog(currentTitle: currentTitle),
    );

    if (newTitle == null || newTitle == currentTitle) return;

    final success = await widget.registry.updateTitle(vault.id, password, newTitle);
    
    if (mounted) {
      if (success) {
        setState(() {
          if (_revealedDetails.containsKey(vault.id)) {
            _revealedDetails[vault.id] = newTitle;
          }
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: const Text('Title updated'),
            backgroundColor: CyberpunkTheme.neonGreen.withOpacity(0.9),
          ),
        );
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Failed to update title'),
            backgroundColor: CyberpunkTheme.error,
          ),
        );
      }
    }
  }

  Future<void> _deleteVault(VaultInfo vault) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: CyberpunkTheme.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: BorderSide(color: CyberpunkTheme.error.withOpacity(0.3)),
        ),
        title: const Text(
          'DELETE VAULT',
          style: TextStyle(
            color: CyberpunkTheme.error,
            letterSpacing: 2,
          ),
        ),
        content: const Text(
          'Are you sure you want to delete this vault?\n\nThis will permanently delete all encrypted data. This action cannot be undone.',
          style: TextStyle(color: CyberpunkTheme.textSecondary),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel', style: TextStyle(color: CyberpunkTheme.textSecondary)),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            style: TextButton.styleFrom(foregroundColor: CyberpunkTheme.error),
            child: const Text('DELETE FOREVER'),
          ),
        ],
      ),
    );

    if (confirm != true) return;

    final success = await widget.registry.deleteVault(vault.id);
    
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(success ? 'Vault deleted' : 'Failed to delete vault'),
          backgroundColor: success ? CyberpunkTheme.warning : CyberpunkTheme.error,
        ),
      );
    }
  }

  Future<void> _exportVault(VaultInfo vault) async {
    final password = await _askPassword('Export Vault', 'Enter password to export vault:');
    if (password == null) return;

    try {
      await VaultChannel.openVaultById(vaultId: vault.id, password: password);
      await VaultChannel.closeVault();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Incorrect password'),
            backgroundColor: CyberpunkTheme.error,
          ),
        );
      }
      return;
    }

    setState(() {
      _isExporting = true;
      _exportProgress = 0;
    });
    
    // Keep screen awake during export
    await VaultChannel.enableWakelock();
    SecureLogger.d('VaultDashboardScreen', '_exportVault: wakelock enabled');
    
    try {
      final success = await VaultChannel.exportVaultById(vaultId: vault.id);
      
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(success ? 'Vault exported' : 'Export cancelled'),
            backgroundColor: success ? CyberpunkTheme.neonGreen.withOpacity(0.9) : CyberpunkTheme.surface,
          ),
        );
      }
    } catch (_) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Export failed'),
            backgroundColor: CyberpunkTheme.error,
          ),
        );
      }
    } finally {
      // Disable wakelock
      await VaultChannel.disableWakelock();
      SecureLogger.d('VaultDashboardScreen', '_exportVault: wakelock disabled');
      
      if (mounted) {
        setState(() {
          _isExporting = false;
          _exportProgress = null;
        });
      }
    }
  }

  Future<String?> _askPassword(String title, String message) async {
    final controller = TextEditingController();
    bool obscure = true;

    final password = await showDialog<String>(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setState) => AlertDialog(
          backgroundColor: CyberpunkTheme.surface,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: BorderSide(color: CyberpunkTheme.neonGreen.withOpacity(0.3)),
          ),
          title: Text(
            title.toUpperCase(),
            style: const TextStyle(
              color: CyberpunkTheme.neonGreen,
              letterSpacing: 2,
              fontWeight: FontWeight.w600,
            ),
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(message, style: const TextStyle(color: CyberpunkTheme.textSecondary)),
              const SizedBox(height: 16),
              CyberTextField(
                controller: controller,
                obscureText: obscure,
                labelText: 'Password',
                suffixIcon: IconButton(
                  icon: Icon(
                    obscure ? Icons.visibility : Icons.visibility_off,
                    color: CyberpunkTheme.textSecondary,
                  ),
                  onPressed: () => setState(() => obscure = !obscure),
                ),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel', style: TextStyle(color: CyberpunkTheme.textSecondary)),
            ),
            TextButton(
              onPressed: () => Navigator.pop(context, controller.text),
              child: const Text('OK', style: TextStyle(color: CyberpunkTheme.neonGreen)),
            ),
          ],
        ),
      ),
    );
    
    // CRITICAL: Clear SecureKeyboard target FIRST to prevent it from accessing
    // the controller during widget rebuilds. This must happen synchronously.
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    if (SecureKeyboard.target.value?.controller == controller) {
      // Clear immediately without using hide() which has callback delay
      SecureKeyboard.target.value = null;
      SecureKeyboard.visible.value = false;
      SecureKeyboard.inset.value = 0;
    }
    
    // Then delay disposal to ensure dialog is fully closed and all animations complete
    // 800ms accounts for dialog close animation + any potential rebuilds
    Future.delayed(const Duration(milliseconds: 800), () {
      SecurePassphrase.disposeController(controller);
    });
    
    return password?.isNotEmpty == true ? password : null;
  }


  @override
  Widget build(BuildContext context) {
    return LoadingOverlay(
      isLoading: _isCreating || _isImporting || _isExporting,
      message: _isCreating
          ? 'Creating vault...'
          : _isImporting
              ? 'Importing vault...'
              : _isExporting
                  ? 'Exporting vault...'
                  : 'Processing...',
      progress: _isImporting
          ? _importProgress
          : _isExporting
              ? _exportProgress
              : null,
      child: Scaffold(
        backgroundColor: CyberpunkTheme.background,
        appBar: AppBar(
          title: const Text(
            'NOLEAK VAULTS',
            style: TextStyle(
              letterSpacing: 3,
              fontWeight: FontWeight.w600,
            ),
          ),
          backgroundColor: Colors.transparent,
          elevation: 0,
          actions: [
            // Hide All button - only show when there are revealed details
            if (_hasRevealedDetails)
              IconButton(
                icon: const Icon(Icons.visibility_off, color: CyberpunkTheme.neonGreen),
                tooltip: 'Hide All Details',
                onPressed: _hideAllDetails,
              ),
            // Settings button
            IconButton(
              icon: const Icon(Icons.settings, color: CyberpunkTheme.textSecondary),
              tooltip: 'Settings',
              onPressed: _showSettings,
            ),
            if (widget.registry.vaultCount > 0)
              Padding(
                padding: const EdgeInsets.only(right: 8),
                child: Center(
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                    decoration: BoxDecoration(
                      border: Border.all(color: CyberpunkTheme.neonGreen.withOpacity(0.3)),
                      borderRadius: BorderRadius.circular(20),
                    ),
                    child: Text(
                      '${widget.registry.vaultCount}/${VaultRegistry.maxVaults}',
                      style: const TextStyle(
                        color: CyberpunkTheme.neonGreen,
                        fontSize: 12,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                ),
              ),
          ],
        ),
        body: ListenableBuilder(
          listenable: widget.registry,
          builder: (context, _) {
            if (widget.registry.isLoading) {
              return const Center(
                child: CircularProgressIndicator(
                  color: CyberpunkTheme.neonGreen,
                ),
              );
            }

            if (widget.registry.vaults.isEmpty) {
              return _buildEmptyState();
            }

            return _buildVaultList();
          },
        ),
        floatingActionButton: Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            // Info button - bottom left
            Padding(
              padding: const EdgeInsets.only(left: 32),
              child: FloatingActionButton.small(
                heroTag: 'info_btn',
                onPressed: _openInfoPage,
                backgroundColor: CyberpunkTheme.surface,
                foregroundColor: CyberpunkTheme.neonGreen,
                elevation: 4,
                child: const Icon(Icons.info_outline, size: 20),
              ),
            ),
            // Create button - bottom right (only when vaults exist and can add more)
            if (widget.registry.canAddVault && widget.registry.vaults.isNotEmpty)
              Container(
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(16),
                  boxShadow: [
                    BoxShadow(
                      color: CyberpunkTheme.neonGreen.withOpacity(0.4),
                      blurRadius: 20,
                      spreadRadius: 2,
                    ),
                  ],
                ),
                child: FloatingActionButton.extended(
                  heroTag: 'create_btn',
                  onPressed: (_isCreating || _isImporting || _isExporting) ? null : _createVault,
                  backgroundColor: CyberpunkTheme.neonGreen,
                  foregroundColor: CyberpunkTheme.background,
                  icon: const Icon(Icons.add),
                  label: const Text(
                    'CREATE',
                    style: TextStyle(fontWeight: FontWeight.bold, letterSpacing: 1),
                  ),
                ),
              )
            else
              const SizedBox.shrink(),
          ],
        ),
        floatingActionButtonLocation: FloatingActionButtonLocation.centerFloat,
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            // Glowing shield icon
            Container(
              padding: const EdgeInsets.all(32),
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                boxShadow: [
                  BoxShadow(
                    color: CyberpunkTheme.neonGreen.withOpacity(0.2),
                    blurRadius: 50,
                    spreadRadius: 10,
                  ),
                ],
              ),
              child: const Icon(
                Icons.shield_outlined,
                size: 80,
                color: CyberpunkTheme.neonGreen,
              ),
            ),
            const SizedBox(height: 24),
            // Cyberpunk slogan with glitch effect styling
            ShaderMask(
              shaderCallback: (bounds) => LinearGradient(
                colors: [
                  CyberpunkTheme.neonGreen,
                  CyberpunkTheme.neonGreen.withOpacity(0.7),
                  CyberpunkTheme.textPrimary,
                ],
                stops: const [0.0, 0.5, 1.0],
              ).createShader(bounds),
              child: const Text(
                'TAKE BACK CONTROL',
                style: TextStyle(
                  fontSize: 22,
                  fontWeight: FontWeight.w900,
                  color: Colors.white,
                  letterSpacing: 4,
                ),
                textAlign: TextAlign.center,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              'OF YOUR PRIVACY',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.w300,
                color: CyberpunkTheme.neonGreen.withOpacity(0.8),
                letterSpacing: 6,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 32),
            const Text(
              'NO VAULTS YET',
              style: TextStyle(
                fontSize: 24,
                fontWeight: FontWeight.bold,
                color: CyberpunkTheme.textPrimary,
                letterSpacing: 3,
              ),
            ),
            const SizedBox(height: 8),
            const Text(
              'Create a new vault or import an existing one',
              style: TextStyle(
                fontSize: 14,
                color: CyberpunkTheme.textSecondary,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 40),
            SizedBox(
              width: 280,
              child: CyberButton(
                text: 'CREATE VAULT',
                icon: Icons.add,
                onPressed: (_isCreating || _isImporting || _isExporting) ? null : _createVault,
                isLoading: _isCreating,
              ),
            ),
            const SizedBox(height: 16),
            SizedBox(
              width: 280,
              child: CyberButton(
                text: 'IMPORT VAULT',
                icon: Icons.file_download,
                onPressed: (_isImporting || _isCreating || _isExporting) ? null : _importVault,
                isLoading: _isImporting,
                outlined: true,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildVaultList() {
    return Column(
      children: [
        // Import button at top
        if (widget.registry.canAddVault)
          Padding(
            padding: const EdgeInsets.all(16),
            child: CyberButton(
              text: 'IMPORT EXISTING VAULT',
              icon: Icons.file_download,
              onPressed: (_isImporting || _isCreating || _isExporting) ? null : _importVault,
              isLoading: _isImporting,
              outlined: true,
            ),
          ),

        // Vault list
        Expanded(
          child: ListView.builder(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            itemCount: widget.registry.vaults.length,
            itemBuilder: (context, index) {
              final vault = widget.registry.vaults[index];
              final isRevealed = _isRevealed(vault.id);
              return _VaultCard(
                vault: vault,
                index: index,
                isRevealed: isRevealed,
                isRevealing: _revealingVaults.contains(vault.id),
                revealedTitle: isRevealed ? _revealedDetails[vault.id] : null,
                onTap: () => widget.onUnlockVault(vault.id),
                onRevealDetail: () => _revealDetail(vault),
                onHideDetail: () => _hideDetail(vault.id),
                onEditTitle: () => _editTitle(vault),
                onExport: () => _exportVault(vault),
                onDelete: () => _deleteVault(vault),
              );
            },
          ),
        ),
      ],
    );
  }
}


class _VaultCard extends StatelessWidget {
  final VaultInfo vault;
  final int index;
  final bool isRevealed;
  final bool isRevealing;
  final String? revealedTitle;
  final VoidCallback onTap;
  final VoidCallback onRevealDetail;
  final VoidCallback onHideDetail;
  final VoidCallback onEditTitle;
  final VoidCallback onExport;
  final VoidCallback onDelete;

  const _VaultCard({
    required this.vault,
    required this.index,
    required this.isRevealed,
    required this.isRevealing,
    this.revealedTitle,
    required this.onTap,
    required this.onRevealDetail,
    required this.onHideDetail,
    required this.onEditTitle,
    required this.onExport,
    required this.onDelete,
  });

  String get displayTitle {
    if (isRevealed && revealedTitle != null && revealedTitle!.isNotEmpty) {
      return revealedTitle!;
    }
    return 'Vault #${index + 1}';
  }

  String _formatSize(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }

  String get displaySize {
    if (isRevealed) return _formatSize(vault.sizeBytes);
    return '•••••';
  }

  String get displayDate {
    if (isRevealed) return _formatDate(vault.createdAt);
    return '••••••••';
  }

  String _formatDate(DateTime date) {
    return '${date.day}/${date.month}/${date.year}';
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: CyberpunkTheme.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: isRevealed
              ? CyberpunkTheme.neonGreen.withOpacity(0.5)
              : CyberpunkTheme.surfaceBorder,
        ),
        boxShadow: isRevealed
            ? [
                BoxShadow(
                  color: CyberpunkTheme.neonGreen.withOpacity(0.1),
                  blurRadius: 20,
                  spreadRadius: 2,
                ),
              ]
            : null,
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(16),
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                // Vault icon with glow
                Container(
                  width: 56,
                  height: 56,
                  decoration: BoxDecoration(
                    color: isRevealed
                        ? CyberpunkTheme.neonGreen.withOpacity(0.1)
                        : CyberpunkTheme.surfaceLight,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: isRevealed
                          ? CyberpunkTheme.neonGreen.withOpacity(0.3)
                          : CyberpunkTheme.surfaceBorder,
                    ),
                    boxShadow: isRevealed
                        ? [
                            BoxShadow(
                              color: CyberpunkTheme.neonGreen.withOpacity(0.2),
                              blurRadius: 12,
                            ),
                          ]
                        : null,
                  ),
                  child: Icon(
                    isRevealed ? Icons.lock_open : Icons.lock,
                    color: isRevealed
                        ? CyberpunkTheme.neonGreen
                        : CyberpunkTheme.textSecondary,
                    size: 28,
                  ),
                ),
                const SizedBox(width: 16),

                // Title and info
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Expanded(
                            child: Text(
                              displayTitle,
                              style: TextStyle(
                                color: isRevealed
                                    ? CyberpunkTheme.textPrimary
                                    : CyberpunkTheme.textSecondary,
                                fontSize: 16,
                                fontWeight: FontWeight.w600,
                                fontStyle: isRevealed
                                    ? FontStyle.normal
                                    : FontStyle.italic,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          IconButton(
                            icon: isRevealing
                                ? const SizedBox(
                                    width: 20,
                                    height: 20,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2,
                                      valueColor: AlwaysStoppedAnimation<Color>(
                                        CyberpunkTheme.neonGreen,
                                      ),
                                    ),
                                  )
                                : Icon(
                                    isRevealed
                                        ? Icons.visibility_off
                                        : Icons.visibility,
                                    size: 20,
                                    color: isRevealed
                                        ? CyberpunkTheme.neonGreen
                                        : CyberpunkTheme.textHint,
                                  ),
                            onPressed: isRevealing ? null : (isRevealed ? onHideDetail : onRevealDetail),
                            tooltip: isRevealed ? 'Hide details' : 'Reveal details',
                            constraints: const BoxConstraints(),
                            padding: const EdgeInsets.all(8),
                          ),
                        ],
                      ),
                      const SizedBox(height: 4),
                      Text(
                        '$displaySize • Created $displayDate',
                        style: TextStyle(
                          color: isRevealed
                              ? CyberpunkTheme.textSecondary
                              : CyberpunkTheme.textHint,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                ),

                // Menu
                PopupMenuButton<String>(
                  icon: Icon(Icons.more_vert, color: CyberpunkTheme.textSecondary),
                  color: CyberpunkTheme.surface,
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                    side: BorderSide(color: CyberpunkTheme.surfaceBorder),
                  ),
                  onSelected: (value) {
                    switch (value) {
                      case 'edit':
                        onEditTitle();
                        break;
                      case 'export':
                        onExport();
                        break;
                      case 'delete':
                        onDelete();
                        break;
                    }
                  },
                  itemBuilder: (context) => [
                    PopupMenuItem(
                      value: 'edit',
                      child: Row(
                        children: [
                          Icon(Icons.edit, size: 20, color: CyberpunkTheme.neonGreen),
                          const SizedBox(width: 12),
                          const Text('Edit Title', style: TextStyle(color: CyberpunkTheme.textPrimary)),
                        ],
                      ),
                    ),
                    PopupMenuItem(
                      value: 'export',
                      child: Row(
                        children: [
                          Icon(Icons.file_upload, size: 20, color: CyberpunkTheme.neonGreen),
                          const SizedBox(width: 12),
                          const Text('Export', style: TextStyle(color: CyberpunkTheme.textPrimary)),
                        ],
                      ),
                    ),
                    PopupMenuItem(
                      value: 'delete',
                      child: Row(
                        children: [
                          const Icon(Icons.delete, size: 20, color: CyberpunkTheme.error),
                          const SizedBox(width: 12),
                          const Text('Delete', style: TextStyle(color: CyberpunkTheme.error)),
                        ],
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}


// ========== Dialogs ==========

class _CreateVaultDialog extends StatefulWidget {
  const _CreateVaultDialog();

  @override
  State<_CreateVaultDialog> createState() => _CreateVaultDialogState();
}

class _CreateVaultDialogState extends State<_CreateVaultDialog> {
  final _titleController = TextEditingController();
  final _passwordController = TextEditingController();
  final _confirmController = TextEditingController();
  bool _obscurePassword = true;
  bool _obscureConfirm = true;

  bool get _isValid {
    return _titleController.text.isNotEmpty &&
        _meetsPassphraseRules(_passwordController.text) &&
        _passwordController.text == _confirmController.text;
  }

  bool _meetsPassphraseRules(String pass) {
    return pass.length >= 12 && _hasNumber(pass) && _hasSymbol(pass);
  }

  bool _hasNumber(String pass) {
    return RegExp(r'[0-9]').hasMatch(pass);
  }

  bool _hasSymbol(String pass) {
    return RegExp(r'[^A-Za-z0-9]').hasMatch(pass);
  }

  @override
  void dispose() {
    _titleController.dispose();
    SecurePassphrase.disposeController(_passwordController);
    SecurePassphrase.disposeController(_confirmController);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: CyberpunkTheme.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
        side: BorderSide(color: CyberpunkTheme.neonGreen.withOpacity(0.3)),
      ),
      child: Container(
        width: MediaQuery.of(context).size.width * 0.9,
        constraints: const BoxConstraints(maxWidth: 400),
        padding: const EdgeInsets.all(24),
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Header
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: CyberpunkTheme.neonGreen.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: const Icon(
                      Icons.add_box_outlined,
                      color: CyberpunkTheme.neonGreen,
                      size: 24,
                    ),
                  ),
                  const SizedBox(width: 16),
                  const Expanded(
                    child: Text(
                      'CREATE VAULT',
                      style: TextStyle(
                        color: CyberpunkTheme.textPrimary,
                        fontSize: 20,
                        fontWeight: FontWeight.bold,
                        letterSpacing: 2,
                      ),
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close, color: CyberpunkTheme.textSecondary),
                    onPressed: () => Navigator.pop(context),
                  ),
                ],
              ),
              const SizedBox(height: 24),

              // Vault name
              CyberTextField(
                controller: _titleController,
                labelText: 'Vault Name',
                hintText: 'e.g., Personal, Work, Photos',
                onChanged: (_) => setState(() {}),
              ),
              const SizedBox(height: 20),

              // Password
              CyberTextField(
                controller: _passwordController,
                labelText: 'Password',
                hintText: 'Min 12 chars + 1 number + 1 symbol',
                obscureText: _obscurePassword,
                onChanged: (_) => setState(() {}),
                suffixIcon: IconButton(
                  icon: Icon(
                    _obscurePassword ? Icons.visibility : Icons.visibility_off,
                    color: CyberpunkTheme.textSecondary,
                  ),
                  onPressed: () => setState(() => _obscurePassword = !_obscurePassword),
                ),
              ),

              // Password strength meter
              PasswordStrengthMeter(
                password: _passwordController.text,
                minLength: 12,
              ),
              if (_passwordController.text.isNotEmpty &&
                  !_meetsPassphraseRules(_passwordController.text))
                Padding(
                  padding: const EdgeInsets.only(top: 8),
                  child: Text(
                    'Must include at least 1 number and 1 symbol',
                    style: TextStyle(
                      color: CyberpunkTheme.error.withOpacity(0.9),
                      fontSize: 12,
                    ),
                  ),
                ),
              const SizedBox(height: 20),

              // Confirm password
              CyberTextField(
                controller: _confirmController,
                labelText: 'Confirm Password',
                obscureText: _obscureConfirm,
                onChanged: (_) => setState(() {}),
                errorText: _confirmController.text.isNotEmpty &&
                        _passwordController.text != _confirmController.text
                    ? 'Passwords do not match'
                    : null,
                suffixIcon: IconButton(
                  icon: Icon(
                    _obscureConfirm ? Icons.visibility : Icons.visibility_off,
                    color: CyberpunkTheme.textSecondary,
                  ),
                  onPressed: () => setState(() => _obscureConfirm = !_obscureConfirm),
                ),
              ),
              const SizedBox(height: 24),

              // Warning
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: CyberpunkTheme.warning.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: CyberpunkTheme.warning.withOpacity(0.3)),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.warning_amber, color: CyberpunkTheme.warning, size: 20),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        'No recovery option. If you forget your password, your data will be permanently lost.',
                        style: TextStyle(
                          color: CyberpunkTheme.warning.withOpacity(0.9),
                          fontSize: 12,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 24),

              // Buttons
              Row(
                children: [
                  Expanded(
                    child: TextButton(
                      onPressed: () => Navigator.pop(context),
                      child: const Text(
                        'CANCEL',
                        style: TextStyle(color: CyberpunkTheme.textSecondary),
                      ),
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    flex: 2,
                    child: CyberButton(
                      text: 'CREATE',
                      icon: Icons.add,
                      onPressed: _isValid
                          ? () => Navigator.pop(context, {
                                'title': _titleController.text,
                                'password': _passwordController.text,
                              })
                          : null,
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _EditTitleDialog extends StatefulWidget {
  final String currentTitle;

  const _EditTitleDialog({required this.currentTitle});

  @override
  State<_EditTitleDialog> createState() => _EditTitleDialogState();
}

class _EditTitleDialogState extends State<_EditTitleDialog> {
  late TextEditingController _controller;

  @override
  void initState() {
    super.initState();
    _controller = TextEditingController(text: widget.currentTitle);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: CyberpunkTheme.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: BorderSide(color: CyberpunkTheme.neonGreen.withOpacity(0.3)),
      ),
      title: const Text(
        'EDIT TITLE',
        style: TextStyle(
          color: CyberpunkTheme.neonGreen,
          letterSpacing: 2,
          fontWeight: FontWeight.w600,
        ),
      ),
      content: CyberTextField(
        controller: _controller,
        labelText: 'Vault Name',
        onChanged: (_) => setState(() {}),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Cancel', style: TextStyle(color: CyberpunkTheme.textSecondary)),
        ),
        TextButton(
          onPressed: _controller.text.isNotEmpty
              ? () => Navigator.pop(context, _controller.text)
              : null,
          child: const Text('SAVE', style: TextStyle(color: CyberpunkTheme.neonGreen)),
        ),
      ],
    );
  }
}

/// Settings bottom sheet
class _SettingsSheet extends StatefulWidget {
  const _SettingsSheet();

  @override
  State<_SettingsSheet> createState() => _SettingsSheetState();
}

class _SettingsSheetState extends State<_SettingsSheet> {
  bool _isProcessing = false;

  Future<void> _toggleSecureKeyboard(bool newValue) async {
    if (_isProcessing) return;

    // If turning ON, just enable it
    if (newValue) {
      await AppSettings.instance.setSecureKeyboardEnabled(true);
      return;
    }

    // If turning OFF, show warning dialog
    final confirmed = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) => const _SecureKeyboardWarningDialog(),
    );

    if (confirmed != true || !mounted) return;

    // Require biometric verification
    setState(() => _isProcessing = true);
    try {
      final biometricSuccess = await VaultChannel.authenticateBiometric();
      if (!biometricSuccess) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Biometric verification required'),
              backgroundColor: CyberpunkTheme.error,
            ),
          );
        }
        return;
      }

      await AppSettings.instance.setSecureKeyboardEnabled(false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: const Text('Secure keyboard disabled'),
            backgroundColor: CyberpunkTheme.warning,
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _isProcessing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header
            Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: CyberpunkTheme.neonGreen.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: const Icon(
                    Icons.settings,
                    color: CyberpunkTheme.neonGreen,
                    size: 20,
                  ),
                ),
                const SizedBox(width: 12),
                const Text(
                  'SETTINGS',
                  style: TextStyle(
                    color: CyberpunkTheme.textPrimary,
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                    letterSpacing: 2,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 24),
            
            // Secure Keyboard toggle
            ListenableBuilder(
              listenable: AppSettings.instance,
              builder: (context, _) {
                final secureKeyboardEnabled = AppSettings.instance.secureKeyboardEnabled;
                return Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: CyberpunkTheme.surfaceLight,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: secureKeyboardEnabled
                          ? CyberpunkTheme.surfaceBorder
                          : CyberpunkTheme.warning.withOpacity(0.5),
                    ),
                  ),
                  child: Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(
                          color: secureKeyboardEnabled
                              ? CyberpunkTheme.neonGreen.withOpacity(0.1)
                              : CyberpunkTheme.warning.withOpacity(0.1),
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: Icon(
                          Icons.keyboard,
                          color: secureKeyboardEnabled
                              ? CyberpunkTheme.neonGreen
                              : CyberpunkTheme.warning,
                          size: 24,
                        ),
                      ),
                      const SizedBox(width: 16),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            const Text(
                              'Secure Keyboard',
                              style: TextStyle(
                                color: CyberpunkTheme.textPrimary,
                                fontSize: 14,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                            const SizedBox(height: 2),
                            Text(
                              secureKeyboardEnabled
                                  ? 'Protected from keyloggers'
                                  : 'Using system keyboard',
                              style: TextStyle(
                                color: secureKeyboardEnabled
                                    ? CyberpunkTheme.textHint
                                    : CyberpunkTheme.warning,
                                fontSize: 12,
                              ),
                            ),
                          ],
                        ),
                      ),
                      _isProcessing
                          ? const SizedBox(
                              width: 24,
                              height: 24,
                              child: CircularProgressIndicator(
                                strokeWidth: 2,
                                color: CyberpunkTheme.neonGreen,
                              ),
                            )
                          : Switch(
                              value: secureKeyboardEnabled,
                              onChanged: _toggleSecureKeyboard,
                              activeColor: CyberpunkTheme.neonGreen,
                              activeTrackColor: CyberpunkTheme.neonGreen.withOpacity(0.3),
                              inactiveThumbColor: CyberpunkTheme.warning,
                              inactiveTrackColor: CyberpunkTheme.warning.withOpacity(0.3),
                            ),
                    ],
                  ),
                );
              },
            ),

            const SizedBox(height: 16),

            // App Lock toggle
            ListenableBuilder(
              listenable: AppSettings.instance,
              builder: (context, _) {
                final appLockEnabled = AppSettings.instance.appLockEnabled;
                return Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: CyberpunkTheme.surfaceLight,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: CyberpunkTheme.surfaceBorder),
                  ),
                  child: Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(
                          color: appLockEnabled
                              ? CyberpunkTheme.neonGreen.withOpacity(0.1)
                              : CyberpunkTheme.surfaceBorder.withOpacity(0.3),
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: Icon(
                          Icons.fingerprint,
                          color: appLockEnabled
                              ? CyberpunkTheme.neonGreen
                              : CyberpunkTheme.textHint,
                          size: 24,
                        ),
                      ),
                      const SizedBox(width: 16),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            const Text(
                              'App Lock',
                              style: TextStyle(
                                color: CyberpunkTheme.textPrimary,
                                fontSize: 14,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                            const SizedBox(height: 2),
                            Text(
                              appLockEnabled
                                  ? 'Biometric required to open app'
                                  : 'No biometric on app launch',
                              style: const TextStyle(
                                color: CyberpunkTheme.textHint,
                                fontSize: 12,
                              ),
                            ),
                          ],
                        ),
                      ),
                      Switch(
                        value: appLockEnabled,
                        onChanged: (value) {
                          AppSettings.instance.setAppLockEnabled(value);
                        },
                        activeColor: CyberpunkTheme.neonGreen,
                        activeTrackColor: CyberpunkTheme.neonGreen.withOpacity(0.3),
                        inactiveThumbColor: CyberpunkTheme.textHint,
                        inactiveTrackColor: CyberpunkTheme.surfaceBorder,
                      ),
                    ],
                  ),
                );
              },
            ),
            
            const SizedBox(height: 16),
            
            // Idle timeout setting
            ListenableBuilder(
              listenable: AppSettings.instance,
              builder: (context, _) {
                final idleSeconds = AppSettings.instance.idleTimeoutSeconds;
                return Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: CyberpunkTheme.surfaceLight,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: CyberpunkTheme.surfaceBorder),
                  ),
                  child: Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(
                          color: CyberpunkTheme.neonGreen.withOpacity(0.1),
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: const Icon(
                          Icons.timer_outlined,
                          color: CyberpunkTheme.neonGreen,
                          size: 24,
                        ),
                      ),
                      const SizedBox(width: 16),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            const Text(
                              'Idle Timeout',
                              style: TextStyle(
                                color: CyberpunkTheme.textPrimary,
                                fontSize: 14,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                            const SizedBox(height: 2),
                            Text(
                              'Auto-lock after $idleSeconds seconds of inactivity',
                              style: const TextStyle(
                                color: CyberpunkTheme.textHint,
                                fontSize: 12,
                              ),
                            ),
                          ],
                        ),
                      ),
                      DropdownButtonHideUnderline(
                        child: DropdownButton<int>(
                          value: idleSeconds,
                          dropdownColor: CyberpunkTheme.surface,
                          style: const TextStyle(
                            color: CyberpunkTheme.neonGreen,
                            fontSize: 13,
                            fontWeight: FontWeight.w600,
                          ),
                          items: AppSettings.idleTimeoutOptions
                              .map((value) => DropdownMenuItem(
                                    value: value,
                                    child: Text('${value}s'),
                                  ))
                              .toList(),
                          onChanged: (value) {
                            if (value != null) {
                              AppSettings.instance.setIdleTimeoutSeconds(value);
                            }
                          },
                        ),
                      ),
                    ],
                  ),
                );
              },
            ),

            const SizedBox(height: 16),

            // Session limit setting
            ListenableBuilder(
              listenable: AppSettings.instance,
              builder: (context, _) {
                final sessionMinutes = AppSettings.instance.sessionLimitMinutes;
                return Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: CyberpunkTheme.surfaceLight,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: CyberpunkTheme.surfaceBorder),
                  ),
                  child: Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(
                          color: CyberpunkTheme.neonGreen.withOpacity(0.1),
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: const Icon(
                          Icons.lock_clock,
                          color: CyberpunkTheme.neonGreen,
                          size: 24,
                        ),
                      ),
                      const SizedBox(width: 16),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            const Text(
                              'Session Limit',
                              style: TextStyle(
                                color: CyberpunkTheme.textPrimary,
                                fontSize: 14,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                            const SizedBox(height: 2),
                            Text(
                              'Re-auth every $sessionMinutes minutes',
                              style: const TextStyle(
                                color: CyberpunkTheme.textHint,
                                fontSize: 12,
                              ),
                            ),
                          ],
                        ),
                      ),
                      DropdownButtonHideUnderline(
                        child: DropdownButton<int>(
                          value: sessionMinutes,
                          dropdownColor: CyberpunkTheme.surface,
                          style: const TextStyle(
                            color: CyberpunkTheme.neonGreen,
                            fontSize: 13,
                            fontWeight: FontWeight.w600,
                          ),
                          items: AppSettings.sessionLimitOptions
                              .map((value) => DropdownMenuItem(
                                    value: value,
                                    child: Text('${value}m'),
                                  ))
                              .toList(),
                          onChanged: (value) {
                            if (value != null) {
                              AppSettings.instance.setSessionLimitMinutes(value);
                            }
                          },
                        ),
                      ),
                    ],
                  ),
                );
              },
            ),

            const SizedBox(height: 16),

            // Info text
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 4),
              child: Row(
                children: [
                  Icon(
                    Icons.info_outline,
                    color: CyberpunkTheme.textHint,
                    size: 14,
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'Vault unlock always requires biometric after password',
                      style: TextStyle(
                        color: CyberpunkTheme.textHint,
                        fontSize: 11,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            
            const SizedBox(height: 24),
          ],
        ),
      ),
    );
  }
}

/// Warning dialog for disabling secure keyboard
class _SecureKeyboardWarningDialog extends StatefulWidget {
  const _SecureKeyboardWarningDialog();

  @override
  State<_SecureKeyboardWarningDialog> createState() => _SecureKeyboardWarningDialogState();
}

class _SecureKeyboardWarningDialogState extends State<_SecureKeyboardWarningDialog> {
  bool _confirmed = false;

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: CyberpunkTheme.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: BorderSide(color: CyberpunkTheme.warning.withOpacity(0.5)),
      ),
      title: Row(
        children: [
          Icon(Icons.warning_amber, color: CyberpunkTheme.warning, size: 24),
          const SizedBox(width: 12),
          const Text(
            'SECURITY WARNING',
            style: TextStyle(
              color: CyberpunkTheme.warning,
              fontSize: 16,
              fontWeight: FontWeight.bold,
              letterSpacing: 1,
            ),
          ),
        ],
      ),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Disabling the secure keyboard exposes you to the following risks:',
            style: TextStyle(
              color: CyberpunkTheme.textPrimary,
              fontSize: 14,
            ),
          ),
          const SizedBox(height: 16),
          _buildRiskItem('Keyloggers can capture your passwords'),
          _buildRiskItem('Malicious apps may record your keystrokes'),
          _buildRiskItem('Third-party keyboards may store your input'),
          _buildRiskItem('Your passphrase could be compromised'),
          const SizedBox(height: 20),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: CyberpunkTheme.warning.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: CyberpunkTheme.warning.withOpacity(0.3)),
            ),
            child: Row(
              children: [
                Checkbox(
                  value: _confirmed,
                  onChanged: (value) => setState(() => _confirmed = value ?? false),
                  activeColor: CyberpunkTheme.warning,
                  checkColor: CyberpunkTheme.background,
                  side: BorderSide(color: CyberpunkTheme.warning),
                ),
                const SizedBox(width: 8),
                const Expanded(
                  child: Text(
                    'I understand the risks and want to proceed',
                    style: TextStyle(
                      color: CyberpunkTheme.textPrimary,
                      fontSize: 13,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context, false),
          child: const Text(
            'Cancel',
            style: TextStyle(color: CyberpunkTheme.textSecondary),
          ),
        ),
        TextButton(
          onPressed: _confirmed ? () => Navigator.pop(context, true) : null,
          child: Text(
            'Disable',
            style: TextStyle(
              color: _confirmed ? CyberpunkTheme.warning : CyberpunkTheme.textHint,
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildRiskItem(String text) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.error_outline, color: CyberpunkTheme.error, size: 16),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              text,
              style: const TextStyle(
                color: CyberpunkTheme.textSecondary,
                fontSize: 13,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
