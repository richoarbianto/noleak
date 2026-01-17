/// VaultHomeScreen - File Browser and Management
/// 
/// Main screen for browsing and managing files within an unlocked vault.
/// Provides a file manager interface with folder organization.
/// 
/// FEATURES:
/// - Browse files and folders
/// - Import files and folders
/// - Create folders
/// - Move, copy, rename, delete files
/// - Export files (with security warning)
/// - Search files by name
/// - Change vault password
/// - Export entire vault
/// 
/// SECURITY:
/// - Auto-lock on idle (configurable timeout)
/// - Session limit requiring re-authentication
/// - Timer freezing during file operations
/// - Secure file deletion with zeroization

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
import '../models/vault_state.dart';
import '../services/vault_state_manager.dart';
import '../services/vault_channel.dart';
import '../services/streaming_import_service.dart';
import '../services/transfer_progress_service.dart';
import '../services/app_settings.dart';
import '../theme/cyberpunk_theme.dart';
import '../widgets/cyber_text_field.dart';
import '../widgets/cyber_button.dart';
import '../widgets/loading_overlay.dart';
import '../widgets/password_strength_meter.dart';
import '../utils/secure_logger.dart';
import '../utils/secure_passphrase.dart';
import '../widgets/secure_keyboard.dart';

/// Main file browser screen for an unlocked vault.
/// 
/// The [onLogout] callback is called when user locks the vault
/// or session expires.
class VaultHomeScreen extends StatefulWidget {
  final VaultStateManager stateManager;
  final VoidCallback? onLogout;

  const VaultHomeScreen({
    super.key,
    required this.stateManager,
    this.onLogout,
  });

  @override
  State<VaultHomeScreen> createState() => _VaultHomeScreenState();
}

class _VaultHomeScreenState extends State<VaultHomeScreen> {
  final _searchController = TextEditingController();
  final _streamingImportService = StreamingImportService.instance;
  final _transferProgressService = TransferProgressService.instance;
  String _searchQuery = '';
  bool _isImporting = false;
  bool _isExporting = false;
  bool _isVaultOp = false;
  double? _importProgress;
  double? _exportProgress;
  List<int>? _activeImportId;
  int? _activeImportSessionId;
  bool _isImportFinalizing = false;
  String _currentFolderPath = '';
  StreamSubscription<ImportProgress>? _importProgressSub;
  StreamSubscription<TransferProgress>? _transferProgressSub;

  @override
  void initState() {
    super.initState();
    _streamingImportService.initialize();
    _importProgressSub = _streamingImportService.progressStream.listen((progress) {
      if (!_isImporting) return;
      if (_activeImportSessionId != null &&
          progress.sessionId != _activeImportSessionId) {
        return;
      }
      if (_activeImportId != null && !listEquals(progress.importId, _activeImportId)) return;
      final normalized = (progress.percentage / 100).clamp(0.0, 1.0);
      final isFinalizing = !progress.isComplete && normalized >= 1.0;
      if (mounted) {
        setState(() {
          _activeImportId ??= progress.importId;
          _isImportFinalizing = isFinalizing;
          _importProgress = progress.isComplete
              ? 1.0
              : (isFinalizing ? 0.99 : normalized);
        });
      }
    });

    _transferProgressService.initialize();
    _transferProgressSub = _transferProgressService.progressStream.listen((progress) {
      if (!_isExporting) return;
      if (progress.operation != 'export_vault') return;
      if (mounted) {
        setState(() {
          _exportProgress = progress.normalized;
        });
      }
    });
  }

  @override
  void dispose() {
    _importProgressSub?.cancel();
    _transferProgressSub?.cancel();
    _searchController.dispose();
    super.dispose();
  }

  List<VaultEntry> get _filteredEntries {
    if (_searchQuery.isNotEmpty) {
      return widget.stateManager.searchEntries(_searchQuery);
    }
    final current = _currentFolderPath;
    return widget.stateManager.entries
        .where((entry) => widget.stateManager.folderForEntry(entry) == current)
        .toList();
  }

  bool get _isSearching => _searchQuery.isNotEmpty;

  List<String> get _visibleFolders {
    if (_isSearching) return [];
    final prefix = _currentFolderPath.isEmpty ? '' : '$_currentFolderPath/';
    final folders = <String>{};
    for (final path in widget.stateManager.folders) {
      if (prefix.isEmpty) {
        final segment = path.split('/').first;
        if (segment.isNotEmpty) {
          folders.add(segment);
        }
      } else if (path.startsWith(prefix)) {
        final remainder = path.substring(prefix.length);
        if (remainder.isEmpty) continue;
        final segment = remainder.split('/').first;
        if (segment.isNotEmpty) {
          folders.add(segment);
        }
      }
    }
    final list = folders.toList();
    list.sort();
    return list;
  }

  void _enterFolder(String name) {
    widget.stateManager.recordActivity();
    setState(() {
      _currentFolderPath =
          _currentFolderPath.isEmpty ? name : '$_currentFolderPath/$name';
    });
  }

  void _goUpFolder() {
    if (_currentFolderPath.isEmpty) return;
    widget.stateManager.recordActivity();
    final parts = _currentFolderPath.split('/');
    parts.removeLast();
    setState(() {
      _currentFolderPath = parts.join('/');
    });
  }

  String get _currentPathLabel {
    if (_currentFolderPath.isEmpty) return '/';
    return '/$_currentFolderPath';
  }

  void _lockAndLogout() {
    widget.stateManager.lockVault();
    widget.onLogout?.call();
  }

  Future<void> _importFile() async {
    final sessionId = DateTime.now().microsecondsSinceEpoch;

    try {
      // Verify vault is open before attempting import
      final isOpen = await VaultChannel.isVaultOpen();
      if (!isOpen) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Vault is not open. Please unlock again.'),
              backgroundColor: CyberpunkTheme.error,
            ),
          );
        }
        return;
      }

      // Freeze timers during import to prevent session timeout
      widget.stateManager.freezeTimers();
      
      // Keep screen awake during import
      await VaultChannel.enableWakelock();
      SecureLogger.d('VaultHomeScreen', '_importFile: wakelock enabled');
      
      await widget.stateManager.runWithoutAutoLock(() async {
        // Pick file first BEFORE showing progress
        final fileInfo = await VaultChannel.pickFile();
        if (fileInfo == null) {
          // User cancelled file picker, no need to reset state since we haven't started
          return;
        }

        // NOW show progress after file is selected
        if (mounted) {
          setState(() {
            _isImporting = true;
            _importProgress = 0;
            _activeImportId = null;
            _activeImportSessionId = sessionId;
            _isImportFinalizing = false;
          });
        }

        final result = await VaultChannel.importFile(
          fileInfo['uri'] as String,
          sessionId: sessionId,
        );
        
        // Force update progress to 100% on success for small files
        if (mounted) {
           setState(() {
            _importProgress = 1.0;
            _isImportFinalizing = true;
          });
          // Small delay to let user see 100%
          await Future.delayed(const Duration(milliseconds: 200));
        }

        final fileIdRaw = result['fileId'];
        if (fileIdRaw is List) {
          final fileId = List<int>.from(fileIdRaw);
          if (_currentFolderPath.isNotEmpty) {
            await widget.stateManager.applyImportedFiles({
              fileId: _currentFolderPath,
            });
          }
        }
        await widget.stateManager.refreshEntries();
        
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Imported: ${result['name']}'),
              backgroundColor: CyberpunkTheme.neonGreen.withOpacity(0.9),
            ),
          );
        }
      });
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
      // Disable wakelock
      await VaultChannel.disableWakelock();
      SecureLogger.d('VaultHomeScreen', '_importFile: wakelock disabled');
      
      // Always unfreeze timers when done
      widget.stateManager.unfreezeTimers();
      if (mounted) {
        setState(() {
          _isImporting = false;
          _importProgress = null;
          _activeImportId = null;
          _activeImportSessionId = null;
          _isImportFinalizing = false;
        });
      }
    }
  }

  Future<void> _importFolder() async {
    SecureLogger.d('VaultHomeScreen', '_importFolder: starting, currentFolderPath=$_currentFolderPath');
    final sessionId = DateTime.now().microsecondsSinceEpoch;

    try {
      final isOpen = await VaultChannel.isVaultOpen();
      if (!isOpen) {
        SecureLogger.e('VaultHomeScreen', '_importFolder: vault is not open');
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Vault is not open. Please unlock again.'),
              backgroundColor: CyberpunkTheme.error,
            ),
          );
        }
        return;
      }

      // Freeze timers during import to prevent session timeout
      widget.stateManager.freezeTimers();
      
      // Keep screen awake during import
      await VaultChannel.enableWakelock();
      SecureLogger.d('VaultHomeScreen', '_importFolder: wakelock enabled');
      
      await widget.stateManager.runWithoutAutoLock(() async {
        final folderInfo = await VaultChannel.pickFolder();
        if (folderInfo == null) {
          SecureLogger.d('VaultHomeScreen', '_importFolder: user cancelled folder picker');
          return;
        }
        SecureLogger.d('VaultHomeScreen', '_importFolder: folder picked, uri=${folderInfo['uri']}');

        if (mounted) {
          setState(() {
            _isImporting = true;
            _importProgress = 0;
            _activeImportId = null;
            _activeImportSessionId = sessionId;
            _isImportFinalizing = false;
          });
        }

        SecureLogger.d('VaultHomeScreen', '_importFolder: calling VaultChannel.importFolder');
        final result = await VaultChannel.importFolder(
          folderInfo['uri'] as String,
          sessionId: sessionId,
        );

        final files = (result['files'] as List?) ?? [];
        final skipped = (result['skipped'] as num?)?.toInt() ?? 0;
        SecureLogger.d('VaultHomeScreen', '_importFolder: received ${files.length} files, skipped=$skipped');
        
        final imported = <List<int>, String>{};
        for (final item in files) {
          if (item is! Map) continue;
          final fileId = List<int>.from(item['fileId'] as List);
          var folder = (item['folder'] as String?) ?? '';
          SecureLogger.d('VaultHomeScreen', '_importFolder: file folder from native=$folder');
          if (_currentFolderPath.isNotEmpty) {
            folder = folder.isEmpty ? _currentFolderPath : '$_currentFolderPath/$folder';
          }
          SecureLogger.d('VaultHomeScreen', '_importFolder: final folder=$folder');
          imported[fileId] = folder;
        }

        if (imported.isNotEmpty) {
          SecureLogger.d('VaultHomeScreen', '_importFolder: calling applyImportedFiles with ${imported.length} files');
          await widget.stateManager.applyImportedFiles(imported);
          SecureLogger.d('VaultHomeScreen', '_importFolder: calling refreshEntries');
          // Don't call refreshEntries here - it will reload folder map from disk
          // which may fail if the file was just written. The folders are already
          // in memory from applyImportedFiles.
          // Instead, just refresh the entries list without reloading folder map.
          await widget.stateManager.refreshEntriesOnly();
          SecureLogger.d('VaultHomeScreen', '_importFolder: folders after import=${widget.stateManager.folders}');
        }

        if (mounted) {
          final count = imported.length;
          final message = skipped > 0
              ? 'Imported $count file(s), skipped $skipped'
              : 'Imported $count file(s)';
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(message),
              backgroundColor: CyberpunkTheme.neonGreen.withOpacity(0.9),
            ),
          );
        }
      });
    } catch (e) {
      SecureLogger.e('VaultHomeScreen', '_importFolder: error', e);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Import folder failed: $e'),
            backgroundColor: CyberpunkTheme.error,
          ),
        );
      }
    } finally {
      // Disable wakelock
      await VaultChannel.disableWakelock();
      SecureLogger.d('VaultHomeScreen', '_importFolder: wakelock disabled');
      
      // Always unfreeze timers when done
      widget.stateManager.unfreezeTimers();
      if (mounted) {
        setState(() {
          _isImporting = false;
          _importProgress = null;
          _activeImportId = null;
          _activeImportSessionId = null;
          _isImportFinalizing = false;
        });
      }
    }
  }

  Future<void> _showImportOptions() async {
    widget.stateManager.recordActivity();
    final action = await showModalBottomSheet<String>(
      context: context,
      backgroundColor: CyberpunkTheme.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: BorderSide(color: CyberpunkTheme.surfaceBorder),
      ),
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.insert_drive_file, color: CyberpunkTheme.neonGreen),
              title: const Text('Import File', style: TextStyle(color: CyberpunkTheme.textPrimary)),
              onTap: () => Navigator.pop(context, 'file'),
            ),
            ListTile(
              leading: const Icon(Icons.folder, color: CyberpunkTheme.neonGreen),
              title: const Text('Import Folder', style: TextStyle(color: CyberpunkTheme.textPrimary)),
              onTap: () => Navigator.pop(context, 'folder'),
            ),
            ListTile(
              leading: const Icon(Icons.create_new_folder, color: CyberpunkTheme.neonGreen),
              title: const Text('Create Folder', style: TextStyle(color: CyberpunkTheme.textPrimary)),
              onTap: () => Navigator.pop(context, 'create_folder'),
            ),
          ],
        ),
      ),
    );

    if (action == 'file') {
      await _importFile();
    } else if (action == 'folder') {
      await _importFolder();
    } else if (action == 'create_folder') {
      await _createFolder();
    }
  }

  Future<void> _createFolder() async {
    SecureLogger.d('VaultHomeScreen', '_createFolder: starting, currentFolderPath=$_currentFolderPath');
    String? name;
    
    name = await showDialog<String>(
      context: context,
      builder: (context) {
        final controller = TextEditingController();
        return AlertDialog(
          backgroundColor: CyberpunkTheme.surface,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: BorderSide(color: CyberpunkTheme.neonGreen.withOpacity(0.3)),
          ),
          title: const Text(
            'CREATE FOLDER',
            style: TextStyle(color: CyberpunkTheme.neonGreen, letterSpacing: 2),
          ),
          content: CyberTextField(
            controller: controller,
            labelText: 'Folder name',
            maxLines: 1,
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel', style: TextStyle(color: CyberpunkTheme.textSecondary)),
            ),
            TextButton(
              onPressed: () {
                Navigator.pop(context, controller.text);
              },
              child: const Text('CREATE', style: TextStyle(color: CyberpunkTheme.neonGreen)),
            ),
          ],
        );
      },
    );
    
    if (name == null) {
      SecureLogger.d('VaultHomeScreen', '_createFolder: user cancelled');
      return;
    }
    final trimmed = name.trim();
    if (trimmed.isEmpty) {
      SecureLogger.d('VaultHomeScreen', '_createFolder: name is empty after trim');
      return;
    }
    SecureLogger.d('VaultHomeScreen', '_createFolder: creating folder "$trimmed" in parent "$_currentFolderPath"');
    setState(() => _isVaultOp = true);
    // Freeze timers during folder creation (involves vault write operation)
    widget.stateManager.freezeTimers();
    try {
      await widget.stateManager.createFolder(trimmed, parent: _currentFolderPath);
      SecureLogger.d('VaultHomeScreen', '_createFolder: folder created successfully');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Folder created: $trimmed'),
            backgroundColor: CyberpunkTheme.neonGreen.withOpacity(0.9),
          ),
        );
      }
    } catch (e) {
      SecureLogger.e('VaultHomeScreen', '_createFolder: error', e);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Create folder failed: $e'),
            backgroundColor: CyberpunkTheme.error,
          ),
        );
      }
    } finally {
      widget.stateManager.unfreezeTimers();
      if (mounted) setState(() => _isVaultOp = false);
    }
  }

  Future<String?> _selectFolder({required String title}) async {
    final folders = widget.stateManager.folders;
    final options = <String>['']..addAll(folders);
    return showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: CyberpunkTheme.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: BorderSide(color: CyberpunkTheme.surfaceBorder),
        ),
        title: Text(
          title,
          style: const TextStyle(color: CyberpunkTheme.neonGreen, letterSpacing: 2),
        ),
        content: SizedBox(
          width: double.maxFinite,
          child: ListView.separated(
            shrinkWrap: true,
            itemCount: options.length,
            separatorBuilder: (_, __) => const Divider(height: 1, color: CyberpunkTheme.surfaceBorder),
            itemBuilder: (context, index) {
              final path = options[index];
              final label = path.isEmpty ? 'Root /' : '/$path';
              return ListTile(
                title: Text(label, style: const TextStyle(color: CyberpunkTheme.textPrimary)),
                onTap: () => Navigator.pop(context, path),
              );
            },
          ),
        ),
      ),
    );
  }

  Future<void> _moveFile(VaultEntry entry) async {
    final destination = await _selectFolder(title: 'MOVE TO FOLDER');
    if (destination == null) return;
    setState(() => _isVaultOp = true);
    // Freeze timers during move operation (involves vault write)
    widget.stateManager.freezeTimers();
    try {
      await widget.stateManager.moveFileToFolder(entry, destination);
      await widget.stateManager.refreshEntries();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Moved to ${destination.isEmpty ? 'root' : destination}'),
            backgroundColor: CyberpunkTheme.neonGreen.withOpacity(0.9),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Move failed: $e'),
            backgroundColor: CyberpunkTheme.error,
          ),
        );
      }
    } finally {
      widget.stateManager.unfreezeTimers();
      if (mounted) setState(() => _isVaultOp = false);
    }
  }

  Future<void> _copyFile(VaultEntry entry) async {
    SecureLogger.d('VaultHomeScreen', '_copyFile: starting copy of ${entry.name}');
    final destination = await _selectFolder(title: 'COPY TO FOLDER');
    if (destination == null) {
      SecureLogger.d('VaultHomeScreen', '_copyFile: user cancelled folder selection');
      return;
    }
    SecureLogger.d('VaultHomeScreen', '_copyFile: destination=$destination');
    setState(() => _isVaultOp = true);
    // Freeze timers during copy operation (involves vault write)
    widget.stateManager.freezeTimers();
    try {
      SecureLogger.d('VaultHomeScreen', '_copyFile: calling VaultChannel.copyFile');
      final newFileId = await VaultChannel.copyFile(entry.fileId);
      SecureLogger.d('VaultHomeScreen', '_copyFile: newFileId isEmpty=${newFileId.isEmpty}');
      if (newFileId.isNotEmpty) {
        SecureLogger.d('VaultHomeScreen', '_copyFile: calling applyImportedFiles');
        await widget.stateManager.applyImportedFiles({newFileId: destination});
        SecureLogger.d('VaultHomeScreen', '_copyFile: calling refreshEntries');
        await widget.stateManager.refreshEntries();
        SecureLogger.d('VaultHomeScreen', '_copyFile: copy completed successfully');
      }
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Copied to ${destination.isEmpty ? 'root' : destination}'),
            backgroundColor: CyberpunkTheme.neonGreen.withOpacity(0.9),
          ),
        );
      }
    } catch (e) {
      SecureLogger.e('VaultHomeScreen', '_copyFile: error', e);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Copy failed: $e'),
            backgroundColor: CyberpunkTheme.error,
          ),
        );
      }
    } finally {
      widget.stateManager.unfreezeTimers();
      if (mounted) setState(() => _isVaultOp = false);
    }
  }

  Future<void> _showExportDialog() async {
    final passwordController = TextEditingController();
    bool obscure = true;
    
    final confirmed = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) => StatefulBuilder(
        builder: (context, setState) => AlertDialog(
          backgroundColor: CyberpunkTheme.surface,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: BorderSide(color: CyberpunkTheme.neonGreen.withOpacity(0.3)),
          ),
          title: const Text(
            'EXPORT VAULT',
            style: TextStyle(
              color: CyberpunkTheme.neonGreen,
              letterSpacing: 2,
            ),
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Enter your vault password to confirm export:',
                style: TextStyle(color: CyberpunkTheme.textSecondary),
              ),
              const SizedBox(height: 16),
              CyberTextField(
                controller: passwordController,
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
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel', style: TextStyle(color: CyberpunkTheme.textSecondary)),
            ),
            TextButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('EXPORT', style: TextStyle(color: CyberpunkTheme.neonGreen)),
            ),
          ],
        ),
      ),
    );
    
    if (confirmed != true) {
      // CRITICAL: Clear SecureKeyboard target FIRST before disposing
      if (SecureKeyboard.target.value?.controller == passwordController) {
        SecureKeyboard.target.value = null;
        SecureKeyboard.visible.value = false;
        SecureKeyboard.inset.value = 0;
      }
      Future.delayed(const Duration(milliseconds: 800), () {
        SecurePassphrase.disposeController(passwordController);
      });
      return;
    }
    
    final password = passwordController.text;
    // CRITICAL: Clear SecureKeyboard target FIRST before disposing
    if (SecureKeyboard.target.value?.controller == passwordController) {
      SecureKeyboard.target.value = null;
      SecureKeyboard.visible.value = false;
      SecureKeyboard.inset.value = 0;
    }
    Future.delayed(const Duration(milliseconds: 800), () {
      SecurePassphrase.disposeController(passwordController);
    });
    
    if (password.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Password required'), backgroundColor: CyberpunkTheme.error),
        );
      }
      return;
    }
    
    try {
      final verified = await VaultChannel.verifyPassword(password);
      if (!verified) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Incorrect password'), backgroundColor: CyberpunkTheme.error),
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
      SecureLogger.d('VaultHomeScreen', '_showExportDialog: wakelock enabled');
      
      final ok = await widget.stateManager.runWithFrozenTimers(() async {
        return await widget.stateManager.runWithoutAutoLock(() async {
          return await widget.stateManager.exportVault();
        });
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content: Text(ok ? 'Vault exported successfully' : 'Export cancelled'),
          backgroundColor: ok ? CyberpunkTheme.neonGreen.withOpacity(0.9) : CyberpunkTheme.surface,
        ));
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content: Text('Export failed: $e'),
          backgroundColor: CyberpunkTheme.error,
        ));
      }
    } finally {
      // Disable wakelock
      await VaultChannel.disableWakelock();
      SecureLogger.d('VaultHomeScreen', '_showExportDialog: wakelock disabled');
      
      if (mounted) {
        setState(() {
          _isExporting = false;
          _exportProgress = null;
        });
      }
    }
  }

  Future<void> _showChangePasswordDialog() async {
    final result = await showDialog<Map<String, String>>(
      context: context,
      barrierDismissible: false,
      builder: (context) => const _ChangePasswordDialog(),
    );
    
    if (result == null) return;
    
    final currentPassword = result['current'] ?? '';
    final newPassword = result['new'] ?? '';
    final confirmPassword = result['confirm'] ?? '';
    
    if (currentPassword.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Current password required'), backgroundColor: CyberpunkTheme.error),
        );
      }
      return;
    }
    
    if (newPassword.length < 12) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('New password must be at least 12 characters'), backgroundColor: CyberpunkTheme.error),
        );
      }
      return;
    }
    
    if (newPassword != confirmPassword) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('New passwords do not match'), backgroundColor: CyberpunkTheme.error),
        );
      }
      return;
    }
    
    setState(() => _isVaultOp = true);
    try {
      final success = await VaultChannel.changePassword(currentPassword, newPassword);
      
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content: Text(success ? 'Password changed successfully' : 'Incorrect current password'),
          backgroundColor: success ? CyberpunkTheme.neonGreen.withOpacity(0.9) : CyberpunkTheme.error,
        ));
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content: Text('Failed to change password: $e'),
          backgroundColor: CyberpunkTheme.error,
        ));
      }
    } finally {
      if (mounted) setState(() => _isVaultOp = false);
    }
  }

  Future<void> _deleteFile(VaultEntry entry) async {
    SecureLogger.d('VaultHomeScreen', '_deleteFile: starting deletion of ${entry.name}');
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: CyberpunkTheme.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: BorderSide(color: CyberpunkTheme.error.withOpacity(0.3)),
        ),
        title: const Text(
          'DELETE FILE',
          style: TextStyle(color: CyberpunkTheme.error, letterSpacing: 2),
        ),
        content: Text(
          'Are you sure you want to delete "${entry.name}"?\n\nThis action cannot be undone.',
          style: const TextStyle(color: CyberpunkTheme.textSecondary),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel', style: TextStyle(color: CyberpunkTheme.textSecondary)),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            style: TextButton.styleFrom(foregroundColor: CyberpunkTheme.error),
            child: const Text('DELETE'),
          ),
        ],
      ),
    );

    if (confirm == true) {
      SecureLogger.d('VaultHomeScreen', '_deleteFile: user confirmed deletion');
      setState(() => _isVaultOp = true);
      try {
        SecureLogger.d('VaultHomeScreen', '_deleteFile: calling VaultChannel.deleteFile');
        await VaultChannel.deleteFile(entry.fileId);
        SecureLogger.d('VaultHomeScreen', '_deleteFile: calling removeFileFromFolderMap');
        await widget.stateManager.removeFileFromFolderMap(entry.fileId);
        SecureLogger.d('VaultHomeScreen', '_deleteFile: calling refreshEntries');
        await widget.stateManager.refreshEntries();
        SecureLogger.d('VaultHomeScreen', '_deleteFile: deletion completed successfully');
        
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Deleted: ${entry.name}'),
              backgroundColor: CyberpunkTheme.warning,
            ),
          );
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Delete failed: $e'),
              backgroundColor: CyberpunkTheme.error,
            ),
          );
        }
      } finally {
        if (mounted) setState(() => _isVaultOp = false);
      }
    }
  }

  Future<void> _exportFile(VaultEntry entry) async {
    SecureLogger.d('VaultHomeScreen', '_exportFile: starting export of ${entry.name}');
    widget.stateManager.recordActivity();
    
    // Show security warning and confirmation dialog
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: CyberpunkTheme.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: BorderSide(color: CyberpunkTheme.warning.withOpacity(0.3)),
        ),
        title: Row(
          children: [
            Icon(Icons.warning_amber, color: CyberpunkTheme.warning, size: 24),
            const SizedBox(width: 8),
            const Text(
              'EXPORT FILE',
              style: TextStyle(color: CyberpunkTheme.warning, letterSpacing: 2),
            ),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'You are about to export "${entry.name}" outside the vault.',
              style: const TextStyle(color: CyberpunkTheme.textPrimary),
            ),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: CyberpunkTheme.warning.withOpacity(0.1),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: CyberpunkTheme.warning.withOpacity(0.3)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(Icons.shield_outlined, color: CyberpunkTheme.warning, size: 18),
                      const SizedBox(width: 8),
                      const Text(
                        'Security Notice',
                        style: TextStyle(
                          color: CyberpunkTheme.warning,
                          fontWeight: FontWeight.bold,
                          fontSize: 13,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    '• The exported file will be DECRYPTED\n'
                    '• It will be accessible outside the vault\n'
                    '• Other apps may be able to access it\n'
                    '• Consider deleting after use',
                    style: TextStyle(
                      color: CyberpunkTheme.textSecondary,
                      fontSize: 12,
                      height: 1.5,
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
            child: const Text('Cancel', style: TextStyle(color: CyberpunkTheme.textSecondary)),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            style: TextButton.styleFrom(foregroundColor: CyberpunkTheme.warning),
            child: const Text('EXPORT'),
          ),
        ],
      ),
    );

    if (confirm != true) {
      SecureLogger.d('VaultHomeScreen', '_exportFile: user cancelled');
      return;
    }

    SecureLogger.d('VaultHomeScreen', '_exportFile: user confirmed, starting export');
    setState(() => _isVaultOp = true);
    
    // Keep screen awake during export
    await VaultChannel.enableWakelock();
    SecureLogger.d('VaultHomeScreen', '_exportFile: wakelock enabled');
    
    try {
      // SECURITY: Wrap with runWithoutAutoLock to prevent vault from locking
      // during file picker operation (same pattern as vault export)
      final success = await widget.stateManager.runWithFrozenTimers(() async {
        return await widget.stateManager.runWithoutAutoLock(() async {
          return await VaultChannel.exportFile(entry.fileId, entry.name);
        });
      });
      SecureLogger.d('VaultHomeScreen', '_exportFile: export result=$success');
      
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(success ? 'Exported: ${entry.name}' : 'Export cancelled'),
            backgroundColor: success 
                ? CyberpunkTheme.neonGreen.withOpacity(0.9) 
                : CyberpunkTheme.surface,
          ),
        );
      }
    } catch (e) {
      SecureLogger.e('VaultHomeScreen', '_exportFile: error', e);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Export failed: $e'),
            backgroundColor: CyberpunkTheme.error,
          ),
        );
      }
    } finally {
      // Disable wakelock
      await VaultChannel.disableWakelock();
      SecureLogger.d('VaultHomeScreen', '_exportFile: wakelock disabled');
      
      if (mounted) setState(() => _isVaultOp = false);
    }
  }

  Future<void> _deleteFolder(String folderPath) async {
    SecureLogger.d('VaultHomeScreen', '_deleteFolder: starting deletion of $folderPath');
    widget.stateManager.recordActivity();
    
    // Get file count for confirmation message
    final fileCount = widget.stateManager.getFileCountInFolderRecursive(folderPath);
    final folderName = folderPath.split('/').last;
    SecureLogger.d('VaultHomeScreen', '_deleteFolder: folderName=$folderName, fileCount=$fileCount');
    
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: CyberpunkTheme.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: BorderSide(color: CyberpunkTheme.error.withOpacity(0.3)),
        ),
        title: const Text(
          'DELETE FOLDER',
          style: TextStyle(color: CyberpunkTheme.error, letterSpacing: 2),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Are you sure you want to delete "$folderName"?',
              style: const TextStyle(color: CyberpunkTheme.textSecondary),
            ),
            const SizedBox(height: 12),
            if (fileCount > 0)
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: CyberpunkTheme.error.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: CyberpunkTheme.error.withOpacity(0.3)),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.warning_amber, color: CyberpunkTheme.error, size: 20),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'This will permanently delete $fileCount file(s) and all subfolders.',
                        style: TextStyle(
                          color: CyberpunkTheme.error.withOpacity(0.9),
                          fontSize: 13,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            const SizedBox(height: 8),
            const Text(
              'This action cannot be undone.',
              style: TextStyle(color: CyberpunkTheme.textHint, fontSize: 12),
            ),
          ],
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

    if (confirm == true) {
      SecureLogger.d('VaultHomeScreen', '_deleteFolder: user confirmed deletion');
      // Freeze timers during folder deletion (involves vault write operations)
      widget.stateManager.freezeTimers();
      setState(() => _isVaultOp = true);
      try {
        SecureLogger.d('VaultHomeScreen', '_deleteFolder: calling stateManager.deleteFolder');
        final deletedCount = await widget.stateManager.deleteFolder(folderPath);
        SecureLogger.d('VaultHomeScreen', '_deleteFolder: deletedCount=$deletedCount');
        
        // Refresh entries to update UI
        SecureLogger.d('VaultHomeScreen', '_deleteFolder: calling refreshEntries');
        await widget.stateManager.refreshEntries();
        SecureLogger.d('VaultHomeScreen', '_deleteFolder: deletion completed successfully');
        
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Deleted folder "$folderName" ($deletedCount files)'),
              backgroundColor: CyberpunkTheme.warning,
            ),
          );
        }
      } catch (e) {
        SecureLogger.e('VaultHomeScreen', '_deleteFolder: error', e);
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Delete folder failed: $e'),
              backgroundColor: CyberpunkTheme.error,
            ),
          );
        }
      } finally {
        widget.stateManager.unfreezeTimers();
        if (mounted) setState(() => _isVaultOp = false);
      }
    }
  }

  Future<void> _renameFolder(String folderPath) async {
    widget.stateManager.recordActivity();
    
    final folderName = folderPath.split('/').last;
    
    final newName = await showDialog<String>(
      context: context,
      builder: (context) {
        final controller = TextEditingController(text: folderName);
        return AlertDialog(
          backgroundColor: CyberpunkTheme.surface,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: BorderSide(color: CyberpunkTheme.cyan.withOpacity(0.3)),
          ),
          title: const Text(
            'RENAME FOLDER',
            style: TextStyle(color: CyberpunkTheme.cyan, letterSpacing: 2),
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              CyberTextField(
                controller: controller,
                labelText: 'Folder name',
                hintText: 'Enter a new name',
                autofocus: true,
                onSubmitted: (_) => Navigator.pop(context, controller.text),
              ),
              const SizedBox(height: 8),
              const Text(
                'All files in this folder will be updated.',
                style: TextStyle(color: CyberpunkTheme.textHint, fontSize: 12),
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
              style: TextButton.styleFrom(foregroundColor: CyberpunkTheme.cyan),
              child: const Text('RENAME'),
            ),
          ],
        );
      },
    );

    if (newName != null && newName.isNotEmpty && newName != folderName) {
      // Validate folder name - security check
      if (newName.startsWith('__')) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Folder name cannot start with "__"'),
              backgroundColor: CyberpunkTheme.error,
            ),
          );
        }
        return;
      }
      
      // Check for invalid characters
      if (newName.contains('/') || newName.contains('\\')) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Folder name cannot contain "/" or "\\"'),
              backgroundColor: CyberpunkTheme.error,
            ),
          );
        }
        return;
      }
      
      // Freeze timers during folder rename (involves vault write operations)
      widget.stateManager.freezeTimers();
      setState(() => _isVaultOp = true);
      try {
        // Calculate new path for updating current folder if needed
        final lastSlash = folderPath.lastIndexOf('/');
        final parentPath = lastSlash > 0 ? folderPath.substring(0, lastSlash) : '';
        final newFolderPath = parentPath.isEmpty ? newName : '$parentPath/$newName';
        
        await widget.stateManager.renameFolder(folderPath, newName);
        
        // Refresh entries to update UI
        await widget.stateManager.refreshEntries();
        
        // Update current folder path if we're inside the renamed folder
        if (_currentFolderPath == folderPath) {
          setState(() {
            _currentFolderPath = newFolderPath;
          });
        } else if (_currentFolderPath.startsWith('$folderPath/')) {
          setState(() {
            _currentFolderPath = newFolderPath + _currentFolderPath.substring(folderPath.length);
          });
        }
        
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Folder renamed to "$newName"'),
              backgroundColor: CyberpunkTheme.neonGreen,
            ),
          );
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Rename folder failed: $e'),
              backgroundColor: CyberpunkTheme.error,
            ),
          );
        }
      } finally {
        widget.stateManager.unfreezeTimers();
        if (mounted) setState(() => _isVaultOp = false);
      }
    }
  }

  Future<void> _renameFile(VaultEntry entry) async {
    final newName = await showDialog<String>(
      context: context,
      builder: (context) {
        final controller = TextEditingController(text: entry.name);
        return AlertDialog(
          backgroundColor: CyberpunkTheme.surface,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: BorderSide(color: CyberpunkTheme.neonGreen.withOpacity(0.3)),
          ),
          title: const Text(
            'RENAME FILE',
            style: TextStyle(color: CyberpunkTheme.neonGreen, letterSpacing: 2),
          ),
          content: CyberTextField(
            controller: controller,
            labelText: 'File name',
            hintText: 'Enter a new name',
            onSubmitted: (_) => Navigator.pop(context, controller.text),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel', style: TextStyle(color: CyberpunkTheme.textSecondary)),
            ),
            TextButton(
              onPressed: () => Navigator.pop(context, controller.text),
              child: const Text('SAVE', style: TextStyle(color: CyberpunkTheme.neonGreen)),
            ),
          ],
        );
      },
    );

    if (newName == null) return;
    final trimmed = newName.trim();
    if (trimmed.isEmpty || trimmed == entry.name) return;
    if (trimmed.length > 4096 || trimmed.startsWith('__')) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Invalid file name'),
            backgroundColor: CyberpunkTheme.error,
          ),
        );
      }
      return;
    }

    setState(() => _isVaultOp = true);
    try {
      await VaultChannel.renameFile(entry.fileId, trimmed);
      await widget.stateManager.refreshEntries();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Renamed to: $trimmed'),
            backgroundColor: CyberpunkTheme.neonGreen.withOpacity(0.9),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Rename failed: $e'),
            backgroundColor: CyberpunkTheme.error,
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _isVaultOp = false);
    }
  }

  void _openFile(VaultEntry entry) {
    widget.stateManager.recordActivity();
    
    if (entry.isAudio) {
      Navigator.pushNamed(context, '/audio-player', arguments: entry);
    } else if (entry.isVideo) {
      Navigator.pushNamed(context, '/video-player', arguments: entry);
    } else if (entry.isImage) {
      Navigator.pushNamed(context, '/image-viewer', arguments: entry);
    } else if (entry.isPdf || entry.isDocx || entry.isPptx || entry.isXlsx) {
      Navigator.pushNamed(context, '/document-viewer', arguments: entry);
    } else if (entry.isCsv || entry.isTextLike) {
      Navigator.pushNamed(context, '/text-viewer', arguments: entry);
    } else {
      Navigator.pushNamed(context, '/text-viewer', arguments: entry);
    }
  }


  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, _) {
        if (didPop) return;
        if (_currentFolderPath.isNotEmpty) {
          _goUpFolder();
        } else {
          _lockAndLogout();
        }
      },
      child: LoadingOverlay(
        isLoading: _isImporting || _isExporting || _isVaultOp,
        message: _isImporting
            ? (_isImportFinalizing ? 'Finalizing import...' : 'Importing...')
            : _isExporting
                ? 'Exporting vault...'
                : 'Processing...',
        progress: _isImporting
            ? _importProgress
            : _isExporting
                ? _exportProgress
                : null,
        child: GestureDetector(
          onTap: () => widget.stateManager.recordActivity(),
          child: Scaffold(
          backgroundColor: CyberpunkTheme.background,
          appBar: AppBar(
            leading: _currentFolderPath.isEmpty
                ? null
                : IconButton(
                    icon: const Icon(Icons.arrow_back, color: CyberpunkTheme.neonGreen),
                    tooltip: 'Back',
                    onPressed: _goUpFolder,
                  ),
            title: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  (widget.stateManager.currentVaultTitle ?? 'VAULT').toUpperCase(),
                  style: const TextStyle(
                    letterSpacing: 2,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                if (_currentFolderPath.isNotEmpty)
                  Text(
                    _currentPathLabel,
                    style: const TextStyle(
                      color: CyberpunkTheme.textHint,
                      fontSize: 12,
                    ),
                  ),
              ],
            ),
            backgroundColor: Colors.transparent,
            elevation: 0,
            actions: [
              // Lock button with glow
              Container(
                margin: const EdgeInsets.only(right: 8),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(8),
                  boxShadow: [
                    BoxShadow(
                      color: CyberpunkTheme.neonGreen.withOpacity(0.2),
                      blurRadius: 8,
                    ),
                  ],
                ),
                child: IconButton(
                  icon: const Icon(Icons.lock, color: CyberpunkTheme.neonGreen),
                  tooltip: 'Lock Now',
                  onPressed: _lockAndLogout,
                ),
              ),
              PopupMenuButton<String>(
                icon: const Icon(Icons.more_vert, color: CyberpunkTheme.textSecondary),
                color: CyberpunkTheme.surface,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                  side: BorderSide(color: CyberpunkTheme.surfaceBorder),
                ),
                onSelected: (value) {
                  if (value == 'lock') {
                    _lockAndLogout();
                  } else if (value == 'change_password') {
                    _showChangePasswordDialog();
                  } else if (value == 'export') {
                    _showExportDialog();
                  }
                },
                itemBuilder: (context) => [
                  PopupMenuItem(
                    value: 'change_password',
                    child: Row(
                      children: [
                        const Icon(Icons.key, size: 20, color: CyberpunkTheme.neonGreen),
                        const SizedBox(width: 12),
                        const Text('Change Password', style: TextStyle(color: CyberpunkTheme.textPrimary)),
                      ],
                    ),
                  ),
                  PopupMenuItem(
                    value: 'export',
                    child: Row(
                      children: [
                        const Icon(Icons.file_upload, size: 20, color: CyberpunkTheme.neonGreen),
                        const SizedBox(width: 12),
                        const Text('Export Vault', style: TextStyle(color: CyberpunkTheme.textPrimary)),
                      ],
                    ),
                  ),
                  PopupMenuItem(
                    value: 'lock',
                    child: Row(
                      children: [
                        const Icon(Icons.lock, size: 20, color: CyberpunkTheme.neonGreen),
                        const SizedBox(width: 12),
                        const Text('Lock Now', style: TextStyle(color: CyberpunkTheme.textPrimary)),
                      ],
                    ),
                  ),
                ],
              ),
            ],
          ),
          body: Column(
            children: [
              // Search bar with cyberpunk style
              Padding(
                padding: const EdgeInsets.all(16),
                child: Container(
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(12),
                    boxShadow: _searchQuery.isNotEmpty
                        ? [
                            BoxShadow(
                              color: CyberpunkTheme.neonGreen.withOpacity(0.2),
                              blurRadius: 12,
                            ),
                          ]
                        : null,
                  ),
                  child: TextField(
                    controller: _searchController,
                    readOnly: AppSettings.instance.secureKeyboardEnabled,
                    showCursor: true,
                    enableInteractiveSelection: !AppSettings.instance.secureKeyboardEnabled,
                    autocorrect: false,
                    enableSuggestions: false,
                    onTap: () {
                      if (AppSettings.instance.secureKeyboardEnabled) {
                        SecureKeyboard.show(
                          context,
                          controller: _searchController,
                          onChanged: (value) {
                            setState(() => _searchQuery = value);
                            widget.stateManager.recordActivity();
                          },
                        );
                      }
                    },
                    onChanged: (value) {
                      setState(() => _searchQuery = value);
                      widget.stateManager.recordActivity();
                    },
                    style: const TextStyle(color: CyberpunkTheme.textPrimary),
                    cursorColor: CyberpunkTheme.neonGreen,
                    decoration: InputDecoration(
                      hintText: 'Search files...',
                      hintStyle: const TextStyle(color: CyberpunkTheme.textHint),
                      prefixIcon: Icon(
                        Icons.search,
                        color: _searchQuery.isNotEmpty
                            ? CyberpunkTheme.neonGreen
                            : CyberpunkTheme.textHint,
                      ),
                      filled: true,
                      fillColor: CyberpunkTheme.surfaceLight,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(12),
                        borderSide: BorderSide(color: CyberpunkTheme.surfaceBorder),
                      ),
                      enabledBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(12),
                        borderSide: BorderSide(color: CyberpunkTheme.surfaceBorder),
                      ),
                      focusedBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(12),
                        borderSide: const BorderSide(color: CyberpunkTheme.neonGreen, width: 2),
                      ),
                      suffixIcon: _searchQuery.isNotEmpty
                          ? IconButton(
                              icon: const Icon(Icons.clear, color: CyberpunkTheme.textSecondary),
                              onPressed: () {
                                _searchController.clear();
                                setState(() => _searchQuery = '');
                              },
                            )
                          : null,
                    ),
                  ),
                ),
              ),

              // File list
              Expanded(
                child: Builder(
                  builder: (context) {
                    final folders = _visibleFolders;
                    final entries = _filteredEntries;
                    if (folders.isEmpty && entries.isEmpty) {
                      return _buildEmptyState();
                    }
                    return ListView.builder(
                      itemCount: folders.length + entries.length,
                      padding: const EdgeInsets.only(left: 16, right: 16, bottom: 80),
                      itemBuilder: (context, index) {
                        if (index < folders.length) {
                          final name = folders[index];
                          final fullPath = _currentFolderPath.isEmpty 
                              ? name 
                              : '$_currentFolderPath/$name';
                          return _FolderListItem(
                            name: name,
                            onTap: () => _enterFolder(name),
                            onRename: () => _renameFolder(fullPath),
                            onDelete: () => _deleteFolder(fullPath),
                          );
                        }
                        final entry = entries[index - folders.length];
                        return _FileListItem(
                          entry: entry,
                          onTap: () => _openFile(entry),
                          onRename: () => _renameFile(entry),
                          onDelete: () => _deleteFile(entry),
                          onMove: () => _moveFile(entry),
                          onCopy: () => _copyFile(entry),
                          onExport: () => _exportFile(entry),
                        );
                      },
                    );
                  },
                ),
              ),
            ],
          ),
          floatingActionButton: Container(
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
            child: FloatingActionButton(
              onPressed: (_isImporting || _isExporting || _isVaultOp) ? null : _showImportOptions,
              backgroundColor: CyberpunkTheme.neonGreen,
              foregroundColor: CyberpunkTheme.background,
              child: const Icon(Icons.add),
            ),
          ),
        ),
      ),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            padding: const EdgeInsets.all(24),
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              boxShadow: [
                BoxShadow(
                  color: CyberpunkTheme.neonGreen.withOpacity(0.1),
                  blurRadius: 30,
                  spreadRadius: 5,
                ),
              ],
            ),
            child: Icon(
              _searchQuery.isEmpty ? Icons.folder_open : Icons.search_off,
              size: 64,
              color: CyberpunkTheme.neonGreen.withOpacity(0.5),
            ),
          ),
          const SizedBox(height: 24),
          Text(
            _searchQuery.isEmpty ? 'NO FILES YET' : 'NO FILES FOUND',
            style: const TextStyle(
              color: CyberpunkTheme.textSecondary,
              fontSize: 16,
              letterSpacing: 2,
            ),
          ),
          if (_searchQuery.isEmpty) ...[
            const SizedBox(height: 8),
            const Text(
              'Tap + to import files or folders',
              style: TextStyle(
                color: CyberpunkTheme.textHint,
                fontSize: 14,
              ),
            ),
          ],
        ],
      ),
    );
  }
}


class _FileListItem extends StatelessWidget {
  final VaultEntry entry;
  final VoidCallback onTap;
  final VoidCallback onRename;
  final VoidCallback onDelete;
  final VoidCallback onMove;
  final VoidCallback onCopy;
  final VoidCallback onExport;

  const _FileListItem({
    required this.entry,
    required this.onTap,
    required this.onRename,
    required this.onDelete,
    required this.onMove,
    required this.onCopy,
    required this.onExport,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      decoration: BoxDecoration(
        color: CyberpunkTheme.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: CyberpunkTheme.surfaceBorder),
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(12),
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Row(
              children: [
                // File type icon
                Container(
                  width: 48,
                  height: 48,
                  decoration: BoxDecoration(
                    color: CyberpunkTheme.surfaceLight,
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: CyberpunkTheme.surfaceBorder),
                  ),
                  child: Center(
                    child: Text(
                      entry.typeIcon,
                      style: const TextStyle(fontSize: 24),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                // File info
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        entry.name,
                        style: const TextStyle(
                          color: CyberpunkTheme.textPrimary,
                          fontWeight: FontWeight.w500,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 4),
                      Text(
                        '${entry.sizeFormatted} • ${_formatDate(entry.createdAt)}',
                        style: const TextStyle(
                          color: CyberpunkTheme.textHint,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                ),
                PopupMenuButton<String>(
                  icon: const Icon(Icons.more_vert, color: CyberpunkTheme.textSecondary),
                  color: CyberpunkTheme.surface,
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                    side: BorderSide(color: CyberpunkTheme.surfaceBorder),
                  ),
                  onSelected: (value) {
                    if (value == 'rename') {
                      onRename();
                    } else if (value == 'move') {
                      onMove();
                    } else if (value == 'copy') {
                      onCopy();
                    } else if (value == 'export') {
                      onExport();
                    } else if (value == 'delete') {
                      onDelete();
                    }
                  },
                  itemBuilder: (context) => [
                    PopupMenuItem(
                      value: 'rename',
                      child: Row(
                        children: [
                          const Icon(Icons.edit, size: 20, color: CyberpunkTheme.neonGreen),
                          const SizedBox(width: 12),
                          const Text('Rename', style: TextStyle(color: CyberpunkTheme.textPrimary)),
                        ],
                      ),
                    ),
                    PopupMenuItem(
                      value: 'move',
                      child: Row(
                        children: [
                          const Icon(Icons.drive_file_move, size: 20, color: CyberpunkTheme.neonGreen),
                          const SizedBox(width: 12),
                          const Text('Move', style: TextStyle(color: CyberpunkTheme.textPrimary)),
                        ],
                      ),
                    ),
                    PopupMenuItem(
                      value: 'copy',
                      child: Row(
                        children: [
                          const Icon(Icons.copy, size: 20, color: CyberpunkTheme.neonGreen),
                          const SizedBox(width: 12),
                          const Text('Copy', style: TextStyle(color: CyberpunkTheme.textPrimary)),
                        ],
                      ),
                    ),
                    PopupMenuItem(
                      value: 'export',
                      child: Row(
                        children: [
                          const Icon(Icons.file_download_outlined, size: 20, color: CyberpunkTheme.warning),
                          const SizedBox(width: 12),
                          const Text('Export', style: TextStyle(color: CyberpunkTheme.warning)),
                        ],
                      ),
                    ),
                    PopupMenuItem(
                      value: 'delete',
                      child: Row(
                        children: [
                          const Icon(Icons.delete_outline, size: 20, color: CyberpunkTheme.error),
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

  String _formatDate(DateTime date) {
    return '${date.day}/${date.month}/${date.year}';
  }
}

class _FolderListItem extends StatelessWidget {
  final String name;
  final VoidCallback onTap;
  final VoidCallback? onDelete;
  final VoidCallback? onRename;

  const _FolderListItem({
    required this.name,
    required this.onTap,
    this.onDelete,
    this.onRename,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      decoration: BoxDecoration(
        color: CyberpunkTheme.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: CyberpunkTheme.surfaceBorder),
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: onTap,
          onLongPress: (onDelete != null || onRename != null) ? () => _showFolderOptions(context) : null,
          borderRadius: BorderRadius.circular(12),
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Row(
              children: [
                Container(
                  width: 48,
                  height: 48,
                  decoration: BoxDecoration(
                    color: CyberpunkTheme.surfaceLight,
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: CyberpunkTheme.surfaceBorder),
                  ),
                  child: const Center(
                    child: Icon(Icons.folder, color: CyberpunkTheme.neonGreen),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    name,
                    style: const TextStyle(
                      color: CyberpunkTheme.textPrimary,
                      fontWeight: FontWeight.w500,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                const Icon(Icons.chevron_right, color: CyberpunkTheme.textSecondary),
              ],
            ),
          ),
        ),
      ),
    );
  }

  void _showFolderOptions(BuildContext context) {
    showModalBottomSheet(
      context: context,
      backgroundColor: CyberpunkTheme.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (context) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 16),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: CyberpunkTheme.surfaceBorder,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              const SizedBox(height: 16),
              Text(
                name,
                style: const TextStyle(
                  color: CyberpunkTheme.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 16),
              if (onRename != null)
                ListTile(
                  leading: const Icon(Icons.edit, color: CyberpunkTheme.cyan),
                  title: const Text('Rename Folder', style: TextStyle(color: CyberpunkTheme.textPrimary)),
                  subtitle: const Text(
                    'Change folder name',
                    style: TextStyle(color: CyberpunkTheme.textHint, fontSize: 12),
                  ),
                  onTap: () {
                    Navigator.pop(context);
                    onRename?.call();
                  },
                ),
              if (onDelete != null)
                ListTile(
                  leading: const Icon(Icons.delete_forever, color: CyberpunkTheme.error),
                  title: const Text('Delete Folder', style: TextStyle(color: CyberpunkTheme.error)),
                  subtitle: const Text(
                    'Delete folder and all contents',
                    style: TextStyle(color: CyberpunkTheme.textHint, fontSize: 12),
                  ),
                  onTap: () {
                    Navigator.pop(context);
                    onDelete?.call();
                  },
                ),
            ],
          ),
        ),
      ),
    );
  }
}

class _ChangePasswordDialog extends StatefulWidget {
  const _ChangePasswordDialog();

  @override
  State<_ChangePasswordDialog> createState() => _ChangePasswordDialogState();
}

class _ChangePasswordDialogState extends State<_ChangePasswordDialog> {
  late final TextEditingController _currentPasswordController;
  late final TextEditingController _newPasswordController;
  late final TextEditingController _confirmPasswordController;
  bool _obscureCurrent = true;
  bool _obscureNew = true;
  bool _obscureConfirm = true;

  @override
  void initState() {
    super.initState();
    _currentPasswordController = TextEditingController();
    _newPasswordController = TextEditingController();
    _confirmPasswordController = TextEditingController();
  }

  @override
  void dispose() {
    SecurePassphrase.disposeController(_currentPasswordController);
    SecurePassphrase.disposeController(_newPasswordController);
    SecurePassphrase.disposeController(_confirmPasswordController);
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
                      Icons.key,
                      color: CyberpunkTheme.neonGreen,
                      size: 24,
                    ),
                  ),
                  const SizedBox(width: 16),
                  const Expanded(
                    child: Text(
                      'CHANGE PASSWORD',
                      style: TextStyle(
                        color: CyberpunkTheme.textPrimary,
                        fontSize: 18,
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

              // Current password
              CyberTextField(
                controller: _currentPasswordController,
                labelText: 'Current Password',
                obscureText: _obscureCurrent,
                suffixIcon: IconButton(
                  icon: Icon(
                    _obscureCurrent ? Icons.visibility : Icons.visibility_off,
                    color: CyberpunkTheme.textSecondary,
                  ),
                  onPressed: () => setState(() => _obscureCurrent = !_obscureCurrent),
                ),
              ),
              const SizedBox(height: 16),

              // New password
              CyberTextField(
                controller: _newPasswordController,
                labelText: 'New Password (min 12 chars)',
                obscureText: _obscureNew,
                onChanged: (_) => setState(() {}),
                suffixIcon: IconButton(
                  icon: Icon(
                    _obscureNew ? Icons.visibility : Icons.visibility_off,
                    color: CyberpunkTheme.textSecondary,
                  ),
                  onPressed: () => setState(() => _obscureNew = !_obscureNew),
                ),
              ),

              // Password strength meter
              PasswordStrengthMeter(
                password: _newPasswordController.text,
                minLength: 12,
              ),
              const SizedBox(height: 16),

              // Confirm password
              CyberTextField(
                controller: _confirmPasswordController,
                labelText: 'Confirm New Password',
                obscureText: _obscureConfirm,
                suffixIcon: IconButton(
                  icon: Icon(
                    _obscureConfirm ? Icons.visibility : Icons.visibility_off,
                    color: CyberpunkTheme.textSecondary,
                  ),
                  onPressed: () => setState(() => _obscureConfirm = !_obscureConfirm),
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
                      text: 'CHANGE',
                      icon: Icons.key,
                      onPressed: () {
                        Navigator.pop(context, {
                          'current': _currentPasswordController.text,
                          'new': _newPasswordController.text,
                          'confirm': _confirmPasswordController.text,
                        });
                      },
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
