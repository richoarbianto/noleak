import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/foundation.dart';
import 'package:flutter/scheduler.dart';
import 'package:flutter/services.dart';
import '../models/vault_state.dart';
import '../utils/secure_logger.dart';
import '../utils/secure_passphrase.dart';
import 'vault_channel.dart';
import 'app_settings.dart';

/// VaultStateManager - Vault State and Session Management
/// 
/// Central state manager for vault operations, handling:
/// - Vault state transitions (locked/unlocked/blocked)
/// - Session timeout management (idle + absolute limits)
/// - File entry management and folder organization
/// - Brute-force protection with progressive lockout
/// 
/// SECURITY FEATURES:
/// - Auto-lock on idle timeout (configurable 10-30 seconds)
/// - Session limit requiring re-authentication (3-10 minutes)
/// - Timer freezing during file operations to prevent data loss
/// - Secure folder map persistence with atomic writes
/// 
/// The manager implements [ChangeNotifier] to allow UI components
/// to react to state changes.
class VaultStateManager extends ChangeNotifier {
  VaultState _state = VaultState.uninitialized;
  List<VaultEntry> _entries = [];
  DateTime? _lastActivity;
  int _failedAttempts = 0;
  DateTime? _lockoutUntil;
  Timer? _idleTimer;
  Timer? _sessionTimer;
  bool _reauthInProgress = false;
  bool _suppressAutoLock = false;
  bool _timersFrozen = false;  // For freezing timers during import
  DateTime? _frozenIdleRemaining;
  DateTime? _frozenSessionRemaining;
  String? _currentVaultId;
  String? _currentVaultTitle;
  final Map<String, String> _fileFolders = {};
  final Set<String> _folders = {};
  
  // Constants
  static const int maxFailedAttempts = 5;
  static const int baseLockoutSeconds = 60;
  static const int maxLockoutSeconds = 30 * 60; // 30 minutes
  static const String _folderMapName = '__folder_map__';
  static const String _folderMapTempName = '__folder_map__.tmp';
  static const int _folderMapVersion = 1;
  VaultState get state => _state;
  List<VaultEntry> get entries => _entries;
  DateTime? get lastActivity => _lastActivity;
  bool get isLocked => _state != VaultState.unlocked;
  bool get isBlocked => _state == VaultState.blocked;
  String? get currentVaultId => _currentVaultId;
  String? get currentVaultTitle => _currentVaultTitle;
  int get failedAttempts => _failedAttempts;
  List<String> get folders => _folders.toList()..sort();

  VaultStateManager() {
    AppSettings.instance.addListener(_handleSettingsChange);
  }

  /// Safe notifyListeners that defers to next frame to avoid build conflicts
  void _safeNotify() {
    SchedulerBinding.instance.addPostFrameCallback((_) {
      notifyListeners();
    });
  }
  
  /// Get remaining lockout time in seconds
  int get lockoutRemainingSeconds {
    if (_lockoutUntil == null) return 0;
    final remaining = _lockoutUntil!.difference(DateTime.now()).inSeconds;
    return remaining > 0 ? remaining : 0;
  }
  
  bool get isLockedOut => lockoutRemainingSeconds > 0;

  /// Initialize state manager
  Future<void> initialize() async {
    // Check environment first
    final isSecure = await VaultChannel.checkEnvironment();
    if (!isSecure) {
      _state = VaultState.blocked;
      notifyListeners();
      return;
    }

    // Check if vault exists
    final exists = await VaultChannel.vaultExists();
    if (!exists) {
      _state = VaultState.uninitialized;
    } else {
      final isOpen = await VaultChannel.isVaultOpen();
      _state = isOpen ? VaultState.unlocked : VaultState.locked;
    }
    
    notifyListeners();
  }

  /// Check if environment is secure before sensitive operations
  Future<void> _checkSecurity() async {
    final isSecure = await VaultChannel.checkEnvironment();
    if (!isSecure) {
      _state = VaultState.blocked;
      notifyListeners();
      throw Exception('Environment not supported');
    }
  }

  /// Create a new vault
  Future<void> createVault(String passphrase) async {
    // Security check before vault creation (PRD Req 2.3)
    await _checkSecurity();
    
    await VaultChannel.createVault(passphrase);
    _state = VaultState.locked;
    notifyListeners();
  }

  /// Unlock vault with passphrase
  Future<bool> unlockVault(String passphrase) async {
    // Security check before unlock (PRD Req 2.4)
    await _checkSecurity();
    
    if (isLockedOut) {
      throw Exception('Too many failed attempts. Try again in $lockoutRemainingSeconds seconds.');
    }

    try {
      await VaultChannel.openVault(passphrase);
      
      // Require biometric after passphrase
      final biometricSuccess = await VaultChannel.authenticateBiometric();
      if (!biometricSuccess) {
        await VaultChannel.closeVault();
        throw Exception('Biometric authentication required');
      }
      
      // Load entries
      await _loadEntries();
      
      _state = VaultState.unlocked;
      _failedAttempts = 0;
      _lockoutUntil = null;
      _updateActivity();
      _startIdleTimer();
      _startSessionTimer();
      notifyListeners();
      return true;
    } on PlatformException catch (e) {
      if (e.code == 'RATE_LIMITED') {
        _applyRateLimit(e);
      } else {
        _handleFailedAttempt();
      }
      rethrow;
    } catch (e) {
      _handleFailedAttempt();
      rethrow;
    }
  }

  /// Unlock a specific vault by ID (multi-vault mode)
  /// Called after VaultChannel.openVaultById has already succeeded
  Future<void> unlockVaultById(String vaultId, {String? password}) async {
    SecureLogger.d('VaultStateManager', 'unlockVaultById called for: $vaultId');
    _currentVaultId = vaultId;
    
    // Load entries (including system entries like __vault_title__)
    SecureLogger.d('VaultStateManager', 'Loading entries...');
    await _loadEntriesWithSystemFiles();
    SecureLogger.d('VaultStateManager', 'Loaded ${_entries.length} entries');
    
    // Try to load vault title from entries
    _currentVaultTitle = null;
    final titleEntry = _entries.where((e) => e.name == '__vault_title__').firstOrNull;
    SecureLogger.d('VaultStateManager', 'Title entry found: ${titleEntry != null}');
    if (titleEntry != null) {
      try {
        final titleData = await VaultChannel.readFile(titleEntry.fileId);
        _currentVaultTitle = String.fromCharCodes(titleData);
        SecureLogger.d('VaultStateManager', 'Title loaded: $_currentVaultTitle');
      } catch (e) {
        SecureLogger.e('VaultStateManager', 'Title read failed', e);
      }
    }
    
    // Filter out system entries from visible list
    _entries = _entries.where((e) => !e.name.startsWith('__')).toList();
    SecureLogger.d('VaultStateManager', 'Filtered entries: ${_entries.length}');
    
    _state = VaultState.unlocked;
    _failedAttempts = 0;
    _lockoutUntil = null;
    _updateActivity();
    _startIdleTimer();
    _startSessionTimer();
    SecureLogger.d('VaultStateManager', 'State set to UNLOCKED, calling notifyListeners');
    notifyListeners();
  }
  
  /// Load entries including system files (for title extraction)
  Future<void> _loadEntriesWithSystemFiles() async {
    try {
      final entriesData = await VaultChannel.listFiles();
      final entries = entriesData.map((e) => VaultEntry(
        fileId: List<int>.from(e['fileId'] as List),
        name: e['name'] as String,
        type: e['type'] as int,
        size: e['size'] as int,
        createdAt: DateTime.fromMillisecondsSinceEpoch(e['createdAt'] as int),
        mimeType: e['mimeType'] as String?,
        chunkCount: (e['chunkCount'] as int?) ?? 0,
      )).toList();
      await _loadFolderMap(entries);
      _entries = entries;
    } catch (e) {
      _entries = [];
    }
  }

  /// Temporarily suppress auto-lock (e.g., during external pickers)
  Future<T> runWithoutAutoLock<T>(Future<T> Function() action) async {
    _suppressAutoLock = true;
    try {
      return await action();
    } finally {
      _suppressAutoLock = false;
    }
  }

  /// Freeze session and idle timers (e.g., during file/folder import)
  /// SECURITY: Timers are paused but will resume after import completes
  void freezeTimers() {
    if (_timersFrozen || _state != VaultState.unlocked) return;
    _timersFrozen = true;
    SecureLogger.d('VaultStateManager', 'Freezing timers for import operation');
    
    // Store remaining time before stopping
    _frozenIdleRemaining = _lastActivity;
    _frozenSessionRemaining = DateTime.now();
    
    _stopIdleTimer();
    _stopSessionTimer();
  }

  /// Unfreeze and restart timers after import completes
  void unfreezeTimers() {
    if (!_timersFrozen) return;
    _timersFrozen = false;
    SecureLogger.d('VaultStateManager', 'Unfreezing timers after import operation');
    
    // Reset activity and restart timers
    _updateActivity();
    _startIdleTimer();
    _startSessionTimer();
    
    _frozenIdleRemaining = null;
    _frozenSessionRemaining = null;
  }

  /// Run an action with timers frozen (for import operations)
  Future<T> runWithFrozenTimers<T>(Future<T> Function() action) async {
    freezeTimers();
    try {
      return await action();
    } finally {
      unfreezeTimers();
    }
  }

  /// Export encrypted vault container
  Future<bool> exportVault() async {
    await _checkSecurity();
    return await VaultChannel.exportVault();
  }

  /// Import encrypted vault container (replaces existing, locks state)
  Future<bool> importVault() async {
    await _checkSecurity();
    final ok = await VaultChannel.importVault();
    if (ok) {
      _state = VaultState.locked;
      _entries = [];
      notifyListeners();
    }
    return ok;
  }

  /// Lock the vault
  Future<void> lockVault() async {
    _stopIdleTimer();
    _stopSessionTimer();
    await VaultChannel.closeVault();
    _state = VaultState.locked;
    _entries = [];
    _currentVaultId = null;
    _currentVaultTitle = null;  // SECURITY: Wipe title from memory
    notifyListeners();
  }

  /// Handle failed unlock attempt
  void _handleFailedAttempt() {
    _failedAttempts++;
    
    if (_failedAttempts >= maxFailedAttempts) {
      // Calculate lockout duration with exponential backoff
      final lockoutMultiplier = _failedAttempts - maxFailedAttempts + 1;
      var lockoutSeconds = baseLockoutSeconds * (1 << (lockoutMultiplier - 1));
      lockoutSeconds = lockoutSeconds.clamp(baseLockoutSeconds, maxLockoutSeconds);
      
      _lockoutUntil = DateTime.now().add(Duration(seconds: lockoutSeconds));
    }
    
    notifyListeners();
  }

  void _applyRateLimit(PlatformException e) {
    final details = e.details;
    int? remainingSeconds;
    if (details is Map && details['remainingSeconds'] is int) {
      remainingSeconds = details['remainingSeconds'] as int;
    }
    if (remainingSeconds != null && remainingSeconds > 0) {
      _lockoutUntil = DateTime.now().add(Duration(seconds: remainingSeconds));
    } else {
      _lockoutUntil = DateTime.now().add(const Duration(seconds: baseLockoutSeconds));
    }
    _failedAttempts = maxFailedAttempts;
    notifyListeners();
  }

  /// Update last activity timestamp
  void _updateActivity() {
    _lastActivity = DateTime.now();
  }

  /// Record user activity (call this on user interaction)
  void recordActivity() {
    if (_state == VaultState.unlocked) {
      _updateActivity();
      _restartIdleTimer();
    }
  }

  /// Load entries from vault
  Future<void> _loadEntries() async {
    try {
      final entriesData = await VaultChannel.listFiles();
      final entries = entriesData.map((e) => VaultEntry(
        fileId: List<int>.from(e['fileId'] as List),
        name: e['name'] as String,
        type: e['type'] as int,
        size: e['size'] as int,
        createdAt: DateTime.fromMillisecondsSinceEpoch(e['createdAt'] as int),
        mimeType: e['mimeType'] as String?,
        chunkCount: (e['chunkCount'] as int?) ?? 0,
      )).toList();
      
      await _loadFolderMap(entries);
      // Filter out system entries (e.g., __vault_title__)
      _entries = entries.where((e) => !e.name.startsWith('__')).toList();
    } catch (e) {
      _entries = [];
    }
  }

  String folderForEntry(VaultEntry entry) {
    return _fileFolders[_fileIdToHex(entry.fileId)] ?? '';
  }

  bool hasFolder(String path) {
    final normalized = _normalizeFolderPath(path);
    return normalized.isEmpty || _folders.contains(normalized);
  }

  Future<void> createFolder(String name, {String parent = ''}) async {
    SecureLogger.d('VaultStateManager', 'createFolder: name=$name, parent=$parent');
    final normalizedParent = _normalizeFolderPath(parent);
    final normalizedName = _normalizeFolderName(name);
    SecureLogger.d('VaultStateManager', 'createFolder: normalizedParent=$normalizedParent, normalizedName=$normalizedName');
    if (normalizedName.isEmpty) {
      SecureLogger.e('VaultStateManager', 'createFolder: folder name is empty after normalization');
      throw Exception('Folder name cannot be empty');
    }
    final fullPath = _normalizeFolderPath(
      normalizedParent.isEmpty ? normalizedName : '$normalizedParent/$normalizedName',
    );
    SecureLogger.d('VaultStateManager', 'createFolder: fullPath=$fullPath');
    if (fullPath.isEmpty) {
      SecureLogger.e('VaultStateManager', 'createFolder: fullPath is empty after normalization');
      throw Exception('Invalid folder name');
    }
    final added = _addFolderWithParents(fullPath);
    SecureLogger.d('VaultStateManager', 'createFolder: _addFolderWithParents returned $added, folders=${_folders.toList()}');
    
    // Only persist if folder was actually added (optimization for large vaults)
    if (added) {
      try {
        await _persistFolderMap();
        SecureLogger.d('VaultStateManager', 'createFolder: folder map persisted successfully');
      } catch (e) {
        SecureLogger.e('VaultStateManager', 'Failed to persist folder map after create: $e');
        _scheduleFolderMapPersist();
      }
    } else {
      SecureLogger.d('VaultStateManager', 'createFolder: folder already exists, skipping persist');
    }
    _safeNotify();
  }

  Future<void> moveFileToFolder(VaultEntry entry, String destination) async {
    final normalized = _normalizeFolderPath(destination);
    if (normalized.isNotEmpty) {
      _addFolderWithParents(normalized);
    }
    _fileFolders[_fileIdToHex(entry.fileId)] = normalized;
    try {
      await _persistFolderMap();
    } catch (e) {
      SecureLogger.e('VaultStateManager', 'Failed to persist folder map after move: $e');
      _scheduleFolderMapPersist();
    }
    _safeNotify();
  }

  /// Delete a folder and all its contents (files and subfolders)
  /// SECURITY: All files are securely deleted via VaultChannel.deleteFile
  /// which performs secure zeroization before deletion
  Future<int> deleteFolder(String folderPath) async {
    SecureLogger.d('VaultStateManager', 'deleteFolder: starting deletion of $folderPath');
    final normalized = _normalizeFolderPath(folderPath);
    if (normalized.isEmpty) {
      SecureLogger.e('VaultStateManager', 'deleteFolder: invalid folder path (empty after normalization)');
      throw Exception('Invalid folder path');
    }
    
    if (!_folders.contains(normalized)) {
      SecureLogger.e('VaultStateManager', 'deleteFolder: folder does not exist: $normalized');
      throw Exception('Folder does not exist');
    }
    
    SecureLogger.d('VaultStateManager', 'deleteFolder: deleting folder: $normalized');
    
    int deletedCount = 0;
    
    // Find all files in this folder and subfolders
    final filesToDelete = <String, List<int>>{};
    for (final entry in _entries) {
      final fileFolder = _fileFolders[_fileIdToHex(entry.fileId)] ?? '';
      // Check if file is in this folder or any subfolder
      if (fileFolder == normalized || fileFolder.startsWith('$normalized/')) {
        filesToDelete[_fileIdToHex(entry.fileId)] = entry.fileId;
      }
    }
    SecureLogger.d('VaultStateManager', 'deleteFolder: found ${filesToDelete.length} files to delete');
    
    // Delete all files in the folder
    for (final entry in filesToDelete.entries) {
      try {
        SecureLogger.d('VaultStateManager', 'deleteFolder: deleting file ${entry.key.substring(0, 8)}...');
        await VaultChannel.deleteFile(entry.value);
        _fileFolders.remove(entry.key);
        _entries.removeWhere((e) => _fileIdToHex(e.fileId) == entry.key);
        deletedCount++;
        SecureLogger.d('VaultStateManager', 'deleteFolder: deleted file ${entry.key.substring(0, 8)}...');
      } catch (e) {
        SecureLogger.e('VaultStateManager', 'deleteFolder: failed to delete file ${entry.key.substring(0, 8)}...', e);
        // Continue deleting other files even if one fails
      }
    }
    
    // Remove this folder and all subfolders from the folder set
    final foldersToRemove = _folders
        .where((f) => f == normalized || f.startsWith('$normalized/'))
        .toList();
    SecureLogger.d('VaultStateManager', 'deleteFolder: removing ${foldersToRemove.length} folders: $foldersToRemove');
    for (final folder in foldersToRemove) {
      _folders.remove(folder);
    }
    
    // Persist changes
    await _persistFolderMap();
    notifyListeners();
    
    SecureLogger.d('VaultStateManager', 'deleteFolder: completed, deleted $deletedCount files');
    return deletedCount;
  }

  /// Rename a folder
  /// SECURITY: Only updates folder metadata, no file content is modified
  /// All file-to-folder mappings are updated atomically
  Future<void> renameFolder(String oldPath, String newName) async {
    final normalizedOld = _normalizeFolderPath(oldPath);
    if (normalizedOld.isEmpty) {
      throw Exception('Invalid folder path');
    }
    
    if (!_folders.contains(normalizedOld)) {
      throw Exception('Folder does not exist');
    }
    
    // Validate new name
    final normalizedNewName = _normalizeFolderName(newName);
    if (normalizedNewName.isEmpty) {
      throw Exception('New folder name cannot be empty');
    }
    
    // Security: Prevent system folder names
    if (normalizedNewName.startsWith('__')) {
      throw Exception('Folder name cannot start with "__"');
    }
    
    // Calculate new path (keep parent, change only the folder name)
    final lastSlash = normalizedOld.lastIndexOf('/');
    final parentPath = lastSlash > 0 ? normalizedOld.substring(0, lastSlash) : '';
    final normalizedNew = parentPath.isEmpty 
        ? normalizedNewName 
        : '$parentPath/$normalizedNewName';
    
    // Check if new folder already exists
    if (_folders.contains(normalizedNew)) {
      throw Exception('A folder with this name already exists');
    }
    
    SecureLogger.d('VaultStateManager', 'Renaming folder: $normalizedOld -> $normalizedNew');
    
    // Update all subfolders
    final foldersToUpdate = _folders
        .where((f) => f == normalizedOld || f.startsWith('$normalizedOld/'))
        .toList();
    
    for (final folder in foldersToUpdate) {
      _folders.remove(folder);
      if (folder == normalizedOld) {
        _folders.add(normalizedNew);
      } else {
        // Update subfolder path
        final newSubPath = normalizedNew + folder.substring(normalizedOld.length);
        _folders.add(newSubPath);
      }
    }
    
    // Update all file-to-folder mappings
    final filesToUpdate = <String, String>{};
    for (final entry in _fileFolders.entries) {
      final fileFolder = entry.value;
      if (fileFolder == normalizedOld) {
        filesToUpdate[entry.key] = normalizedNew;
      } else if (fileFolder.startsWith('$normalizedOld/')) {
        final newFileFolder = normalizedNew + fileFolder.substring(normalizedOld.length);
        filesToUpdate[entry.key] = newFileFolder;
      }
    }
    
    for (final entry in filesToUpdate.entries) {
      _fileFolders[entry.key] = entry.value;
    }
    
    // Persist changes
    await _persistFolderMap();
    notifyListeners();
    
    SecureLogger.d('VaultStateManager', 'Folder renamed: $normalizedOld -> $normalizedNew');
  }

  /// Get list of files in a specific folder (not including subfolders)
  List<VaultEntry> getFilesInFolder(String folderPath) {
    final normalized = _normalizeFolderPath(folderPath);
    return _entries.where((e) {
      final fileFolder = _fileFolders[_fileIdToHex(e.fileId)] ?? '';
      return fileFolder == normalized;
    }).toList();
  }

  /// Get count of all files in a folder and its subfolders
  int getFileCountInFolderRecursive(String folderPath) {
    final normalized = _normalizeFolderPath(folderPath);
    if (normalized.isEmpty) return 0;
    
    int count = 0;
    for (final entry in _entries) {
      final fileFolder = _fileFolders[_fileIdToHex(entry.fileId)] ?? '';
      if (fileFolder == normalized || fileFolder.startsWith('$normalized/')) {
        count++;
      }
    }
    return count;
  }

  /// Apply imported files to folder map
  /// Note: This will persist the folder map which can be slow after large imports
  Future<void> applyImportedFiles(Map<List<int>, String> fileFolders) async {
    SecureLogger.d('VaultStateManager', 'applyImportedFiles: processing ${fileFolders.length} files');
    if (fileFolders.isEmpty) return;
    
    // Update in-memory state first
    for (final entry in fileFolders.entries) {
      final folder = _normalizeFolderPath(entry.value);
      SecureLogger.d('VaultStateManager', 'applyImportedFiles: fileId=${_fileIdToHex(entry.key).substring(0, 8)}..., folder=$folder');
      if (folder.isNotEmpty) {
        final added = _addFolderWithParents(folder);
        SecureLogger.d('VaultStateManager', 'applyImportedFiles: _addFolderWithParents($folder) returned $added');
      }
      _fileFolders[_fileIdToHex(entry.key)] = folder;
    }
    SecureLogger.d('VaultStateManager', 'applyImportedFiles: folders after update=${_folders.toList()}');
    
    // Persist with retry logic (can fail if vault is busy)
    try {
      await _persistFolderMap();
      SecureLogger.d('VaultStateManager', 'applyImportedFiles: folder map persisted successfully');
    } catch (e) {
      // Log error but don't fail - folder map is in memory and will be persisted later
      SecureLogger.e('VaultStateManager', 'Failed to persist folder map after import: $e');
      // Schedule a delayed retry
      _scheduleFolderMapPersist();
    }
    
    // IMPORTANT: Notify listeners so UI updates to show new folders
    notifyListeners();
  }
  
  Timer? _folderMapPersistTimer;
  
  void _scheduleFolderMapPersist() {
    _folderMapPersistTimer?.cancel();
    _folderMapPersistTimer = Timer(const Duration(seconds: 5), () async {
      if (_state == VaultState.unlocked) {
        try {
          await _persistFolderMap();
          SecureLogger.d('VaultStateManager', 'Delayed folder map persist succeeded');
        } catch (e) {
          SecureLogger.e('VaultStateManager', 'Delayed folder map persist failed: $e');
        }
      }
    });
  }

  Future<void> removeFileFromFolderMap(List<int> fileId) async {
    final hexId = _fileIdToHex(fileId);
    SecureLogger.d('VaultStateManager', 'removeFileFromFolderMap: removing file ${hexId.substring(0, 8)}...');
    final removed = _fileFolders.remove(hexId) != null;
    SecureLogger.d('VaultStateManager', 'removeFileFromFolderMap: removed=$removed');
    if (removed) {
      await _persistFolderMap();
      SecureLogger.d('VaultStateManager', 'removeFileFromFolderMap: folder map persisted');
      notifyListeners();
    }
  }

  Future<void> _loadFolderMap(List<VaultEntry> allEntries) async {
    SecureLogger.d('VaultStateManager', '_loadFolderMap: starting, allEntries=${allEntries.length}');
    VaultEntry? mapEntry;
    VaultEntry? tempEntry;
    for (final entry in allEntries) {
      if (entry.name == _folderMapName) {
        mapEntry = entry;
        SecureLogger.d('VaultStateManager', '_loadFolderMap: found mapEntry');
      } else if (entry.name == _folderMapTempName) {
        tempEntry = entry;
        SecureLogger.d('VaultStateManager', '_loadFolderMap: found tempEntry');
      }
    }

    if (mapEntry == null && tempEntry != null) {
      SecureLogger.d('VaultStateManager', '_loadFolderMap: renaming temp to main');
      try {
        await VaultChannel.renameFile(
          tempEntry.fileId,
          _folderMapName,
          allowSystem: true,
        );
        mapEntry = VaultEntry(
          fileId: tempEntry.fileId,
          name: _folderMapName,
          type: tempEntry.type,
          size: tempEntry.size,
          createdAt: tempEntry.createdAt,
          mimeType: tempEntry.mimeType,
          chunkCount: tempEntry.chunkCount,
        );
      } catch (e) {
        // Ignore and treat as no map.
        SecureLogger.e('VaultStateManager', '_loadFolderMap: rename failed', e);
      }
    }

    SecureLogger.d('VaultStateManager', '_loadFolderMap: clearing folders and fileFolders, mapEntry=${mapEntry != null}');
    _fileFolders.clear();
    _folders.clear();

    if (mapEntry == null) {
      SecureLogger.d('VaultStateManager', '_loadFolderMap: no mapEntry found, returning empty');
      return;
    }

    Uint8List? mapBytes;
    try {
      mapBytes = await VaultChannel.readFile(mapEntry.fileId);
      SecureLogger.d('VaultStateManager', '_loadFolderMap: read ${mapBytes.length} bytes');
      final decoded = jsonDecode(utf8.decode(mapBytes)) as Map<String, dynamic>;
      SecureLogger.d('VaultStateManager', '_loadFolderMap: decoded version=${decoded['version']}');
      if (decoded['version'] != _folderMapVersion) {
        SecureLogger.w('VaultStateManager', '_loadFolderMap: version mismatch, expected $_folderMapVersion');
        return;
      }
      final folders = decoded['folders'];
      if (folders is List) {
        SecureLogger.d('VaultStateManager', '_loadFolderMap: loading ${folders.length} folders');
        for (final value in folders) {
          final normalized = _normalizeFolderPath(value.toString());
          if (normalized.isNotEmpty) {
            _addFolderWithParents(normalized);
          }
        }
      }
      final files = decoded['files'];
      if (files is Map) {
        SecureLogger.d('VaultStateManager', '_loadFolderMap: loading ${files.length} file mappings');
        files.forEach((key, value) {
          final folder = _normalizeFolderPath(value.toString());
          _fileFolders[key.toString()] = folder;
          if (folder.isNotEmpty) {
            _addFolderWithParents(folder);
          }
        });
      }
      SecureLogger.d('VaultStateManager', '_loadFolderMap: loaded folders=${_folders.toList()}');
    } catch (e) {
      SecureLogger.e('VaultStateManager', '_loadFolderMap: error loading', e);
      _fileFolders.clear();
      _folders.clear();
    } finally {
      SecurePassphrase.zeroize(mapBytes);
    }

    final existing = allEntries
        .where((e) => !e.name.startsWith('__'))
        .map((e) => _fileIdToHex(e.fileId))
        .toSet();
    final removedKeys = _fileFolders.keys.where((k) => !existing.contains(k)).toList();
    for (final key in removedKeys) {
      _fileFolders.remove(key);
    }
    if (removedKeys.isNotEmpty) {
      await _persistFolderMap();
    }
  }

  Future<void> _persistFolderMap() async {
    SecureLogger.d('VaultStateManager', '_persistFolderMap: starting, folders=${_folders.toList()}, files=${_fileFolders.length}');
    final payload = jsonEncode({
      'version': _folderMapVersion,
      'folders': _folders.toList()..sort(),
      'files': _fileFolders,
    });
    final bytes = Uint8List.fromList(utf8.encode(payload));
    SecureLogger.d('VaultStateManager', '_persistFolderMap: payload size=${bytes.length}');
    try {
      // Retry logic for folder map persistence
      // This can fail if vault is busy with other operations
      const maxRetries = 3;
      const retryDelayMs = 500;
      
      for (int attempt = 0; attempt < maxRetries; attempt++) {
        try {
          SecureLogger.d('VaultStateManager', '_persistFolderMap: attempt ${attempt + 1}');
          await _upsertSystemFile(_folderMapName, bytes, mime: 'application/json');
          SecureLogger.d('VaultStateManager', '_persistFolderMap: _upsertSystemFile completed');
          return; // Success
        } catch (e) {
          SecureLogger.w('VaultStateManager', 'Folder map persist attempt ${attempt + 1} failed: $e');
          if (attempt < maxRetries - 1) {
            // Wait before retry, increasing delay each time
            await Future.delayed(Duration(milliseconds: retryDelayMs * (attempt + 1)));
          } else {
            // Final attempt failed, rethrow
            rethrow;
          }
        }
      }
    } finally {
      SecurePassphrase.zeroize(bytes);
    }
  }

  Future<void> _upsertSystemFile(String name, Uint8List data, {String? mime}) async {
    SecureLogger.d('VaultStateManager', '_upsertSystemFile: starting for $name, size=${data.length}');
    final tempName = '$name.tmp';
    final entries = await VaultChannel.listFiles();
    Map<String, dynamic>? existing;
    Map<String, dynamic>? tempExisting;
    for (final entry in entries) {
      if (entry['name'] == name) {
        existing = entry;
      } else if (entry['name'] == tempName) {
        tempExisting = entry;
      }
    }
    SecureLogger.d('VaultStateManager', '_upsertSystemFile: existing=${existing != null}, tempExisting=${tempExisting != null}');
    
    if (tempExisting != null) {
      SecureLogger.d('VaultStateManager', '_upsertSystemFile: deleting old temp file');
      await VaultChannel.deleteFile(List<int>.from(tempExisting['fileId'] as List));
      SecureLogger.d('VaultStateManager', '_upsertSystemFile: old temp file deleted');
    }

    SecureLogger.d('VaultStateManager', '_upsertSystemFile: creating temp file $tempName');
    final created = await VaultChannel.importBytes(
      data: data,
      name: tempName,
      mime: mime,
      type: 1,
    );
    SecureLogger.d('VaultStateManager', '_upsertSystemFile: temp file created, fileId=${created.take(4)}');

    if (existing != null) {
      SecureLogger.d('VaultStateManager', '_upsertSystemFile: deleting old main file');
      await VaultChannel.deleteFile(List<int>.from(existing['fileId'] as List));
      SecureLogger.d('VaultStateManager', '_upsertSystemFile: old main file deleted');
    }
    
    SecureLogger.d('VaultStateManager', '_upsertSystemFile: renaming temp to main');
    try {
      await VaultChannel.renameFile(
        created,
        name,
        allowSystem: true,
      );
      SecureLogger.d('VaultStateManager', '_upsertSystemFile: rename completed successfully');
    } catch (e) {
      SecureLogger.e('VaultStateManager', '_upsertSystemFile: rename failed', e);
      rethrow;
    }
  }

  String _fileIdToHex(List<int> fileId) {
    final buffer = StringBuffer();
    for (final b in fileId) {
      buffer.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }

  bool _addFolderWithParents(String path) {
    final normalized = _normalizeFolderPath(path);
    if (normalized.isEmpty) return false;
    bool added = false;
    final parts = normalized.split('/');
    var current = '';
    for (final part in parts) {
      current = current.isEmpty ? part : '$current/$part';
      if (_folders.add(current)) {
        added = true;
      }
    }
    return added;
  }

  String _normalizeFolderPath(String path) {
    final cleaned = path.replaceAll('\\', '/').trim();
    if (cleaned.isEmpty) return '';
    final parts = cleaned
        .split('/')
        .map((p) => p.trim())
        .where((p) => p.isNotEmpty && p != '.' && p != '..')
        .toList();
    return parts.join('/');
  }

  String _normalizeFolderName(String name) {
    final trimmed = name.replaceAll('\\', '/').trim();
    if (trimmed.isEmpty) return '';
    if (trimmed.contains('/')) return '';
    if (trimmed.startsWith('__')) return '';
    if (trimmed.length > 128) return '';
    return trimmed;
  }

  /// Refresh entries list
  Future<void> refreshEntries() async {
    if (_state == VaultState.unlocked) {
      await _loadEntries();
      notifyListeners();
    }
  }

  /// Refresh entries list without reloading folder map
  /// Use this after applyImportedFiles to avoid race condition with folder map persistence
  Future<void> refreshEntriesOnly() async {
    if (_state != VaultState.unlocked) return;
    try {
      final entriesData = await VaultChannel.listFiles();
      final entries = entriesData.map((e) => VaultEntry(
        fileId: List<int>.from(e['fileId'] as List),
        name: e['name'] as String,
        type: e['type'] as int,
        size: e['size'] as int,
        createdAt: DateTime.fromMillisecondsSinceEpoch(e['createdAt'] as int),
        mimeType: e['mimeType'] as String?,
        chunkCount: (e['chunkCount'] as int?) ?? 0,
      )).toList();
      // Filter out system entries but DON'T reload folder map
      _entries = entries.where((e) => !e.name.startsWith('__')).toList();
      notifyListeners();
    } catch (e) {
      SecureLogger.e('VaultStateManager', 'refreshEntriesOnly failed', e);
    }
  }

  /// Start idle timer
  void _startIdleTimer() {
    // Don't start timer if frozen
    if (_timersFrozen) return;
    _stopIdleTimer();
    final seconds = AppSettings.instance.idleTimeoutSeconds;
    _idleTimer = Timer(Duration(seconds: seconds), () {
      // Double-check frozen state before locking
      if (_state == VaultState.unlocked && !_timersFrozen) {
        lockVault();
      }
    });
  }

  /// Restart idle timer
  void _restartIdleTimer() {
    if (!_timersFrozen) {
      _startIdleTimer();
    }
  }

  /// Stop idle timer
  void _stopIdleTimer() {
    _idleTimer?.cancel();
    _idleTimer = null;
  }

  void _startSessionTimer() {
    // Don't start timer if frozen
    if (_timersFrozen) return;
    _stopSessionTimer();
    final minutes = AppSettings.instance.sessionLimitMinutes;
    _sessionTimer = Timer(Duration(minutes: minutes), () {
      // Double-check frozen state before reauthentication
      if (_state == VaultState.unlocked && !_timersFrozen) {
        _reauthenticateSession();
      }
    });
  }

  void _stopSessionTimer() {
    _sessionTimer?.cancel();
    _sessionTimer = null;
  }

  Future<void> _reauthenticateSession() async {
    // Don't reauthenticate if timers are frozen (during import)
    if (_reauthInProgress || _timersFrozen) return;
    _reauthInProgress = true;
    try {
      final ok = await VaultChannel.authenticateBiometric();
      if (ok) {
        _updateActivity();
        _restartIdleTimer();
        _startSessionTimer();
      } else {
        // Only lock if not frozen
        if (!_timersFrozen) {
          await lockVault();
        }
      }
    } finally {
      _reauthInProgress = false;
    }
  }

  void _handleSettingsChange() {
    // Don't restart timers if they are frozen (during import operations)
    if (_state == VaultState.unlocked && !_timersFrozen) {
      _startIdleTimer();
      _startSessionTimer();
    }
  }

  /// Handle app lifecycle change
  void onAppLifecycleChange(bool isBackground) {
    // Don't auto-lock if timers are frozen (during import operations)
    if (isBackground && _state == VaultState.unlocked && !_suppressAutoLock && !_timersFrozen) {
      lockVault();
    }
  }

  /// Search entries by name
  List<VaultEntry> searchEntries(String query) {
    if (query.isEmpty) return _entries;
    final lowerQuery = query.toLowerCase();
    return _entries.where((e) => e.name.toLowerCase().contains(lowerQuery)).toList();
  }

  @override
  void dispose() {
    _stopIdleTimer();
    _stopSessionTimer();
    _folderMapPersistTimer?.cancel();
    AppSettings.instance.removeListener(_handleSettingsChange);
    super.dispose();
  }
}
