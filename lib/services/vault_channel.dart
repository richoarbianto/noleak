import 'dart:typed_data';
import 'package:flutter/services.dart';

/// VaultChannel - Flutter Platform Channel Bridge
/// 
/// This class provides the Dart interface to native Android functionality
/// via Flutter's MethodChannel. All vault operations are performed in
/// native code (Kotlin/C) for security reasons.
/// 
/// Key responsibilities:
/// - Vault lifecycle (create, open, close)
/// - File operations (import, read, delete, export)
/// - Security checks (environment verification, biometrics)
/// - Media playback (video/audio streaming from encrypted data)
/// 
/// SECURITY: All sensitive operations are delegated to native code
/// where memory can be properly locked and zeroized.
class VaultChannel {
  static const _channel = MethodChannel('com.noleak.vault');

  /// Enable wakelock to keep screen on
  static Future<void> enableWakelock() async {
    try {
      await _channel.invokeMethod('enableWakelock');
    } on PlatformException {
      // Ignore if not supported
    }
  }

  /// Disable wakelock to allow screen to turn off
  static Future<void> disableWakelock() async {
    try {
      await _channel.invokeMethod('disableWakelock');
    } on PlatformException {
      // Ignore if not supported
    }
  }

  /// Check if environment is secure (no root/tamper detected)
  static Future<bool> checkEnvironment() async {
    final result = await _channel.invokeMethod<Map>('checkEnvironment');
    return result?['ok'] == true;
  }

  /// Check if vault file exists
  static Future<bool> vaultExists() async {
    return await _channel.invokeMethod<bool>('vaultExists') ?? false;
  }

  /// Check if vault is currently open
  static Future<bool> isVaultOpen() async {
    return await _channel.invokeMethod<bool>('isVaultOpen') ?? false;
  }

  /// Create a new vault with passphrase
  static Future<void> createVault(String passphrase) async {
    await _channel.invokeMethod('createVault', {'passphrase': passphrase});
  }

  /// Open vault with passphrase
  static Future<void> openVault(String passphrase) async {
    await _channel.invokeMethod('openVault', {'passphrase': passphrase});
  }

  /// Close the vault
  static Future<void> closeVault() async {
    await _channel.invokeMethod('closeVault');
  }

  /// Pick a file using SAF
  static Future<Map<String, dynamic>?> pickFile() async {
    final result = await _channel.invokeMethod<Map>('pickFile');
    if (result == null) return null;
    return Map<String, dynamic>.from(result);
  }

  /// Pick a folder using SAF
  static Future<Map<String, dynamic>?> pickFolder() async {
    final result = await _channel.invokeMethod<Map>('pickFolder');
    if (result == null) return null;
    return Map<String, dynamic>.from(result);
  }

  /// Import a file into the vault
  static Future<Map<String, dynamic>> importFile(String uri, {int? sessionId}) async {
    final result = await _channel.invokeMethod<Map>('importFile', {
      'uri': uri,
      'sessionId': sessionId,
    });
    return Map<String, dynamic>.from(result!);
  }

  /// Import a folder (nested) into the vault
  static Future<Map<String, dynamic>> importFolder(
    String uri, {
    int? sessionId,
  }) async {
    final result = await _channel.invokeMethod<Map>('importFolder', {
      'uri': uri,
      'sessionId': sessionId,
    });
    if (result == null) return {};
    return Map<String, dynamic>.from(result);
  }

  /// Import in-memory data (used for system metadata like folder map)
  static Future<List<int>> importBytes({
    required Uint8List data,
    required String name,
    String? mime,
    int type = 1,
  }) async {
    final result = await _channel.invokeMethod<List>('importBytes', {
      'data': data,
      'name': name,
      'mime': mime,
      'type': type,
    });
    return (result ?? <int>[]).cast<int>();
  }

  /// Read a file from the vault
  static Future<Uint8List> readFile(List<int> fileId) async {
    final result = await _channel.invokeMethod<Uint8List>('readFile', {'fileId': fileId});
    return result!;
  }

  /// Read text preview from vault (max 1MB for large files)
  /// Returns map with: data (Uint8List), truncated (bool), totalSize (int)
  static Future<Map<String, dynamic>> readTextPreview(List<int> fileId, {int maxBytes = 1024 * 1024}) async {
    final result = await _channel.invokeMethod<Map>('readTextPreview', {
      'fileId': fileId,
      'maxBytes': maxBytes,
    });
    return Map<String, dynamic>.from(result!);
  }

  /// Delete a file from the vault
  static Future<void> deleteFile(List<int> fileId) async {
    await _channel.invokeMethod('deleteFile', {'fileId': fileId});
  }

  /// Rename a file in the vault
  static Future<void> renameFile(
    List<int> fileId,
    String name, {
    bool allowSystem = false,
  }) async {
    await _channel.invokeMethod('renameFile', {
      'fileId': fileId,
      'name': name,
      'allowSystem': allowSystem,
    });
  }

  /// Copy a file in the vault (re-encrypts to new file ID)
  static Future<List<int>> copyFile(List<int> fileId) async {
    final result = await _channel.invokeMethod<List>('copyFile', {'fileId': fileId});
    return (result ?? <int>[]).cast<int>();
  }

  /// Export a decrypted file to external storage via SAF
  /// Returns true if export was successful, false if cancelled
  static Future<bool> exportFile(List<int> fileId, String suggestedName) async {
    try {
      return await _channel.invokeMethod<bool>('exportFile', {
        'fileId': fileId,
        'suggestedName': suggestedName,
      }) ?? false;
    } on PlatformException {
      return false;
    }
  }

  /// Get number of entries in vault
  static Future<int> getEntryCount() async {
    return await _channel.invokeMethod<int>('getEntryCount') ?? 0;
  }

  /// List all files in vault
  static Future<List<Map<String, dynamic>>> listFiles() async {
    final result = await _channel.invokeMethod<List>('listFiles');
    if (result == null) return [];
    return result.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  /// Authenticate with biometric
  static Future<bool> authenticateBiometric() async {
    try {
      return await _channel.invokeMethod<bool>('authenticateBiometric') ?? false;
    } on PlatformException {
      return false;
    }
  }

  // Video methods

  /// Open a video for playback
  /// Returns map with: handle, textureId, width, height, durationMs
  static Future<Map<String, dynamic>> openVideo({
    required List<int> fileId,
    required int chunkCount,
    int durationMs = 0,
    int width = 0,
    int height = 0,
    int size = 0,
  }) async {
    final result = await _channel.invokeMethod<Map>('openVideo', {
      'fileId': fileId,
      'chunkCount': chunkCount,
      'durationMs': durationMs,
      'width': width,
      'height': height,
      'size': size,
    });
    return Map<String, dynamic>.from(result!);
  }

  /// Open an audio file for playback
  /// Returns map with: handle, durationMs
  static Future<Map<String, dynamic>> openAudio({
    required List<int> fileId,
    String? mimeType,
  }) async {
    final result = await _channel.invokeMethod<Map>('openAudio', {
      'fileId': fileId,
      'mimeType': mimeType,
    });
    return Map<String, dynamic>.from(result!);
  }

  /// Play video by handle
  static Future<bool> playVideo(int handle) async {
    return await _channel.invokeMethod<bool>('playVideo', {'handle': handle}) ?? false;
  }

  /// Pause video by handle
  static Future<bool> pauseVideo(int handle) async {
    return await _channel.invokeMethod<bool>('pauseVideo', {'handle': handle}) ?? false;
  }

  /// Seek video to position (milliseconds)
  static Future<bool> seekVideo(int handle, int positionMs) async {
    return await _channel.invokeMethod<bool>('seekVideo', {
      'handle': handle,
      'positionMs': positionMs,
    }) ?? false;
  }

  /// Get current video position (milliseconds)
  static Future<int> getVideoPosition(int handle) async {
    return await _channel.invokeMethod<int>('getVideoPosition', {'handle': handle}) ?? 0;
  }

  /// Get video duration (milliseconds)
  static Future<int> getVideoDuration(int handle) async {
    return await _channel.invokeMethod<int>('getVideoDuration', {'handle': handle}) ?? 0;
  }

  /// Check if video is playing
  static Future<bool> isVideoPlaying(int handle) async {
    return await _channel.invokeMethod<bool>('isVideoPlaying', {'handle': handle}) ?? false;
  }

  /// Close video by handle
  static Future<bool> closeVideo(int handle) async {
    return await _channel.invokeMethod<bool>('closeVideo', {'handle': handle}) ?? false;
  }

  /// Play audio by handle
  static Future<bool> playAudio(int handle) async {
    return await _channel.invokeMethod<bool>('playAudio', {'handle': handle}) ?? false;
  }

  /// Pause audio by handle
  static Future<bool> pauseAudio(int handle) async {
    return await _channel.invokeMethod<bool>('pauseAudio', {'handle': handle}) ?? false;
  }

  /// Seek audio to position (milliseconds)
  static Future<bool> seekAudio(int handle, int positionMs) async {
    return await _channel.invokeMethod<bool>('seekAudio', {
      'handle': handle,
      'positionMs': positionMs,
    }) ?? false;
  }

  /// Get current audio position (milliseconds)
  static Future<int> getAudioPosition(int handle) async {
    return await _channel.invokeMethod<int>('getAudioPosition', {'handle': handle}) ?? 0;
  }

  /// Get audio duration (milliseconds)
  static Future<int> getAudioDuration(int handle) async {
    return await _channel.invokeMethod<int>('getAudioDuration', {'handle': handle}) ?? 0;
  }

  /// Check if audio is playing
  static Future<bool> isAudioPlaying(int handle) async {
    return await _channel.invokeMethod<bool>('isAudioPlaying', {'handle': handle}) ?? false;
  }

  /// Close audio by handle
  static Future<bool> closeAudio(int handle) async {
    return await _channel.invokeMethod<bool>('closeAudio', {'handle': handle}) ?? false;
  }

  /// Export encrypted vault container via SAF (ACTION_CREATE_DOCUMENT)
  static Future<bool> exportVault() async {
    return await _channel.invokeMethod<bool>('exportVault') ?? false;
  }

  /// Import encrypted vault container via SAF (ACTION_OPEN_DOCUMENT)
  static Future<bool> importVault() async {
    return await _channel.invokeMethod<bool>('importVault') ?? false;
  }

  /// Verify password matches the current vault
  static Future<bool> verifyPassword(String password) async {
    try {
      return await _channel.invokeMethod<bool>('verifyPassword', {'password': password}) ?? false;
    } on PlatformException {
      return false;
    }
  }

  /// Change vault password (requires current password verification)
  static Future<bool> changePassword(String currentPassword, String newPassword) async {
    try {
      return await _channel.invokeMethod<bool>('changePassword', {
        'currentPassword': currentPassword,
        'newPassword': newPassword,
      }) ?? false;
    } on PlatformException {
      return false;
    }
  }

  // ========== Multi-Vault Methods ==========

  /// List all vaults on device
  static Future<List<Map<String, dynamic>>> listVaults() async {
    try {
      final result = await _channel.invokeMethod<List>('listVaults');
      if (result == null) return [];
      return result.map((e) => Map<String, dynamic>.from(e as Map)).toList();
    } on PlatformException {
      return [];
    }
  }

  /// Create a new vault with encrypted title
  /// Throws PlatformException on failure with error details
  static Future<Map<String, dynamic>?> createVaultWithTitle({
    required String title,
    required String password,
  }) async {
    final result = await _channel.invokeMethod<Map>('createVaultWithTitle', {
      'title': title,
      'password': password,
    });
    return result != null ? Map<String, dynamic>.from(result) : null;
  }

  /// Import vault with title (legacy)
  static Future<Map<String, dynamic>?> importVaultWithTitle({required String title}) async {
    try {
      final result = await _channel.invokeMethod<Map>('importVaultWithTitle', {
        'title': title,
      });
      return result != null ? Map<String, dynamic>.from(result) : null;
    } on PlatformException {
      return null;
    }
  }

  /// Import vault file (title is read from inside the vault)
  static Future<Map<String, dynamic>?> importVaultFile() async {
    try {
      final result = await _channel.invokeMethod<Map>('importVaultFile');
      return result != null ? Map<String, dynamic>.from(result) : null;
    } on PlatformException {
      return null;
    }
  }

  /// Pick vault file only (returns URI string, doesn't import)
  /// Use this for 2-step import to show progress indicator in Flutter UI
  static Future<String?> pickVaultFile() async {
    try {
      return await _channel.invokeMethod<String>('pickVaultFile');
    } on PlatformException {
      return null;
    }
  }

  /// Import vault from URI (with progress via TransferProgressService)
  /// Use after pickVaultFile() to import with progress indicator
  static Future<Map<String, dynamic>?> importVaultFromUri(String uri) async {
    try {
      final result = await _channel.invokeMethod<Map>('importVaultFromUri', {'uri': uri});
      return result != null ? Map<String, dynamic>.from(result) : null;
    } on PlatformException {
      return null;
    }
  }

  /// Get decrypted vault title (requires password)
  static Future<String?> getVaultTitle({
    required String vaultId,
    required String password,
  }) async {
    try {
      return await _channel.invokeMethod<String>('getVaultTitle', {
        'vaultId': vaultId,
        'password': password,
      });
    } on PlatformException {
      return null;
    }
  }

  /// Set vault title (requires password, encrypts new title)
  static Future<bool> setVaultTitle({
    required String vaultId,
    required String password,
    required String newTitle,
  }) async {
    try {
      return await _channel.invokeMethod<bool>('setVaultTitle', {
        'vaultId': vaultId,
        'password': password,
        'newTitle': newTitle,
      }) ?? false;
    } on PlatformException {
      return false;
    }
  }

  /// Delete a vault completely
  static Future<bool> deleteVault({required String vaultId}) async {
    try {
      return await _channel.invokeMethod<bool>('deleteVaultById', {
        'vaultId': vaultId,
      }) ?? false;
    } on PlatformException {
      return false;
    }
  }

  /// Open a specific vault by ID
  static Future<void> openVaultById({
    required String vaultId,
    required String password,
  }) async {
    await _channel.invokeMethod('openVaultById', {
      'vaultId': vaultId,
      'password': password,
    });
  }

  /// Export a specific vault
  static Future<bool> exportVaultById({required String vaultId}) async {
    try {
      return await _channel.invokeMethod<bool>('exportVaultById', {
        'vaultId': vaultId,
      }) ?? false;
    } on PlatformException {
      return false;
    }
  }
}
