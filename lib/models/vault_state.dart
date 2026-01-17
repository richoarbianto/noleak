/// Vault State Enumeration
/// 
/// Represents the current state of a vault in the application lifecycle.
/// The state machine transitions are:
/// 
/// ```
/// uninitialized → locked (after vault creation)
/// locked → unlocked (after successful authentication)
/// unlocked → locked (after timeout or manual lock)
/// any state → blocked (if security check fails)
/// ```
enum VaultState {
  /// No vault exists yet
  uninitialized,
  
  /// Vault exists but is locked
  locked,
  
  /// Vault is unlocked and accessible
  unlocked,
  
  /// Device is compromised (root/tamper detected)
  blocked,
}

/// Represents a file entry stored in the encrypted vault.
/// 
/// Each entry contains metadata about the encrypted file including:
/// - [fileId]: Unique 16-byte identifier for the file
/// - [name]: Original filename (stored encrypted in vault)
/// - [type]: File type category (1=text, 2=image, 3=video)
/// - [size]: Original file size in bytes
/// - [mimeType]: MIME type for proper file handling
/// - [chunkCount]: Number of encrypted chunks (for streaming)
/// 
/// The actual file content is stored encrypted in the vault container
/// and can only be accessed when the vault is unlocked.
class VaultEntry {
  final List<int> fileId;
  final String name;
  final int type; // 1=txt, 2=img, 3=video
  final int size;
  final DateTime createdAt;
  final String? mimeType;
  final int chunkCount;

  VaultEntry({
    required this.fileId,
    required this.name,
    required this.type,
    required this.size,
    required this.createdAt,
    this.mimeType,
    this.chunkCount = 0,
  });

  String get _extension {
    final dot = name.lastIndexOf('.');
    if (dot == -1 || dot == name.length - 1) return '';
    return name.substring(dot + 1).toLowerCase();
  }

  bool get isVideo {
    if (mimeType != null && mimeType!.startsWith('video/')) return true;
    return type == 3;
  }

  bool get isImage {
    if (mimeType != null && mimeType!.startsWith('image/')) return true;
    return type == 2;
  }

  bool get isAudio {
    if (mimeType != null && mimeType!.startsWith('audio/')) return true;
    return const {'mp3', 'm4a', 'wav'}.contains(_extension);
  }

  bool get isPdf {
    if (mimeType == 'application/pdf') return true;
    return _extension == 'pdf';
  }

  bool get isDocx {
    return mimeType == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
        _extension == 'docx';
  }

  bool get isPptx {
    return mimeType == 'application/vnd.openxmlformats-officedocument.presentationml.presentation' ||
        _extension == 'pptx';
  }

  bool get isXlsx {
    return mimeType == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' ||
        _extension == 'xlsx';
  }

  bool get isCsv {
    return mimeType == 'text/csv' ||
        mimeType == 'text/comma-separated-values' ||
        _extension == 'csv';
  }

  bool get isTextLike {
    if (mimeType == null) return type == 1;
    if (mimeType!.startsWith('text/')) return true;
    return const {
      'application/x-pem-file',
      'application/pgp-keys',
      'application/x-ssh-key',
      'application/pkcs8',
    }.contains(mimeType);
  }

  String get typeIcon {
    if (isPdf) return '📕';
    if (isDocx) return '📝';
    if (isPptx) return '📽️';
    if (isXlsx) return '📊';
    if (isCsv) return '📊';
    if (isAudio) return '🎧';
    if (isVideo) return '🎬';
    if (isImage) return '🖼️';
    return '📄';
  }

  String get sizeFormatted {
    if (size < 1024) return '$size B';
    if (size < 1024 * 1024) return '${(size / 1024).toStringAsFixed(1)} KB';
    if (size < 1024 * 1024 * 1024) {
      return '${(size / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(size / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
  }
}
