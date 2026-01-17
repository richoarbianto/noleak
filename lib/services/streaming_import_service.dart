/// StreamingImportService - Large File Import Handler
/// 
/// Handles streaming import of large files to avoid memory exhaustion.
/// Files are imported in chunks (1MB each) and encrypted incrementally.
/// 
/// Features:
/// - Progress tracking via [progressStream]
/// - Resume support for interrupted imports
/// - Abort capability for pending imports
/// 
/// The service uses EventChannel to receive progress updates from
/// native code during the import process.

import 'dart:async';
import 'package:flutter/services.dart';

/// Progress data for an ongoing file import operation.
/// 
/// Contains information about:
/// - [importId]: Unique identifier for this import operation
/// - [bytesWritten]: Bytes processed so far
/// - [totalBytes]: Total file size
/// - [chunksCompleted]: Number of chunks encrypted
/// - [percentage]: Progress as 0-100 value
/// - [isComplete]: Whether import finished successfully
/// - [error]: Error message if import failed
class ImportProgress {
  final List<int> importId;
  final int bytesWritten;
  final int totalBytes;
  final int chunksCompleted;
  final int totalChunks;
  final double percentage;
  final bool isComplete;
  final String? error;
  final int? sessionId;

  ImportProgress({
    required this.importId,
    required this.bytesWritten,
    required this.totalBytes,
    required this.chunksCompleted,
    required this.totalChunks,
    required this.percentage,
    required this.isComplete,
    this.error,
    this.sessionId,
  });

  factory ImportProgress.fromMap(Map<dynamic, dynamic> map) {
    final sessionValue = map['sessionId'];
    return ImportProgress(
      importId: (map['importId'] as List).cast<int>(),
      bytesWritten: (map['bytesWritten'] as num).toInt(),
      totalBytes: (map['totalBytes'] as num).toInt(),
      chunksCompleted: (map['chunksCompleted'] as num).toInt(),
      totalChunks: (map['totalChunks'] as num).toInt(),
      percentage: (map['percentage'] as num).toDouble(),
      isComplete: map['isComplete'] as bool? ?? false,
      error: map['error'] as String?,
      sessionId: sessionValue is num ? sessionValue.toInt() : null,
    );
  }
}

/// Pending import state for resume
class PendingImport {
  final List<int> importId;
  final List<int> fileId;
  final String? fileName;
  final String? mimeType;
  final int fileType;
  final int fileSize;
  final int totalChunks;
  final int completedChunks;
  final double progress;
  final int createdAt;
  final int updatedAt;

  PendingImport({
    required this.importId,
    required this.fileId,
    this.fileName,
    this.mimeType,
    required this.fileType,
    required this.fileSize,
    required this.totalChunks,
    required this.completedChunks,
    required this.progress,
    required this.createdAt,
    required this.updatedAt,
  });

  factory PendingImport.fromMap(Map<dynamic, dynamic> map) {
    return PendingImport(
      importId: (map['importId'] as List).cast<int>(),
      fileId: (map['fileId'] as List).cast<int>(),
      fileName: map['fileName'] as String?,
      mimeType: map['mimeType'] as String?,
      fileType: (map['fileType'] as num).toInt(),
      fileSize: (map['fileSize'] as num).toInt(),
      totalChunks: (map['totalChunks'] as num).toInt(),
      completedChunks: (map['completedChunks'] as num).toInt(),
      progress: (map['progress'] as num).toDouble(),
      createdAt: (map['createdAt'] as num).toInt(),
      updatedAt: (map['updatedAt'] as num).toInt(),
    );
  }

  String get progressText {
    final percent = (progress * 100).toStringAsFixed(1);
    return '$percent% ($completedChunks/$totalChunks chunks)';
  }

  String get sizeText {
    if (fileSize < 1024) return '$fileSize B';
    if (fileSize < 1024 * 1024) return '${(fileSize / 1024).toStringAsFixed(1)} KB';
    if (fileSize < 1024 * 1024 * 1024) return '${(fileSize / (1024 * 1024)).toStringAsFixed(1)} MB';
    return '${(fileSize / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }
}


/// Service for streaming file imports with progress tracking and resume support
class StreamingImportService {
  static const _channel = MethodChannel('com.noleak.vault');
  static const _progressChannel = EventChannel('com.noleak.vault/import_progress');
  
  static StreamingImportService? _instance;
  static StreamingImportService get instance => _instance ??= StreamingImportService._();
  
  StreamingImportService._();
  
  StreamSubscription? _progressSubscription;
  final _progressController = StreamController<ImportProgress>.broadcast();
  
  /// Stream of import progress updates
  Stream<ImportProgress> get progressStream => _progressController.stream;
  
  /// Initialize the service and listen for progress events
  void initialize() {
    _progressSubscription?.cancel();
    _progressSubscription = _progressChannel.receiveBroadcastStream().listen(
      (event) {
        if (event is Map) {
          _progressController.add(ImportProgress.fromMap(event));
        }
      },
      onError: (error) {
        // Handle error
      },
    );
  }
  
  /// Dispose the service
  void dispose() {
    _progressSubscription?.cancel();
    _progressController.close();
  }
  
  /// Import a file using streaming (for large files)
  /// Returns the file ID on success
  Future<Map<String, dynamic>?> importFileStreaming(String uri) async {
    try {
      final result = await _channel.invokeMethod('importFileStreaming', {'uri': uri});
      if (result is Map) {
        return Map<String, dynamic>.from(result);
      }
      return null;
    } on PlatformException catch (e) {
      throw ImportException(e.code, e.message ?? 'Import failed');
    }
  }
  
  /// Get list of pending imports that can be resumed
  Future<List<PendingImport>> listPendingImports() async {
    try {
      final result = await _channel.invokeMethod('listPendingImports');
      if (result is List) {
        return result.map((e) => PendingImport.fromMap(e as Map)).toList();
      }
      return [];
    } on PlatformException {
      return [];
    }
  }
  
  /// Abort a pending import
  Future<bool> abortImport(List<int> importId) async {
    try {
      final result = await _channel.invokeMethod('abortImport', {'importId': importId});
      return result == true;
    } on PlatformException {
      return false;
    }
  }
  
  /// Check if there are any pending imports
  Future<bool> hasPendingImports() async {
    final pending = await listPendingImports();
    return pending.isNotEmpty;
  }
}

/// Exception for import errors
class ImportException implements Exception {
  final String code;
  final String message;
  
  ImportException(this.code, this.message);
  
  @override
  String toString() => 'ImportException($code): $message';
  
  bool get isFileTooLarge => code == 'FILE_TOO_LARGE';
  bool get isUnsupportedType => code == 'UNSUPPORTED_TYPE';
  bool get isVaultNotOpen => code == 'VAULT_NOT_OPEN';
  bool get isDiskFull => code == 'DISK_FULL';
}
