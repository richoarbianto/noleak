/// TransferProgressService - Vault Import/Export Progress Tracking
/// 
/// Tracks progress for vault-level operations like importing or
/// exporting entire vault containers. Uses EventChannel to receive
/// progress updates from native code.
/// 
/// Progress events include:
/// - Operation type (import_vault, export_vault)
/// - Bytes processed and total bytes
/// - Completion percentage
/// - Error information if operation fails

import 'dart:async';
import 'package:flutter/services.dart';

/// Progress data for vault transfer operations.
/// 
/// Used for tracking import/export of entire vault containers,
/// which can be large operations requiring progress indication.
class TransferProgress {
  final String operation;
  final int bytesProcessed;
  final int totalBytes;
  final double percent;
  final bool isComplete;
  final String? error;

  TransferProgress({
    required this.operation,
    required this.bytesProcessed,
    required this.totalBytes,
    required this.percent,
    required this.isComplete,
    this.error,
  });

  factory TransferProgress.fromMap(Map<dynamic, dynamic> map) {
    return TransferProgress(
      operation: map['operation'] as String? ?? '',
      bytesProcessed: (map['bytesProcessed'] as num?)?.toInt() ?? 0,
      totalBytes: (map['totalBytes'] as num?)?.toInt() ?? 0,
      percent: (map['percent'] as num?)?.toDouble() ?? 0.0,
      isComplete: map['isComplete'] as bool? ?? false,
      error: map['error'] as String?,
    );
  }

  double get normalized => (percent / 100).clamp(0.0, 1.0);
}

class TransferProgressService {
  static const _progressChannel = EventChannel('com.noleak.vault/transfer_progress');

  static TransferProgressService? _instance;
  static TransferProgressService get instance => _instance ??= TransferProgressService._();

  TransferProgressService._();

  StreamSubscription? _subscription;
  final _progressController = StreamController<TransferProgress>.broadcast();

  Stream<TransferProgress> get progressStream => _progressController.stream;

  void initialize() {
    _subscription?.cancel();
    _subscription = _progressChannel.receiveBroadcastStream().listen(
      (event) {
        if (event is Map) {
          _progressController.add(TransferProgress.fromMap(event));
        }
      },
      onError: (_) {},
    );
  }

  void dispose() {
    _subscription?.cancel();
  }
}
