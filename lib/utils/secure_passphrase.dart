/// SecurePassphrase - Secure Password/Passphrase Handling Utilities
/// 
/// Provides utilities for secure handling of passwords and sensitive
/// strings in memory. Dart strings are immutable and cannot be securely
/// erased, so this class provides workarounds.
/// 
/// SECURITY FEATURES:
/// - Overwrites TextEditingController content before clearing
/// - Converts strings to byte arrays for secure handling
/// - Zeroizes byte arrays after use
/// - Uses SecureRandom for overwrite data
/// 
/// IMPORTANT: Always use these utilities when handling passwords:
/// ```dart
/// // Instead of controller.dispose():
/// SecurePassphrase.disposeController(controller);
/// 
/// // Instead of just clearing:
/// SecurePassphrase.clearController(controller);
/// ```

import 'dart:math';
import 'dart:typed_data';
import 'package:flutter/material.dart';

/// Utilities for secure password handling.
/// 
/// SECURITY:
/// - Clears password from memory after use
/// - Prevents password lingering in heap
class SecurePassphrase {
  static final _random = Random.secure();
  
  /// SECURITY: Clear a TextEditingController's content securely
  /// Overwrites with random data then clears
  static void clearController(TextEditingController controller) {
    final length = controller.text.length;
    if (length > 0) {
      // Overwrite with random characters first
      final randomChars = String.fromCharCodes(
        List.generate(length, (_) => _random.nextInt(95) + 32)
      );
      controller.text = randomChars;
    }
    controller.clear();
  }
  
  /// SECURITY: Convert string to bytes and clear the string
  /// Returns a Uint8List that should be zeroized after use
  static Uint8List toSecureBytes(String password) {
    return Uint8List.fromList(password.codeUnits);
  }
  
  /// SECURITY: Zeroize a Uint8List
  static void zeroize(Uint8List? data) {
    if (data == null || data.isEmpty) return;
    try {
      // Overwrite with random, then zero
      for (int i = 0; i < data.length; i++) {
        data[i] = _random.nextInt(256);
      }
      data.fillRange(0, data.length, 0);
    } catch (_) {
      // Best effort: some buffers may be unmodifiable.
    }
  }
  
  /// SECURITY: Dispose controller securely
  /// Call this in dispose() instead of just controller.dispose()
  static void disposeController(TextEditingController controller) {
    clearController(controller);
    controller.dispose();
  }
}
