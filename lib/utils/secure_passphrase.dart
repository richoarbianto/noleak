/// SecurePassphrase - Secure Password/Passphrase Handling Utilities
///
/// Provides utilities for minimizing immutable password copies and securely
/// clearing mutable password buffers.
///
/// SECURITY FEATURES:
/// - Reads the in-app secure keyboard's mutable byte buffer
/// - Converts system-keyboard strings to canonical UTF-8 bytes
/// - Zeroizes byte arrays after use
///
/// IMPORTANT: Always use these utilities when handling passwords:
/// ```dart
/// // Instead of controller.dispose():
/// SecurePassphrase.disposeController(controller);
///
/// // Instead of just clearing:
/// SecurePassphrase.clearController(controller);
/// ```

import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import '../widgets/secure_keyboard.dart';

/// Utilities for secure password handling.
///
/// SECURITY:
/// - Clears password from memory after use
/// - Prevents password lingering in heap
class SecurePassphrase {
  static const int maxBytes = 1024;

  /// Clears the mutable secure-keyboard buffer and drops controller text.
  /// Dart strings are immutable, so controller text cannot be overwritten.
  static void clearController(TextEditingController controller) {
    SecureKeyboard.clearInput(controller);
    controller.clear();
  }

  /// SECURITY: Convert string to bytes and clear the string
  /// Returns a Uint8List that should be zeroized after use
  static Uint8List toSecureBytes(String password) {
    final bytes = _utf8Bytes(password);
    if (bytes.length > maxBytes) {
      zeroize(bytes);
      throw ArgumentError('Passphrase exceeds $maxBytes UTF-8 bytes');
    }
    return bytes;
  }

  /// Extract password bytes without reconstructing a String when the secure
  /// keyboard is active.
  static Uint8List fromController(TextEditingController controller) {
    final bytes =
        SecureKeyboard.copyInput(controller) ?? _utf8Bytes(controller.text);
    if (bytes.length > maxBytes) {
      zeroize(bytes);
      throw ArgumentError('Passphrase exceeds $maxBytes UTF-8 bytes');
    }
    return bytes;
  }

  static int controllerLength(TextEditingController controller) =>
      SecureKeyboard.inputLength(controller) ?? controller.text.length;

  static int controllerByteLength(TextEditingController controller) {
    final secureLength = SecureKeyboard.inputLength(controller);
    if (secureLength != null) return secureLength;
    final bytes = _utf8Bytes(controller.text);
    try {
      return bytes.length;
    } finally {
      zeroize(bytes);
    }
  }

  static bool controllerWithinLimit(TextEditingController controller) =>
      controllerByteLength(controller) <= maxBytes;

  static bool controllerIsEmpty(TextEditingController controller) =>
      controllerLength(controller) == 0;

  static bool controllersMatch(
    TextEditingController first,
    TextEditingController second,
  ) {
    if (!controllerWithinLimit(first) || !controllerWithinLimit(second)) {
      return false;
    }
    final a = fromController(first);
    final b = fromController(second);
    try {
      var difference = a.length ^ b.length;
      final length = a.length < b.length ? a.length : b.length;
      for (var i = 0; i < length; i++) {
        difference |= a[i] ^ b[i];
      }
      return difference == 0;
    } finally {
      zeroize(a);
      zeroize(b);
    }
  }

  static bool controllerHasNumber(TextEditingController controller) =>
      _containsByte(controller, (byte) => byte >= 0x30 && byte <= 0x39);

  static bool controllerHasSymbol(TextEditingController controller) =>
      _containsByte(
        controller,
        (byte) => !((byte >= 0x30 && byte <= 0x39) ||
            (byte >= 0x41 && byte <= 0x5a) ||
            (byte >= 0x61 && byte <= 0x7a)),
      );

  static bool _containsByte(
    TextEditingController controller,
    bool Function(int) predicate,
  ) {
    final bytes = fromController(controller);
    try {
      return bytes.any(predicate);
    } finally {
      zeroize(bytes);
    }
  }

  static Uint8List _utf8Bytes(String value) {
    return utf8.encode(value);
  }

  /// SECURITY: Zeroize a Uint8List
  static void zeroize(Uint8List? data) {
    if (data == null || data.isEmpty) return;
    try {
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
