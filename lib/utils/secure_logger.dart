/// SecureLogger - Production-Safe Logging Utility
/// 
/// Provides logging functionality that is automatically stripped from
/// release builds. All log output is prefixed with [NoLeak] for easy
/// filtering in logcat.
/// 
/// SECURITY: Logs are only emitted in debug mode (kDebugMode).
/// In release builds, all logging calls become no-ops, preventing
/// any sensitive information from being logged in production.
/// 
/// Usage:
/// ```dart
/// SecureLogger.d('MyClass', 'Debug message');
/// SecureLogger.e('MyClass', 'Error occurred', error);
/// SecureLogger.security('Vault unlocked');
/// ```

import 'package:flutter/foundation.dart';

/// Production-safe logging utility.
/// 
/// Only logs in debug mode (kDebugMode).
/// All logs are stripped from release builds.
class SecureLogger {
  static const String _prefix = '[NoLeak]';
  
  /// Log debug message (only in debug mode)
  static void d(String tag, String message) {
    if (kDebugMode) {
      debugPrint('$_prefix[$tag] $message');
    }
  }
  
  /// Log info message (only in debug mode)
  static void i(String tag, String message) {
    if (kDebugMode) {
      debugPrint('$_prefix[$tag] ℹ️ $message');
    }
  }
  
  /// Log warning message (only in debug mode)
  static void w(String tag, String message) {
    if (kDebugMode) {
      debugPrint('$_prefix[$tag] ⚠️ $message');
    }
  }
  
  /// Log error message (only in debug mode)
  /// NEVER logs sensitive data like passwords or keys
  static void e(String tag, String message, [Object? error]) {
    if (kDebugMode) {
      debugPrint('$_prefix[$tag] ❌ $message');
      if (error != null) {
        debugPrint('$_prefix[$tag] Error: $error');
      }
    }
  }
  
  /// Log security-related event (only in debug mode)
  /// Use for audit trails in debug builds
  static void security(String event) {
    if (kDebugMode) {
      debugPrint('$_prefix[SECURITY] 🔐 $event');
    }
  }
}
