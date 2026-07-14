import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// AppSettings - Application-Wide Settings Manager
/// 
/// Manages persistent user preferences with secure defaults:
/// - App lock (biometric on app launch) - default: disabled
/// - Secure keyboard (anti-keylogger) - default: enabled
/// - Idle timeout (auto-lock delay) - default: 30 seconds
/// - Session limit (max unlock duration) - default: 5 minutes
/// 
/// Settings are persisted using SharedPreferences and loaded
/// on app startup. The manager implements [ChangeNotifier] to
/// allow UI components to react to setting changes.
class AppSettings extends ChangeNotifier {
  static const String _keyAppLockEnabled = 'app_lock_biometric_enabled';
  static const String _keyIdleTimeoutSeconds = 'idle_timeout_seconds';
  static const String _keySessionLimitMinutes = 'session_limit_minutes';
  static const String _keySecureKeyboardEnabled = 'secure_keyboard_enabled';

  static const List<int> idleTimeoutOptions = [10, 15, 20, 30];
  static const List<int> sessionLimitOptions = [3, 5, 10];
  
  static AppSettings? _instance;
  static AppSettings get instance => _instance ??= AppSettings._();
  
  AppSettings._();
  
  bool _appLockEnabled = false; // Default: disabled (no biometric on app launch)
  int _idleTimeoutSeconds = 30;
  int _sessionLimitMinutes = 5;
  bool _secureKeyboardEnabled = true; // Default: enabled for security
  bool _initialized = false;
  
  /// Whether biometric is required when opening the app (optional setting)
  /// Note: Biometric for vault unlock is ALWAYS required - this only controls app launch
  bool get appLockEnabled => _appLockEnabled;
  int get idleTimeoutSeconds => _idleTimeoutSeconds;
  int get sessionLimitMinutes => _sessionLimitMinutes;
  bool get secureKeyboardEnabled => _secureKeyboardEnabled;
  bool get initialized => _initialized;
  
  /// Initialize settings from storage
  Future<void> init() async {
    if (_initialized) return;
    
    try {
      final prefs = await SharedPreferences.getInstance();
      _appLockEnabled = prefs.getBool(_keyAppLockEnabled) ?? false;
      _idleTimeoutSeconds = prefs.getInt(_keyIdleTimeoutSeconds) ?? _idleTimeoutSeconds;
      if (!idleTimeoutOptions.contains(_idleTimeoutSeconds)) {
        _idleTimeoutSeconds = idleTimeoutOptions.last;
      }
      _sessionLimitMinutes = prefs.getInt(_keySessionLimitMinutes) ?? _sessionLimitMinutes;
      if (!sessionLimitOptions.contains(_sessionLimitMinutes)) {
        _sessionLimitMinutes = sessionLimitOptions[1];
      }
      _secureKeyboardEnabled = prefs.getBool(_keySecureKeyboardEnabled) ?? true;
      _initialized = true;
      notifyListeners();
    } catch (e) {
      // Default to disabled if storage fails
      _appLockEnabled = false;
      _secureKeyboardEnabled = true;
      _initialized = true;
    }
  }
  
  /// Set app lock biometric enabled/disabled
  Future<void> setAppLockEnabled(bool enabled) async {
    if (_appLockEnabled == enabled) return;
    
    _appLockEnabled = enabled;
    notifyListeners();
    
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setBool(_keyAppLockEnabled, enabled);
    } catch (e) {
      // Ignore storage errors, setting is already applied in memory
    }
  }

  Future<void> setIdleTimeoutSeconds(int value) async {
    if (!idleTimeoutOptions.contains(value) || _idleTimeoutSeconds == value) return;
    _idleTimeoutSeconds = value;
    notifyListeners();
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setInt(_keyIdleTimeoutSeconds, value);
    } catch (e) {
      // Ignore storage errors, setting is already applied in memory
    }
  }

  Future<void> setSessionLimitMinutes(int value) async {
    if (!sessionLimitOptions.contains(value) || _sessionLimitMinutes == value) return;
    _sessionLimitMinutes = value;
    notifyListeners();
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setInt(_keySessionLimitMinutes, value);
    } catch (e) {
      // Ignore storage errors, setting is already applied in memory
    }
  }

  /// Set secure keyboard enabled/disabled
  Future<void> setSecureKeyboardEnabled(bool enabled) async {
    if (_secureKeyboardEnabled == enabled) return;
    
    _secureKeyboardEnabled = enabled;
    notifyListeners();
    
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setBool(_keySecureKeyboardEnabled, enabled);
    } catch (e) {
      // Ignore storage errors, setting is already applied in memory
    }
  }
}
