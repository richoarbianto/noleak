/// NoLeak Vault - Main Application Entry Point
/// 
/// A military-grade encrypted vault application that provides:
/// - Zero-knowledge encryption (your password never leaves the device)
/// - Offline-first architecture (no cloud, no servers)
/// - Multi-vault support (up to 25 independent vaults)
/// - Biometric authentication
/// - Secure media playback without temp files
/// 
/// Repository: https://github.com/richoarbianto/noleak
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'models/vault_state.dart';
import 'services/vault_state_manager.dart';
import 'services/vault_registry.dart';
import 'services/vault_channel.dart';
import 'widgets/secure_keyboard.dart';
import 'services/app_settings.dart';
import 'screens/blocked_screen.dart';
import 'screens/app_lock_screen.dart';
import 'screens/vault_dashboard_screen.dart';
import 'screens/unlock_vault_screen.dart';
import 'screens/vault_home_screen.dart';
import 'screens/text_viewer_screen.dart';
import 'screens/image_viewer_screen.dart';
import 'screens/video_player_screen.dart';
import 'screens/document_viewer_screen.dart';
import 'screens/audio_player_screen.dart';
import 'theme/cyberpunk_theme.dart';
import 'widgets/cyber_text_field.dart';
import 'widgets/cyber_button.dart';
import 'utils/secure_logger.dart';
import 'utils/secure_passphrase.dart';

/// Application entry point.
/// 
/// Initializes app settings, locks orientation to portrait,
/// and sets up the system UI overlay style for the cyberpunk theme.
void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  // Initialize app settings
  await AppSettings.instance.init();
  
  // Lock orientation to portrait
  SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
    DeviceOrientation.portraitDown,
  ]);
  
  // Set system UI overlay style for cyberpunk theme
  SystemChrome.setSystemUIOverlayStyle(const SystemUiOverlayStyle(
    statusBarColor: Colors.transparent,
    statusBarIconBrightness: Brightness.light,
    systemNavigationBarColor: CyberpunkTheme.background,
    systemNavigationBarIconBrightness: Brightness.light,
  ));
  
  runApp(const NoLeakApp());
}

class NoLeakApp extends StatefulWidget {
  const NoLeakApp({super.key});

  @override
  State<NoLeakApp> createState() => _NoLeakAppState();
}

class _NoLeakAppState extends State<NoLeakApp> with WidgetsBindingObserver {
  final VaultStateManager _stateManager = VaultStateManager();
  final VaultRegistry _registry = VaultRegistry();
  bool _initialized = false;
  bool _isBlocked = false;
  bool _appLockRequired = false;
  String? _selectedVaultId;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _initialize();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _stateManager.dispose();
    _registry.dispose();
    super.dispose();
  }

  Future<void> _initialize() async {
    // Check environment first
    final isSecure = await VaultChannel.checkEnvironment();
    if (!isSecure) {
      setState(() {
        _isBlocked = true;
        _initialized = true;
      });
      return;
    }

    // Check app lock biometric if enabled
    if (AppSettings.instance.appLockEnabled) {
      SecureLogger.d('NoLeakApp', 'App lock enabled, requesting biometric');
      final biometricSuccess = await VaultChannel.authenticateBiometric();
      if (!biometricSuccess) {
        SecureLogger.d('NoLeakApp', 'App lock biometric failed, showing retry');
        setState(() {
          _initialized = true;
          _appLockRequired = true;
        });
        return;
      }
    }

    // Load vault registry
    await _registry.load();
    
    setState(() => _initialized = true);
  }

  Future<bool> _retryAppLock() async {
    SecureLogger.d('NoLeakApp', 'Retrying app lock biometric');
    final ok = await VaultChannel.authenticateBiometric();
    if (!ok) {
      SecureLogger.d('NoLeakApp', 'App lock biometric failed');
      return false;
    }

    if (mounted) {
      setState(() {
        _appLockRequired = false;
        _initialized = false;
      });
    }
    await _registry.load();
    if (mounted) {
      setState(() => _initialized = true);
    }
    return true;
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    SecureLogger.d('NoLeakApp', 'Lifecycle state changed: $state');
    
    // SECURITY: Lock vault when app goes to background
    // Native layer (MainActivity) handles smart detection for file picker
    switch (state) {
      case AppLifecycleState.paused:
      case AppLifecycleState.hidden:
      case AppLifecycleState.detached:
        SecureLogger.d('NoLeakApp', 'App backgrounded ($state) - triggering lock');
        _stateManager.onAppLifecycleChange(true);
        if (_stateManager.state != VaultState.unlocked) {
          setState(() => _selectedVaultId = null);
        }
        break;
      case AppLifecycleState.inactive:
        // Don't lock on inactive (brief transition state)
        _stateManager.onAppLifecycleChange(false);
        break;
      case AppLifecycleState.resumed:
        _stateManager.onAppLifecycleChange(false);
        break;
    }
  }

  void _onUnlockVault(String vaultId) {
    setState(() => _selectedVaultId = vaultId);
  }

  void _onBackToDashboard() {
    setState(() => _selectedVaultId = null);
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'NoLeak',
      debugShowCheckedModeBanner: false,
      theme: CyberpunkTheme.themeData,
      home: _buildHome(),
      onGenerateRoute: _onGenerateRoute,
      builder: (context, child) {
        // Wrap all routes with SecureKeyboardHost for consistent keyboard support
        return SecureKeyboardHost(child: child ?? const SizedBox.shrink());
      },
    );
  }

  Widget _buildHome() {
    if (_appLockRequired) {
      return AppLockScreen(onRetry: _retryAppLock);
    }

    if (!_initialized) {
      return Scaffold(
        backgroundColor: CyberpunkTheme.background,
        body: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              // Glowing logo
              Container(
                padding: const EdgeInsets.all(24),
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  boxShadow: [
                    BoxShadow(
                      color: CyberpunkTheme.neonGreen.withOpacity(0.3),
                      blurRadius: 30,
                      spreadRadius: 5,
                    ),
                  ],
                ),
                child: const Icon(
                  Icons.shield_outlined,
                  size: 64,
                  color: CyberpunkTheme.neonGreen,
                ),
              ),
              const SizedBox(height: 24),
              const SizedBox(
                width: 32,
                height: 32,
                child: CircularProgressIndicator(
                  strokeWidth: 2,
                  valueColor: AlwaysStoppedAnimation<Color>(
                    CyberpunkTheme.neonGreen,
                  ),
                ),
              ),
            ],
          ),
        ),
      );
    }

    if (_isBlocked) {
      return const BlockedScreen();
    }

    if (_selectedVaultId != null) {
      SecureLogger.d('NoLeakApp', 'Building with selectedVaultId: $_selectedVaultId');
      return ListenableBuilder(
        listenable: _stateManager,
        builder: (context, _) {
          SecureLogger.d('NoLeakApp', 'ListenableBuilder rebuild, state: ${_stateManager.state}');
          switch (_stateManager.state) {
            case VaultState.blocked:
              SecureLogger.d('NoLeakApp', 'Showing BlockedScreen');
              return const BlockedScreen();
            case VaultState.unlocked:
              SecureLogger.d('NoLeakApp', 'Showing VaultHomeScreen');
              return VaultHomeScreen(
                stateManager: _stateManager,
                onLogout: () {
                  _stateManager.lockVault();
                  _onBackToDashboard();
                },
              );
            default:
              SecureLogger.d('NoLeakApp', 'Showing UnlockVaultScreenMulti');
              return UnlockVaultScreenMulti(
                stateManager: _stateManager,
                vaultId: _selectedVaultId!,
                onBack: _onBackToDashboard,
              );
          }
        },
      );
    }

    return VaultDashboardScreen(
      registry: _registry,
      onUnlockVault: _onUnlockVault,
    );
  }

  Route<dynamic>? _onGenerateRoute(RouteSettings settings) {
    switch (settings.name) {
      case '/text-viewer':
        final entry = settings.arguments as VaultEntry;
        return MaterialPageRoute(
          builder: (_) => TextViewerScreen(entry: entry),
        );
      case '/image-viewer':
        final entry = settings.arguments as VaultEntry;
        return MaterialPageRoute(
          builder: (_) => ImageViewerScreen(entry: entry),
        );
      case '/video-player':
        final entry = settings.arguments as VaultEntry;
        return MaterialPageRoute(
          builder: (_) => VideoPlayerScreen(
            entry: entry,
            onActivity: _stateManager.recordActivity,
          ),
        );
      case '/document-viewer':
        final entry = settings.arguments as VaultEntry;
        return MaterialPageRoute(
          builder: (_) => DocumentViewerScreen(entry: entry),
        );
      case '/audio-player':
        final entry = settings.arguments as VaultEntry;
        return MaterialPageRoute(
          builder: (_) => AudioPlayerScreen(
            entry: entry,
            onActivity: _stateManager.recordActivity,
          ),
        );
      default:
        return null;
    }
  }
}

/// UnlockVaultScreenMulti - Multi-vault version with cyberpunk theme
class UnlockVaultScreenMulti extends StatefulWidget {
  final VaultStateManager stateManager;
  final String vaultId;
  final VoidCallback onBack;

  const UnlockVaultScreenMulti({
    super.key,
    required this.stateManager,
    required this.vaultId,
    required this.onBack,
  });

  @override
  State<UnlockVaultScreenMulti> createState() => _UnlockVaultScreenMultiState();
}

class _UnlockVaultScreenMultiState extends State<UnlockVaultScreenMulti> {
  final _passphraseController = TextEditingController();
  final GlobalKey _buttonKey = GlobalKey();
  bool _obscurePassphrase = true;
  bool _isLoading = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    SecureKeyboard.inset.addListener(_onKeyboardInsetChanged);
  }

  @override
  void dispose() {
    SecureKeyboard.inset.removeListener(_onKeyboardInsetChanged);
    SecurePassphrase.disposeController(_passphraseController);
    super.dispose();
  }

  void _onKeyboardInsetChanged() {
    if (SecureKeyboard.inset.value > 0) {
      // Delay to ensure keyboard animation and layout update are complete
      Future.delayed(const Duration(milliseconds: 300), () {
        if (mounted && _buttonKey.currentContext != null) {
          Scrollable.ensureVisible(
            _buttonKey.currentContext!,
            duration: const Duration(milliseconds: 300),
            curve: Curves.easeOut,
            alignment: 1.0,
          );
        }
      });
    }
  }

  Future<void> _unlock() async {
    if (_passphraseController.text.isEmpty) return;

    // Hide secure keyboard before starting unlock
    SecureKeyboard.hide();

    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      SecureLogger.d('UnlockVault', 'Opening vault ${widget.vaultId}');
      
      await VaultChannel.openVaultById(
        vaultId: widget.vaultId,
        password: _passphraseController.text,
      );
      SecureLogger.d('UnlockVault', 'Vault opened successfully');
      
      SecurePassphrase.clearController(_passphraseController);
      
      // Biometric is ALWAYS required for vault unlock
      SecureLogger.d('UnlockVault', 'Requesting biometric auth');
      final biometricSuccess = await VaultChannel.authenticateBiometric();
      SecureLogger.d('UnlockVault', 'Biometric result: $biometricSuccess');
      
      if (!biometricSuccess) {
        await VaultChannel.closeVault();
        throw Exception('Biometric authentication required');
      }
      
      SecureLogger.d('UnlockVault', 'Calling unlockVaultById...');
      await widget.stateManager.unlockVaultById(widget.vaultId);
      SecureLogger.d('UnlockVault', 'State is now: ${widget.stateManager.state}');
      
    } catch (e) {
      SecureLogger.e('UnlockVault', 'Unlock failed', e);
      SecurePassphrase.clearController(_passphraseController);
      setState(() {
        if (e is PlatformException) {
          _error = e.message ?? 'Unlock failed';
        } else {
          _error = e.toString().replaceFirst('Exception: ', '');
        }
      });
    } finally {
      if (mounted) {
        setState(() {
          _isLoading = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, _) {
        if (!didPop) {
          widget.onBack();
        }
      },
      child: Scaffold(
        backgroundColor: CyberpunkTheme.background,
        appBar: AppBar(
          backgroundColor: Colors.transparent,
          elevation: 0,
          leading: IconButton(
            icon: const Icon(Icons.arrow_back, color: CyberpunkTheme.neonGreen),
            onPressed: widget.onBack,
          ),
          title: const Text(
            'UNLOCK VAULT',
            style: TextStyle(
              color: CyberpunkTheme.textPrimary,
              letterSpacing: 2,
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
        body: SafeArea(
        child: ValueListenableBuilder<double>(
          valueListenable: SecureKeyboard.inset,
          builder: (context, keyboardInset, _) {
            return SingleChildScrollView(
              padding: EdgeInsets.fromLTRB(24, 24, 24, 24 + keyboardInset),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
              const SizedBox(height: 32),
              // Glowing lock icon
              Container(
                padding: const EdgeInsets.all(24),
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  boxShadow: [
                    BoxShadow(
                      color: CyberpunkTheme.neonGreen.withOpacity(0.3),
                      blurRadius: 40,
                      spreadRadius: 10,
                    ),
                  ],
                ),
                child: const Icon(
                  Icons.lock_outline,
                  size: 80,
                  color: CyberpunkTheme.neonGreen,
                ),
              ),
              const SizedBox(height: 32),
              const Text(
                'Enter Passphrase',
                style: TextStyle(
                  fontSize: 28,
                  fontWeight: FontWeight.bold,
                  color: CyberpunkTheme.textPrimary,
                  letterSpacing: 1,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 8),
              const Text(
                'Enter your passphrase to access your files',
                style: TextStyle(
                  fontSize: 14,
                  color: CyberpunkTheme.textSecondary,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 48),

              // Passphrase field
              CyberTextField(
                controller: _passphraseController,
                obscureText: _obscurePassphrase,
                enabled: !_isLoading,
                labelText: 'Passphrase',
                onSubmitted: (_) => _unlock(),
                suffixIcon: IconButton(
                  icon: Icon(
                    _obscurePassphrase ? Icons.visibility : Icons.visibility_off,
                    color: CyberpunkTheme.textSecondary,
                  ),
                  onPressed: () {
                    setState(() {
                      _obscurePassphrase = !_obscurePassphrase;
                    });
                  },
                ),
              ),
              const SizedBox(height: 16),

              // Error message
              if (_error != null)
                Container(
                  padding: const EdgeInsets.all(12),
                  margin: const EdgeInsets.only(bottom: 16),
                  decoration: BoxDecoration(
                    color: CyberpunkTheme.error.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: CyberpunkTheme.error.withOpacity(0.3),
                    ),
                  ),
                  child: Row(
                    children: [
                      const Icon(
                        Icons.error_outline,
                        color: CyberpunkTheme.error,
                        size: 20,
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          _error!,
                          style: const TextStyle(color: CyberpunkTheme.error),
                        ),
                      ),
                    ],
                  ),
                ),

              // Unlock button
              CyberButton(
                key: _buttonKey,
                text: 'UNLOCK',
                onPressed: !_isLoading ? _unlock : null,
                isLoading: _isLoading,
                icon: Icons.lock_open,
              ),

              const SizedBox(height: 32),

              // Biometric info - always required for vault unlock
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    Icons.fingerprint,
                    color: CyberpunkTheme.neonGreen.withOpacity(0.6),
                    size: 20,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    'Biometric verification required after passphrase',
                    style: TextStyle(
                      color: CyberpunkTheme.textHint,
                      fontSize: 12,
                    ),
                  ),
                ],
              ),
            ],
          ),
        );
        },
      ),
      ),
      ),
    );
  }
}
