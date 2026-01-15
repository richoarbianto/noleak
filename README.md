# NoLeak Vault

<p align="center">
  <img src="assets/images/logo.png" alt="NoLeak Logo" width="120" height="120">
</p>

<p align="center">
  <strong>Take Back Control of Your Privacy</strong>
</p>

<p align="center">
  A military-grade encrypted vault for Android that keeps your sensitive files completely offline and secure.
</p>

<p align="center">
  <a href="#download">Download</a> •
  <a href="#features">Features</a> •
  <a href="#security">Security</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#building-from-source">Build</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## Download

### 📱 Pre-built APK (Recommended)

Download the latest release APK directly - no compilation needed:

<p align="center">
  <a href="https://github.com/richoarbianto/noleak/releases/latest">
    <img src="https://img.shields.io/badge/Download-APK-brightgreen?style=for-the-badge&logo=android" alt="Download APK">
  </a>
</p>

| Version | Download | Size | Min Android |
|:-------:|:--------:|:----:|:-----------:|
| v1.0.0 | [📥 app-release.apk](https://github.com/richoarbianto/noleak/releases/download/v1.0.0/app-release.apk) | ~25 MB | Android 7.0+ |

> ⚠️ **Note**: Since this APK is not from Play Store, you'll need to enable "Install from unknown sources" in your Android settings.

### Installation Steps

1. Download the APK from the link above
2. Open the downloaded file on your Android device
3. If prompted, allow installation from unknown sources
4. Tap "Install"
5. Open NoLeak and create your first vault!

---

## Overview

NoLeak is a zero-knowledge, offline-first encrypted vault application built with Flutter and native Android (Kotlin/C). It provides military-grade encryption for your most sensitive files without ever connecting to the internet or relying on third-party services.

**No cloud. No servers. No compromises.**

## Features

### 🔐 Military-Grade Encryption
- **XChaCha20-Poly1305** authenticated encryption (256-bit)
- **Argon2id** key derivation with adaptive memory cost (32-256 MB)
- Per-file encryption keys with secure key hierarchy
- Quantum-resistant symmetric cryptography

### 🛡️ Multi-Layer Security
- Root/jailbreak detection
- Emulator and debugger detection
- App tampering verification
- Screenshot and screen recording prevention (FLAG_SECURE)
- Biometric authentication (fingerprint/face)
- Progressive brute-force lockout

### 📁 File Management
- Import files and folders with encryption
- Organize files in virtual folders
- Support for images, videos, audio, documents, and text files
- Secure in-memory media playback (no temp files)
- Export/import encrypted vault containers

### 🎨 Modern UI
- Cyberpunk-themed dark interface
- Secure on-screen keyboard (anti-keylogger)
- Password strength meter with crack-time estimation
- Smooth animations and intuitive navigation

### 🔄 Multi-Vault Support
- Create up to 25 independent vaults
- Each vault has its own password
- Encrypted vault titles for privacy
- Easy vault export/import for backup

## Security

### Cryptographic Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Your Passphrase                          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ Argon2id + salt
┌─────────────────────────────────────────────────────────────┐
│                KEK (Key Encryption Key)                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ XChaCha20-Poly1305 wrap
┌─────────────────────────────────────────────────────────────┐
│                MK (Master Key)                              │
│            Stored encrypted in vault header                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ XChaCha20-Poly1305 wrap
┌─────────────────────────────────────────────────────────────┐
│                DEK (Data Encryption Key)                    │
│            Per-file, stored in encrypted index              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ XChaCha20-Poly1305 encrypt
┌─────────────────────────────────────────────────────────────┐
│                   Encrypted Data                            │
│                    (64KB chunks)                            │
└─────────────────────────────────────────────────────────────┘
```

### Security Features

| Feature | Implementation |
|:--------|:---------------|
| Encryption | XChaCha20-Poly1305 (256-bit) |
| Key Derivation | Argon2id (memory-hard) |
| Integrity | SHA-256 container hash |
| Random Generation | libsodium CSPRNG |
| Memory Protection | mlock() + secure wipe |
| Brute-Force Protection | Progressive lockout (30s → 1hr) |
| Environment Security | Root/emulator/debugger detection |

### What We Protect Against

- ✅ Brute-force attacks (Argon2id + rate limiting)
- ✅ Memory dump attacks (mlock + secure wipe)
- ✅ Keylogger attacks (secure on-screen keyboard)
- ✅ Screenshot/recording (FLAG_SECURE)
- ✅ Rooted device exploitation (root detection)
- ✅ Debugging/instrumentation (debugger detection)
- ✅ App tampering (signature verification)
- ✅ Timing attacks (constant-time comparison)

## Architecture

### Project Structure

```
noleak/
├── lib/                          # Flutter/Dart code
│   ├── main.dart                 # App entry point
│   ├── models/                   # Data models
│   │   ├── vault_info.dart       # Vault metadata
│   │   └── vault_state.dart      # Vault state & file entries
│   ├── screens/                  # UI screens
│   │   ├── vault_dashboard_screen.dart  # Multi-vault dashboard
│   │   ├── vault_home_screen.dart       # File browser
│   │   ├── create_vault_screen.dart     # Vault creation
│   │   ├── unlock_vault_screen.dart     # Vault unlock
│   │   ├── video_player_screen.dart     # Secure video player
│   │   ├── audio_player_screen.dart     # Secure audio player
│   │   ├── image_viewer_screen.dart     # Secure image viewer
│   │   ├── document_viewer_screen.dart  # PDF/Office viewer
│   │   └── text_viewer_screen.dart      # Text file viewer
│   ├── services/                 # Business logic
│   │   ├── vault_channel.dart    # Flutter ↔ Native bridge
│   │   ├── vault_registry.dart   # Multi-vault management
│   │   ├── vault_state_manager.dart  # State & session management
│   │   └── app_settings.dart     # User preferences
│   ├── widgets/                  # Reusable UI components
│   │   ├── secure_keyboard.dart  # Anti-keylogger keyboard
│   │   ├── password_strength_meter.dart  # Password analyzer
│   │   └── cyber_*.dart          # Themed UI components
│   ├── theme/                    # App theming
│   │   └── cyberpunk_theme.dart  # Dark neon theme
│   └── utils/                    # Utilities
│       ├── secure_logger.dart    # Debug-only logging
│       └── secure_passphrase.dart  # Secure string handling
│
├── android/app/src/main/
│   ├── kotlin/com/noleak/noleak/  # Kotlin code
│   │   ├── MainActivity.kt       # Android entry point
│   │   ├── VaultPlugin.kt        # MethodChannel handler
│   │   ├── vault/                # Vault operations
│   │   │   ├── VaultEngine.kt    # JNI bridge to C
│   │   │   ├── VaultBridge.kt    # High-level vault API
│   │   │   └── VaultRegistry.kt  # Multi-vault registry
│   │   ├── security/             # Security modules
│   │   │   ├── SecurityManager.kt    # Security enforcement
│   │   │   ├── RootGate.kt          # Root detection
│   │   │   ├── SecureKeyManager.kt  # Biometric keys
│   │   │   └── PasswordRateLimiter.kt  # Brute-force protection
│   │   ├── video/                # Secure video playback
│   │   └── audio/                # Secure audio playback
│   │
│   └── cpp/                      # Native C code (libsodium)
│       ├── vault_engine.c        # Core vault operations
│       ├── vault_crypto.c        # Cryptographic primitives
│       ├── vault_container.c     # Container format handling
│       ├── vault_index.c         # Encrypted file index
│       ├── vault_streaming.c     # Streaming encryption
│       └── vault_jni.c           # JNI bindings
```

### Technology Stack

| Layer | Technology |
|:------|:-----------|
| UI Framework | Flutter 3.x |
| UI Language | Dart |
| Native Bridge | Kotlin + MethodChannel |
| Cryptography | libsodium (C) |
| Key Storage | Android Keystore |
| Biometrics | AndroidX Biometric |
| Media Playback | ExoPlayer |

## Building from Source

> 💡 **Most users should just [download the APK](#download)**. Build from source only if you want to modify the code or verify the build yourself.

### Prerequisites

- Flutter SDK 3.0+
- Android Studio / VS Code
- Android NDK (for native compilation)
- JDK 17+

### Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/richoarbianto/noleak.git
   cd noleak
   ```

2. **Install dependencies**
   ```bash
   flutter pub get
   ```

3. **Build libsodium** (first time only)
   ```bash
   cd android/app/src/main/cpp
   ./build_libsodium.sh
   cd ../../../../..
   ```

4. **Run the app**
   ```bash
   flutter run
   ```

### Building Release APK

```bash
flutter build apk --release
```

The APK will be at `build/app/outputs/flutter-apk/app-release.apk`

## Contributing

We welcome contributions! Please read our guidelines before submitting.

### Development Guidelines

1. **Security First**: All changes must maintain or improve security
2. **No Network**: The app must remain fully offline
3. **Memory Safety**: Always zeroize sensitive data after use
4. **Code Review**: All PRs require security review

### Code Style

- Dart: Follow [Effective Dart](https://dart.dev/guides/language/effective-dart)
- Kotlin: Follow [Kotlin Coding Conventions](https://kotlinlang.org/docs/coding-conventions.html)
- C: Use consistent formatting, document all functions

### Testing

```bash
# Run Flutter tests
flutter test

# Run integration tests
flutter test integration_test/
```

## License

This project is open source. See [LICENSE](LICENSE) for details.

## Acknowledgments

- [libsodium](https://libsodium.org/) - Cryptographic library
- [Flutter](https://flutter.dev/) - UI framework
- [ExoPlayer](https://exoplayer.dev/) - Media playback

---

<p align="center">
  <strong>Your secrets stay yours.</strong>
</p>
