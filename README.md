# NoLeak Vault

<p align="center">
  <img src="assets/images/logo.png" alt="NoLeak logo" width="120" height="120">
</p>

<p align="center">
  <strong>Offline encrypted vault for Android</strong>
</p>

<p align="center">
  NoLeak stores files in a local encrypted container. It is built with Flutter, Kotlin, native C, and libsodium.
</p>

<p align="center">
  <img src="assets/gifs/noleak.gif" alt="NoLeak app preview" width="320">
</p>

<p align="center">
  <a href="https://github.com/richoarbianto/noleak/releases/latest">Download latest APK</a>
  ·
  <a href="#features">Features</a>
  ·
  <a href="#security-model">Security model</a>
  ·
  <a href="#build-from-source">Build</a>
</p>

---

## Status

NoLeak is an Android-only encrypted vault project under active development. The current app version is `1.0.0`.

Use the latest GitHub release for packaged APK builds:

[https://github.com/richoarbianto/noleak/releases/latest](https://github.com/richoarbianto/noleak/releases/latest)

NoLeak does not provide cloud sync, server-side recovery, or passphrase reset. If a vault passphrase is lost, the vault content cannot be recovered by the app.

## Features

- Multiple independent vaults.
- File import through Android Storage Access Framework.
- Folder organization inside the vault.
- Encrypted vault export and import for backup/restore workflows.
- In-app viewers for images, text, PDF, Office documents, audio, and video.
- PDF preview rendered through Android native PDF rendering without writing plaintext PDF files to app cache.
- Streaming import path for large files.
- Secure on-screen keyboard for passphrase input.
- Configurable app lock and vault auto-lock behavior.

## Supported file types

| Category | Formats |
| --- | --- |
| Images | JPEG, PNG, GIF, WebP |
| Video | MP4, MKV, WebM and other device-supported media formats |
| Audio | MP3, M4A, AAC, WAV, OGG/OPUS, FLAC |
| Documents | PDF, DOCX, XLSX, PPTX |
| Text | Plain text and common key/text formats |

Actual playback support also depends on Android device codec support.

## Security model

NoLeak is designed to protect vault contents while the vault is locked and the encrypted container remains intact. The app focuses on local-only storage and defense-in-depth on Android.

Implemented protections include:

- no Android internet permission in the application manifest;
- XChaCha20-Poly1305 authenticated encryption through libsodium;
- Argon2id passphrase-based key derivation;
- per-file data encryption keys wrapped by a vault master key;
- Android Keystore integration for biometric-gated unlock flows;
- progressive password rate limiting;
- auto-lock on background/lifecycle events;
- Android `FLAG_SECURE` to reduce screen capture exposure;
- root, debugger, emulator, ADB, install-source, and signature checks before vault operations;
- debug-only logging wrappers intended to avoid sensitive logs in release builds.

Runtime environment checks are a defense-in-depth layer. They are not a replacement for strong cryptography, safe passphrases, or secure device handling.

## Cryptography overview

```text
Passphrase
  └─ Argon2id + random salt → KEK
       └─ unwrap encrypted master key
            └─ unwrap per-file DEK
                 └─ decrypt encrypted file chunks
```

| Area | Implementation |
| --- | --- |
| Content encryption | XChaCha20-Poly1305 |
| Key derivation | Argon2id |
| Randomness | libsodium CSPRNG |
| Registry metadata | Android Keystore-backed encryption |
| Biometrics | AndroidX Biometric / Android Keystore |

## Project layout

```text
lib/
  main.dart                         Flutter application entry point
  models/                           Vault and file metadata models
  screens/                          Dashboard, unlock, vault, and viewer screens
  services/                         Dart state management and native channel API
  widgets/                          Secure keyboard and reusable UI components
  utils/                            Logging and passphrase helpers

android/app/src/main/kotlin/
  com/noleak/noleak/MainActivity.kt Android lifecycle and window hardening
  com/noleak/noleak/VaultPlugin.kt  Flutter ↔ Android MethodChannel boundary
  com/noleak/noleak/security/       Environment checks, Keystore, rate limiting
  com/noleak/noleak/vault/          Kotlin vault bridge and SAF handling
  com/noleak/noleak/audio|video/    Media playback adapters

android/app/src/main/cpp/
  vault_crypto.c                    libsodium crypto wrappers
  vault_container.c                 vault container read/write logic
  vault_engine.c                    global vault state and lifecycle
  vault_index.c                     encrypted index serialization
  vault_streaming.c                 streaming import state machine
  vault_jni.c                       JNI bindings
```

## Build from source

Requirements:

- Flutter SDK compatible with Dart `^3.5.2`.
- Android SDK.
- Android NDK `25.1.8937393`.
- JDK 17. Android Studio's bundled JBR is recommended.

If your shell uses a newer JDK by default:

```bash
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
```

Development build:

```bash
flutter pub get
flutter run
```

## Release build

Release builds require local signing configuration. Create `android/key.properties` or provide equivalent environment variables:

```properties
storeFile=app/your-release-key.jks
storePassword=...
keyAlias=...
keyPassword=...
```

Set the expected release certificate SHA-256 digest:

```bash
export NOLEAK_SIGNATURE_SHA256="AA11BB22..."
```

Then build the general release APK:

```bash
flutter build apk --release
```

Output:

```text
build/app/outputs/flutter-apk/app-release.apk
```

Do not commit keystores, signing passwords, or `android/key.properties`.

## Verification

Useful local checks before release:

```bash
flutter analyze
flutter test
flutter build apk --release
```

Analyzer warnings should be reviewed. Build failures should block release.

## Security contribution rules

- Do not add network access unless the threat model and README are updated.
- Do not log passphrases, keys, decrypted file bytes, vault plaintext, or full sensitive paths.
- Avoid plaintext temporary files. If a temporary file is unavoidable, document the lifecycle and cleanup.
- Keep vault format changes backwards-compatible or provide an explicit migration.
- Treat runtime tamper checks as defense-in-depth, not as the primary security boundary.

## License

NoLeak Vault is released under the BSD 3-Clause License. See [LICENSE](LICENSE).
