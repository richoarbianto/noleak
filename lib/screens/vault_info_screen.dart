// User-facing explanation of NoLeak's security model, cryptography, and
// runtime protections. Claims here must stay aligned with the implementation.

import 'package:flutter/material.dart';
import '../services/vault_channel.dart';
import '../theme/cyberpunk_theme.dart';

class VaultInfoScreen extends StatefulWidget {
  const VaultInfoScreen({super.key});

  @override
  State<VaultInfoScreen> createState() => _VaultInfoScreenState();
}

class _VaultInfoScreenState extends State<VaultInfoScreen> {
  int _selectedTab = 0;
  Map<String, dynamic>? _kdfInfo;

  @override
  void initState() {
    super.initState();
    _loadKdfInfo();
  }

  Future<void> _loadKdfInfo() async {
    try {
      final value = await VaultChannel.getKdfInfo();
      if (mounted) setState(() => _kdfInfo = value);
    } catch (_) {
      // Static KDF description remains available if native info is unavailable.
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: CyberpunkTheme.background,
      appBar: AppBar(
        title: const Text(
          'SECURITY CENTER',
          style: TextStyle(
            color: CyberpunkTheme.neonGreen,
            letterSpacing: 1.5,
            fontWeight: FontWeight.w600,
          ),
        ),
        backgroundColor: CyberpunkTheme.background,
        elevation: 0,
        iconTheme: const IconThemeData(color: CyberpunkTheme.neonGreen),
      ),
      body: SafeArea(
        child: Column(
          children: [
            _buildTabBar(),
            Expanded(
              child: IndexedStack(
                index: _selectedTab,
                children: [
                  const _OverviewTab(),
                  _CryptoTab(kdfInfo: _kdfInfo),
                  const _ProtectionTab(),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildTabBar() {
    final tabs = ['Overview', 'Cryptography', 'Protection'];
    return Container(
      margin: const EdgeInsets.fromLTRB(16, 8, 16, 0),
      decoration: BoxDecoration(
        color: CyberpunkTheme.surface,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: CyberpunkTheme.neonGreen.withOpacity(0.3),
        ),
      ),
      child: Row(
        children: List.generate(tabs.length, (i) {
          final selected = _selectedTab == i;
          return Expanded(
            child: GestureDetector(
              onTap: () => setState(() => _selectedTab = i),
              child: Container(
                padding: const EdgeInsets.symmetric(vertical: 12),
                decoration: BoxDecoration(
                  color: selected
                      ? CyberpunkTheme.neonGreen.withOpacity(0.15)
                      : Colors.transparent,
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(
                  tabs[i],
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    color: selected
                        ? CyberpunkTheme.neonGreen
                        : CyberpunkTheme.neonGreenDim,
                    fontWeight: selected ? FontWeight.w600 : FontWeight.w400,
                    fontSize: 13,
                  ),
                ),
              ),
            ),
          );
        }),
      ),
    );
  }
}

// ============================================================================
// OVERVIEW TAB
// ============================================================================
class _OverviewTab extends StatelessWidget {
  const _OverviewTab();

  @override
  Widget build(BuildContext context) {
    return const SingleChildScrollView(
      padding: EdgeInsets.fromLTRB(20, 20, 20, 32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _SloganHeader(),
          SizedBox(height: 24),
          _SectionCard(
            title: 'Protection Model',
            subtitle: 'What NoLeak is designed to protect',
            child: Text(
              'NoLeak protects files at rest inside an encrypted vault. Vault data '
              'stays on your device unless you explicitly export a file or encrypted '
              'container. The Android app has no Internet permission, cloud account, '
              'or remote recovery service.',
              style: _Styles.body,
            ),
          ),
          SizedBox(height: 16),
          _SectionCard(
            title: 'Security Advantages',
            child: Column(
              children: [
                _PrincipleItem(
                  icon: Icons.cloud_off,
                  title: 'Smaller Exposure Surface',
                  desc:
                      'No backend or cloud sync means vault contents are not sent to a remote service.',
                ),
                _PrincipleItem(
                  icon: Icons.verified_user,
                  title: 'Authenticated Encryption',
                  desc:
                      'Encrypted content is authenticated, so modified data is rejected before it is trusted.',
                ),
                _PrincipleItem(
                  icon: Icons.key,
                  title: 'Separated File Keys',
                  desc:
                      'Each file has its own random data key, wrapped by the vault master key.',
                ),
                _PrincipleItem(
                  icon: Icons.layers,
                  title: 'Defense in Depth',
                  desc:
                      'Passphrase, strong biometric authentication, rate limiting, auto-lock, and device checks work together.',
                ),
              ],
            ),
          ),
          SizedBox(height: 16),
          _SectionCard(
            title: 'Your Security Still Matters',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Use a long, unique passphrase and keep your Android device updated. '
                  'NoLeak cannot recover a forgotten passphrase because it does not '
                  'store a recovery key.',
                  style: _Styles.body,
                ),
                SizedBox(height: 12),
                _InfoBox(
                  icon: Icons.info_outline,
                  text:
                      'No application can guarantee secrecy on a fully compromised device. Environment checks reduce risk but are not a substitute for a trusted operating system.',
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

// ============================================================================
// CRYPTOGRAPHY TAB
// ============================================================================
class _CryptoTab extends StatelessWidget {
  final Map<String, dynamic>? kdfInfo;

  const _CryptoTab({required this.kdfInfo});

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(20, 20, 20, 32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _SectionCard(
            title: 'Argon2id Profile',
            subtitle: 'Memory-hard passphrase protection',
            child: _KdfProfilePanel(info: kdfInfo),
          ),
          const SizedBox(height: 16),
          const _SectionCard(
            title: 'Key Architecture',
            subtitle: 'Passphrase-derived access with per-file key separation',
            child: _KeyHierarchyDiagram(),
          ),
          const SizedBox(height: 16),
          const _SectionCard(
            title: 'Cryptographic Components',
            child: Column(
              children: [
                _AlgorithmItem(
                  name: 'XChaCha20-Poly1305',
                  purpose: 'Authenticated Encryption',
                  details:
                      'Encrypts file data, keys, and the vault index with a 256-bit key and a 192-bit nonce. Authentication tags detect modification.',
                  icon: Icons.lock,
                ),
                SizedBox(height: 12),
                _AlgorithmItem(
                  name: 'Argon2id',
                  purpose: 'Passphrase Derivation',
                  details:
                      'Turns the passphrase and a random salt into a key-encryption key. Memory cost makes large-scale guessing more expensive.',
                  icon: Icons.password,
                ),
                SizedBox(height: 12),
                _AlgorithmItem(
                  name: 'libsodium CSPRNG',
                  purpose: 'Secure Randomness',
                  details:
                      'Generates independent salts, nonces, master keys, and per-file data keys.',
                  icon: Icons.casino,
                ),
                SizedBox(height: 12),
                _AlgorithmItem(
                  name: 'SHA-256',
                  purpose: 'Corruption Check',
                  details:
                      'Checks container consistency. Cryptographic tamper detection is provided by the authenticated-encryption tags.',
                  icon: Icons.fact_check,
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          const _SectionCard(
            title: 'Profile Compatibility',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'New vaults select a 64, 128, or 256 MB memory profile based on '
                  'device capacity. The selected values are stored in the vault header.',
                  style: _Styles.body,
                ),
                SizedBox(height: 12),
                _InfoBox(
                  icon: Icons.memory,
                  text:
                      'Existing vaults always use their stored Argon2id values. NoLeak validates imported headers and warns when a vault exceeds this device profile. It never silently lowers the values, because that would derive a different key.',
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

// ============================================================================
// PROTECTION TAB
// ============================================================================
class _ProtectionTab extends StatelessWidget {
  const _ProtectionTab();

  @override
  Widget build(BuildContext context) {
    return const SingleChildScrollView(
      padding: EdgeInsets.fromLTRB(20, 20, 20, 32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _SectionCard(
            title: 'Access & Authentication',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _ProtectionItem(
                  title: 'Passphrase + Strong Biometric',
                  desc:
                      'Vault unlock requires the correct passphrase followed by a Keystore-backed strong biometric check.',
                ),
                _ProtectionItem(
                  title: 'Persistent Attempt Limits',
                  desc:
                      'Short delays begin after failures. After 5 failures, lockout starts at 1 minute and increases up to 30 minutes.',
                ),
                _ProtectionItem(
                  title: 'Per-Vault Coverage',
                  desc:
                      'The app applies the same persistent limiter to unlock, verification, title changes, password changes, and deletion.',
                ),
                _ProtectionItem(
                  title: 'Automatic Re-Authentication',
                  desc:
                      'Configurable idle locking and session biometric checks reduce exposure when the app is left unattended.',
                ),
              ],
            ),
          ),
          SizedBox(height: 16),
          _SectionCard(
            title: 'Device & Runtime Protection',
            child: Column(
              children: [
                _ProtectionItem(
                  title: 'Fail-Closed Environment Gate',
                  desc:
                      'Vault operations are blocked when checks detect root or Magisk artifacts, emulators, debugging, hooking, ADB, an unlocked boot state, an untrusted installer, or an unexpected app signature.',
                ),
                _ProtectionItem(
                  title: 'Screen Capture Reduction',
                  desc:
                      'Android FLAG_SECURE reduces screenshots, screen recording, and recent-app previews.',
                ),
                _ProtectionItem(
                  title: 'Overlay-Touch Blocking',
                  desc:
                      'Non-system overlays are hidden on supported Android versions, and obscured touch events are rejected.',
                ),
                _ProtectionItem(
                  title: 'No Network or Android Backup',
                  desc:
                      'The app removes Internet permission and excludes its private data from Android backup and device-transfer extraction.',
                ),
              ],
            ),
          ),
          SizedBox(height: 16),
          _SectionCard(
            title: 'Sensitive Data Handling',
            child: Column(
              children: [
                _ProtectionItem(
                  title: 'Mutable Passphrase Transport',
                  desc:
                      'Secure fields transport passphrases as mutable UTF-8 bytes and clear app-controlled buffers after use.',
                ),
                _ProtectionItem(
                  title: 'Best-Effort Memory Locking',
                  desc:
                      'The native engine attempts to lock the master key in RAM and continues safely with standard memory when the platform refuses it.',
                ),
                _ProtectionItem(
                  title: 'Buffer Cleanup',
                  desc:
                      'Native keys, passphrases, decrypted chunks, and viewer buffers are zeroized when their lifecycle ends.',
                ),
                _ProtectionItem(
                  title: 'Release Logging Disabled',
                  desc:
                      'Application and native diagnostic logging is disabled in release builds.',
                ),
              ],
            ),
          ),
          SizedBox(height: 16),
          _SectionCard(
            title: 'Important Limits',
            child: Column(
              children: [
                _ProtectionItem(
                  icon: Icons.warning_amber_rounded,
                  color: CyberpunkTheme.warning,
                  title: 'Offline Guessing',
                  desc:
                      'A copied vault can be tested outside NoLeak without the app limiter. A long, unique passphrase remains essential.',
                ),
                _ProtectionItem(
                  icon: Icons.warning_amber_rounded,
                  color: CyberpunkTheme.warning,
                  title: 'Compromised Operating System',
                  desc:
                      'Root and tamper checks raise the barrier but cannot guarantee protection if Android itself is fully controlled by an attacker.',
                ),
                _ProtectionItem(
                  icon: Icons.warning_amber_rounded,
                  color: CyberpunkTheme.warning,
                  title: 'Flash Storage Deletion',
                  desc:
                      'Vault deletion overwrites data before removal, but physical erasure is best-effort on flash storage because of wear leveling.',
                ),
                _ProtectionItem(
                  icon: Icons.visibility,
                  color: CyberpunkTheme.warning,
                  title: 'Showing a Passphrase',
                  desc:
                      'When you choose to reveal a passphrase, Flutter must briefly create a displayable string. Hiding it returns the field to masked output.',
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

// ============================================================================
// KDF PROFILE
// ============================================================================
class _KdfProfilePanel extends StatelessWidget {
  final Map<String, dynamic>? info;

  const _KdfProfilePanel({required this.info});

  String _value(String key, {String suffix = ''}) {
    final value = info?[key];
    return value is num ? '${value.toInt()}$suffix' : '—';
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        LayoutBuilder(
          builder: (context, constraints) {
            final columns = constraints.maxWidth >= 480 ? 3 : 2;
            final width = (constraints.maxWidth - (columns - 1) * 8) / columns;
            return Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                _KdfMetric(
                  width: width,
                  label: 'Memory cost',
                  value: _value('memoryMiB', suffix: ' MB'),
                ),
                _KdfMetric(
                  width: width,
                  label: 'Operations',
                  value: _value('opslimit'),
                ),
                _KdfMetric(
                  width: columns == 2 ? constraints.maxWidth : width,
                  label: 'Parallelism',
                  value: _value('parallelism'),
                ),
              ],
            );
          },
        ),
        const SizedBox(height: 12),
        Text(
          'Higher memory cost makes each passphrase guess more expensive. NoLeak '
          'selects a device-appropriate profile when a vault is created, stores '
          'those values with the vault, and uses them unchanged on every unlock.',
          style: _Styles.bodySmall,
        ),
      ],
    );
  }
}

class _KdfMetric extends StatelessWidget {
  final double width;
  final String label;
  final String value;

  const _KdfMetric({
    required this.width,
    required this.label,
    required this.value,
  });

  @override
  Widget build(BuildContext context) {
    return Semantics(
      label: '$label: $value',
      child: Container(
        width: width,
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 12),
        decoration: BoxDecoration(
          color: CyberpunkTheme.background,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: CyberpunkTheme.neonGreen.withOpacity(0.2),
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(label, style: _Styles.bodySmall),
            const SizedBox(height: 2),
            Text(
              value,
              style: const TextStyle(
                color: CyberpunkTheme.neonGreen,
                fontSize: 16,
                fontWeight: FontWeight.w700,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ============================================================================
// KEY HIERARCHY DIAGRAM
// ============================================================================
class _KeyHierarchyDiagram extends StatelessWidget {
  const _KeyHierarchyDiagram();

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: CyberpunkTheme.background,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: CyberpunkTheme.neonGreen.withOpacity(0.2),
        ),
      ),
      child: const Column(
        children: [
          _KeyNode(
            label: 'Passphrase',
            icon: Icons.password,
            isTop: true,
          ),
          _KeyArrow(label: 'Argon2id + salt'),
          _KeyNode(
            label: 'KEK',
            sublabel: 'Key Encryption Key',
            icon: Icons.vpn_key,
            note: 'Derived during unlock; not written to the vault',
          ),
          _KeyArrow(label: 'XChaCha20-Poly1305 wrap'),
          _KeyNode(
            label: 'MK',
            sublabel: 'Master Key',
            icon: Icons.key,
            note: 'Stored encrypted in vault header',
          ),
          _KeyArrow(label: 'XChaCha20-Poly1305 wrap'),
          _KeyNode(
            label: 'DEK',
            sublabel: 'Data Encryption Key',
            icon: Icons.enhanced_encryption,
            note: 'Random key per file, stored encrypted',
          ),
          _KeyArrow(label: 'XChaCha20-Poly1305 encrypt'),
          _KeyNode(
            label: 'Encrypted Data',
            sublabel: 'Authenticated chunks',
            icon: Icons.folder_zip,
            isBottom: true,
          ),
        ],
      ),
    );
  }
}

class _KeyNode extends StatelessWidget {
  final String label;
  final String? sublabel;
  final String? note;
  final IconData icon;
  final bool isTop;
  final bool isBottom;

  const _KeyNode({
    required this.label,
    required this.icon,
    this.sublabel,
    this.note,
    this.isTop = false,
    this.isBottom = false,
  });

  @override
  Widget build(BuildContext context) {
    final color = isTop
        ? CyberpunkTheme.warning
        : isBottom
            ? CyberpunkTheme.cyan
            : CyberpunkTheme.neonGreen;

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withOpacity(0.5)),
      ),
      child: Row(
        children: [
          Icon(icon, color: color, size: 20),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Wrap(
                  spacing: 6,
                  runSpacing: 2,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  children: [
                    Text(
                      label,
                      style: TextStyle(
                        color: color,
                        fontWeight: FontWeight.w600,
                        fontSize: 13,
                      ),
                    ),
                    if (sublabel != null)
                      Text(
                        '($sublabel)',
                        style: TextStyle(
                          color: color.withOpacity(0.7),
                          fontSize: 12,
                        ),
                      ),
                  ],
                ),
                if (note != null)
                  Text(
                    note!,
                    style: TextStyle(
                      color: CyberpunkTheme.neonGreenDim.withOpacity(0.8),
                      fontSize: 12,
                    ),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _KeyArrow extends StatelessWidget {
  final String label;
  const _KeyArrow({required this.label});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          const SizedBox(width: 24),
          Column(
            children: [
              Container(
                width: 2,
                height: 8,
                color: CyberpunkTheme.neonGreen.withOpacity(0.5),
              ),
              Icon(
                Icons.arrow_downward,
                color: CyberpunkTheme.neonGreen.withOpacity(0.7),
                size: 16,
              ),
            ],
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              label,
              style: TextStyle(
                color: CyberpunkTheme.neonGreenDim.withOpacity(0.8),
                fontSize: 12,
                fontStyle: FontStyle.italic,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

// ============================================================================
// REUSABLE COMPONENTS
// ============================================================================
class _SloganHeader extends StatelessWidget {
  const _SloganHeader();

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        const Text(
          'Security You Can Understand',
          style: TextStyle(
            color: CyberpunkTheme.neonGreen,
            fontSize: 18,
            fontWeight: FontWeight.w700,
            fontStyle: FontStyle.italic,
            letterSpacing: 1.0,
          ),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 6),
        Text(
          'Local encryption, layered access, transparent limits.',
          style: TextStyle(
            color: CyberpunkTheme.neonGreenDim.withOpacity(0.9),
            fontSize: 14,
            fontWeight: FontWeight.w500,
          ),
          textAlign: TextAlign.center,
        ),
      ],
    );
  }
}

class _SectionCard extends StatelessWidget {
  final String title;
  final String? subtitle;
  final Widget child;

  const _SectionCard({
    required this.title,
    required this.child,
    this.subtitle,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: CyberpunkTheme.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: CyberpunkTheme.neonGreen.withOpacity(0.2),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: _Styles.sectionTitle),
          if (subtitle != null) ...[
            const SizedBox(height: 2),
            Text(
              subtitle!,
              style: TextStyle(
                color: CyberpunkTheme.neonGreenDim.withOpacity(0.7),
                fontSize: 12,
              ),
            ),
          ],
          const SizedBox(height: 12),
          child,
        ],
      ),
    );
  }
}

class _PrincipleItem extends StatelessWidget {
  final IconData icon;
  final String title;
  final String desc;

  const _PrincipleItem({
    required this.icon,
    required this.title,
    required this.desc,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: CyberpunkTheme.neonGreen.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(icon, color: CyberpunkTheme.neonGreen, size: 18),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: const TextStyle(
                    color: CyberpunkTheme.neonGreen,
                    fontWeight: FontWeight.w600,
                    fontSize: 13,
                  ),
                ),
                const SizedBox(height: 2),
                Text(desc, style: _Styles.bodySmall),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _AlgorithmItem extends StatelessWidget {
  final String name;
  final String purpose;
  final String details;
  final IconData icon;

  const _AlgorithmItem({
    required this.name,
    required this.purpose,
    required this.details,
    required this.icon,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: CyberpunkTheme.background,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: CyberpunkTheme.neonGreen.withOpacity(0.15),
        ),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, color: CyberpunkTheme.neonGreen, size: 20),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Wrap(
                  spacing: 8,
                  runSpacing: 4,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  children: [
                    Text(
                      name,
                      style: const TextStyle(
                        color: CyberpunkTheme.neonGreen,
                        fontWeight: FontWeight.w700,
                        fontSize: 13,
                      ),
                    ),
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 6,
                        vertical: 2,
                      ),
                      decoration: BoxDecoration(
                        color: CyberpunkTheme.neonGreen.withOpacity(0.15),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: Text(
                        purpose,
                        style: TextStyle(
                          color: CyberpunkTheme.neonGreen.withOpacity(0.9),
                          fontSize: 12,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                Text(details, style: _Styles.bodySmall),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _ProtectionItem extends StatelessWidget {
  final String title;
  final String desc;
  final IconData icon;
  final Color color;

  const _ProtectionItem({
    required this.title,
    required this.desc,
    this.icon = Icons.check_circle,
    this.color = CyberpunkTheme.neonGreen,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            margin: const EdgeInsets.only(top: 4),
            child: Icon(
              icon,
              color: color,
              size: 16,
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    color: color,
                    fontWeight: FontWeight.w600,
                    fontSize: 12,
                  ),
                ),
                Text(desc, style: _Styles.bodySmall),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _InfoBox extends StatelessWidget {
  final IconData icon;
  final String text;

  const _InfoBox({required this.icon, required this.text});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: CyberpunkTheme.cyan.withOpacity(0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: CyberpunkTheme.cyan.withOpacity(0.3),
        ),
      ),
      child: Row(
        children: [
          Icon(icon, color: CyberpunkTheme.cyan, size: 20),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              text,
              style: TextStyle(
                color: CyberpunkTheme.cyan.withOpacity(0.9),
                fontSize: 12,
                height: 1.4,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

// ============================================================================
// STYLES
// ============================================================================
class _Styles {
  static const sectionTitle = TextStyle(
    color: CyberpunkTheme.neonGreen,
    fontSize: 15,
    fontWeight: FontWeight.w600,
    letterSpacing: 0.3,
  );

  static const body = TextStyle(
    color: CyberpunkTheme.neonGreenDim,
    fontSize: 13,
    height: 1.5,
  );

  static final bodySmall = TextStyle(
    color: CyberpunkTheme.neonGreenDim.withOpacity(0.85),
    fontSize: 12,
    height: 1.4,
  );
}
