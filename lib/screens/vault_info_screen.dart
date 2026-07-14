/// VaultInfoScreen - Security Information Display
/// 
/// Educational screen explaining the security architecture and
/// protection mechanisms used by NoLeak Vault. Organized into
/// three tabs:
/// 
/// 1. OVERVIEW: Mission statement and core security principles
/// 2. CRYPTOGRAPHY: Key hierarchy, algorithms, quantum resistance
/// 3. PROTECTION: Brute-force, environment, memory, and data protection
/// 
/// This screen helps users understand the security guarantees
/// provided by the application.

import 'package:flutter/material.dart';
import '../theme/cyberpunk_theme.dart';

/// Security information screen with tabbed content.
/// 
/// Displays detailed information about the cryptographic
/// architecture and security measures implemented.
class VaultInfoScreen extends StatefulWidget {
  const VaultInfoScreen({super.key});

  @override
  State<VaultInfoScreen> createState() => _VaultInfoScreenState();
}

class _VaultInfoScreenState extends State<VaultInfoScreen> {
  int _selectedTab = 0;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: CyberpunkTheme.background,
      appBar: AppBar(
        title: const Text(
          'SECURITY INFO',
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
                children: const [
                  _OverviewTab(),
                  _CryptoTab(),
                  _ProtectionTab(),
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
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(20, 20, 20, 32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const _SloganHeader(),
          const SizedBox(height: 24),
          _SectionCard(
            title: 'Why We Built This',
            child: const Text(
              'No Leak Vaults is designed for those who refuse to let sensitive data '
              'leave their device. Every file stays local, encrypted end-to-end, '
              'and can only be unlocked with your passphrase.\n\n'
              'No cloud. No third parties. Just you and your data.',
              style: _Styles.body,
            ),
          ),
          const SizedBox(height: 16),
          _SectionCard(
            title: 'Core Security Principles',
            child: Column(
              children: const [
                _PrincipleItem(
                  icon: Icons.smartphone,
                  title: 'Local-First',
                  desc: 'No servers, no cloud sync, no external dependencies.',
                ),
                _PrincipleItem(
                  icon: Icons.visibility_off,
                  title: 'Zero-Knowledge',
                  desc: 'Keys derived solely from your passphrase, never stored.',
                ),
                _PrincipleItem(
                  icon: Icons.shield,
                  title: 'Fail-Closed',
                  desc: 'Access denied when root, debug, or tampering detected.',
                ),
                _PrincipleItem(
                  icon: Icons.data_object,
                  title: 'Minimal Metadata',
                  desc: 'Only essential vault information is retained.',
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          _SectionCard(
            title: 'Our Mission',
            child: const Text(
              'To give you absolute control over your data. No third parties. '
              'No cloud dependencies. No compromises on privacy.\n\n'
              'Your secrets stay yours.',
              style: _Styles.body,
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
  const _CryptoTab();

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(20, 20, 20, 32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _SectionCard(
            title: 'Key Hierarchy',
            subtitle: 'Multi-layer encryption architecture',
            child: const _KeyHierarchyDiagram(),
          ),
          const SizedBox(height: 16),
          _SectionCard(
            title: 'Algorithms Used',
            child: Column(
              children: const [
                _AlgorithmItem(
                  name: 'Argon2id',
                  purpose: 'Key Derivation Function (KDF)',
                  details: 'Memory-hard, GPU/ASIC resistant. Adaptive parameters based on device RAM (32-256 MB memory cost).',
                  icon: Icons.key,
                ),
                SizedBox(height: 12),
                _AlgorithmItem(
                  name: 'XChaCha20-Poly1305',
                  purpose: 'Auth Encryption (AEAD)',
                  details: '256-bit key, 192-bit nonce. Provides confidentiality + integrity. No nonce collision risk.',
                  icon: Icons.lock,
                ),
                SizedBox(height: 12),
                _AlgorithmItem(
                  name: 'SHA-256',
                  purpose: 'Integrity Verification',
                  details: 'Container-level integrity hash. Detects file corruption or tampering.',
                  icon: Icons.verified,
                ),
                SizedBox(height: 12),
                _AlgorithmItem(
                  name: 'libsodium CSPRNG',
                  purpose: 'Random Number Generation',
                  details: 'Cryptographically secure random for salts, nonces, and key generation.',
                  icon: Icons.casino,
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          _SectionCard(
            title: 'Quantum Resistance',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: const [
                Text(
                  '256-bit symmetric encryption remains highly resistant to quantum attacks.',
                  style: _Styles.body,
                ),
                SizedBox(height: 12),
                _InfoBox(
                  icon: Icons.science,
                  text: "Even with Grover's algorithm, effective complexity stays at 2¹²⁸—far beyond practical reach.",
                ),
                SizedBox(height: 12),
                Text(
                  'By avoiding RSA/ECC for data protection, this architecture is built to withstand the post-quantum era.',
                  style: _Styles.body,
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
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(20, 20, 20, 32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _SectionCard(
            title: 'Brute-Force Protection',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: const [
                Text(
                  'Multi-layer defense against password guessing attacks:',
                  style: _Styles.body,
                ),
                SizedBox(height: 12),
                _ProtectionItem(
                  title: 'Argon2id KDF',
                  desc: 'Memory-hard function makes each attempt expensive (32-256 MB RAM required per attempt).',
                ),
                _ProtectionItem(
                  title: 'Progressive Lockout',
                  desc: '5 fails → 30s, 8 fails → 2min, 10 fails → 5min, 15 fails → 15min, 20 fails → 1 hour.',
                ),
                _ProtectionItem(
                  title: 'Persistent Tracking',
                  desc: 'Attempt count survives app restart. Cannot bypass by force-closing.',
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          _SectionCard(
            title: 'Environment Security',
            child: Column(
              children: const [
                _ProtectionItem(
                  title: 'Root Detection',
                  desc: 'Detects su binaries, Magisk, and common root indicators.',
                ),
                _ProtectionItem(
                  title: 'Emulator Detection',
                  desc: 'Blocks execution on emulators and virtual devices.',
                ),
                _ProtectionItem(
                  title: 'Debugger Detection',
                  desc: 'Detects attached debuggers and instrumentation.',
                ),
                _ProtectionItem(
                  title: 'Tampering Detection',
                  desc: 'Verifies app signature and detects repackaging.',
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          _SectionCard(
            title: 'Memory Security',
            child: Column(
              children: const [
                _ProtectionItem(
                  title: 'Memory Locking',
                  desc: 'Master key locked in RAM, prevented from swap to disk.',
                ),
                _ProtectionItem(
                  title: 'Secure Wipe',
                  desc: 'All sensitive data overwritten with random bytes then zeroed.',
                ),
                _ProtectionItem(
                  title: 'Constant-Time Comparison',
                  desc: 'Password verification immune to timing attacks.',
                ),
                _ProtectionItem(
                  title: 'No Plaintext Logging',
                  desc: 'Sensitive data sanitized from all log outputs.',
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          _SectionCard(
            title: 'Data Protection',
            child: Column(
              children: const [
                _ProtectionItem(
                  title: 'Screenshot Blocking',
                  desc: 'FLAG_SECURE prevents screenshots and screen recording.',
                ),
                _ProtectionItem(
                  title: 'Backup Exclusion',
                  desc: 'Vault data excluded from Android backup systems.',
                ),
                _ProtectionItem(
                  title: 'Secure File Deletion',
                  desc: 'Files overwritten with random data before deletion.',
                ),
                _ProtectionItem(
                  title: 'Biometric Protection',
                  desc: 'Hardware-backed keys invalidated on fingerprint changes.',
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
      child: Column(
        children: const [
          _KeyNode(
            label: 'Your Passphrase',
            icon: Icons.password,
            isTop: true,
          ),
          _KeyArrow(label: 'Argon2id + salt'),
          _KeyNode(
            label: 'KEK',
            sublabel: 'Key Encryption Key',
            icon: Icons.vpn_key,
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
            note: 'Per-file, stored in encrypted index',
          ),
          _KeyArrow(label: 'XChaCha20-Poly1305 encrypt'),
          _KeyNode(
            label: 'Encrypted Data',
            sublabel: '64KB chunks',
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
                Row(
                  children: [
                    Text(
                      label,
                      style: TextStyle(
                        color: color,
                        fontWeight: FontWeight.w600,
                        fontSize: 13,
                      ),
                    ),
                    if (sublabel != null) ...[
                      const SizedBox(width: 6),
                      Text(
                        '($sublabel)',
                        style: TextStyle(
                          color: color.withOpacity(0.7),
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ],
                ),
                if (note != null)
                  Text(
                    note!,
                    style: TextStyle(
                      color: CyberpunkTheme.neonGreenDim.withOpacity(0.8),
                      fontSize: 10,
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
                fontSize: 10,
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
          'Take Back Control of Your Privacy',
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
          'Total privacy. Fully local.',
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
                Row(
                  children: [
                    Text(
                      name,
                      style: const TextStyle(
                        color: CyberpunkTheme.neonGreen,
                        fontWeight: FontWeight.w700,
                        fontSize: 13,
                      ),
                    ),
                    const SizedBox(width: 8),
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
                          fontSize: 9,
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

  const _ProtectionItem({required this.title, required this.desc});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            margin: const EdgeInsets.only(top: 4),
            child: const Icon(
              Icons.check_circle,
              color: CyberpunkTheme.neonGreen,
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
                  style: const TextStyle(
                    color: CyberpunkTheme.neonGreen,
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
    fontSize: 11,
    height: 1.4,
  );
}
