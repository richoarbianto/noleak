/// CyberButton - Primary Action Button with Neon Glow Effect
/// 
/// A cyberpunk-themed button with animated glow effects on hover/press.
/// Supports two variants:
/// - Filled (default): Solid neon green background
/// - Outlined: Transparent with neon green border
/// 
/// Features:
/// - Loading state with spinner
/// - Optional leading icon
/// - Disabled state handling
/// - Animated glow on interaction

import 'package:flutter/material.dart';
import '../theme/cyberpunk_theme.dart';

/// Primary CTA button with neon glow effect.
/// 
/// Example usage:
/// ```dart
/// CyberButton(
///   text: 'UNLOCK',
///   icon: Icons.lock_open,
///   onPressed: () => handleUnlock(),
///   isLoading: isProcessing,
/// )
/// ```
class CyberButton extends StatefulWidget {
  final String text;
  final VoidCallback? onPressed;
  final bool isLoading;
  final IconData? icon;
  final bool outlined;

  const CyberButton({
    super.key,
    required this.text,
    this.onPressed,
    this.isLoading = false,
    this.icon,
    this.outlined = false,
  });

  @override
  State<CyberButton> createState() => _CyberButtonState();
}

class _CyberButtonState extends State<CyberButton> {
  bool _isHovered = false;

  @override
  Widget build(BuildContext context) {
    final isEnabled = widget.onPressed != null && !widget.isLoading;

    if (widget.outlined) {
      return _buildOutlinedButton(isEnabled);
    }
    return _buildFilledButton(isEnabled);
  }

  Widget _buildFilledButton(bool isEnabled) {
    return AnimatedContainer(
      duration: const Duration(milliseconds: 200),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(12),
        boxShadow: isEnabled && _isHovered
            ? [
                BoxShadow(
                  color: CyberpunkTheme.neonGreen.withOpacity(0.5),
                  blurRadius: 20,
                  spreadRadius: 2,
                ),
              ]
            : isEnabled
                ? [
                    BoxShadow(
                      color: CyberpunkTheme.neonGreen.withOpacity(0.3),
                      blurRadius: 12,
                      spreadRadius: 0,
                    ),
                  ]
                : null,
      ),
      child: MouseRegion(
        onEnter: (_) => setState(() => _isHovered = true),
        onExit: (_) => setState(() => _isHovered = false),
        child: ElevatedButton(
          onPressed: isEnabled ? widget.onPressed : null,
          style: ElevatedButton.styleFrom(
            backgroundColor: isEnabled
                ? CyberpunkTheme.neonGreen
                : CyberpunkTheme.surfaceLight,
            foregroundColor: isEnabled
                ? CyberpunkTheme.background
                : CyberpunkTheme.textHint,
            minimumSize: const Size(double.infinity, 56),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(12),
            ),
          ),
          child: widget.isLoading
              ? const SizedBox(
                  height: 24,
                  width: 24,
                  child: CircularProgressIndicator(
                    strokeWidth: 2.5,
                    valueColor: AlwaysStoppedAnimation<Color>(
                      CyberpunkTheme.background,
                    ),
                  ),
                )
              : Row(
                  mainAxisSize: MainAxisSize.min,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    if (widget.icon != null) ...[
                      Icon(widget.icon, size: 20),
                      const SizedBox(width: 8),
                    ],
                    Text(
                      widget.text,
                      style: const TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                        letterSpacing: 1.0,
                      ),
                    ),
                  ],
                ),
        ),
      ),
    );
  }

  Widget _buildOutlinedButton(bool isEnabled) {
    return AnimatedContainer(
      duration: const Duration(milliseconds: 200),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(12),
        boxShadow: isEnabled && _isHovered
            ? [
                BoxShadow(
                  color: CyberpunkTheme.neonGreen.withOpacity(0.3),
                  blurRadius: 12,
                  spreadRadius: 0,
                ),
              ]
            : null,
      ),
      child: MouseRegion(
        onEnter: (_) => setState(() => _isHovered = true),
        onExit: (_) => setState(() => _isHovered = false),
        child: OutlinedButton(
          onPressed: isEnabled ? widget.onPressed : null,
          style: OutlinedButton.styleFrom(
            foregroundColor: isEnabled
                ? CyberpunkTheme.neonGreen
                : CyberpunkTheme.textHint,
            side: BorderSide(
              color: isEnabled
                  ? CyberpunkTheme.neonGreen
                  : CyberpunkTheme.surfaceBorder,
              width: 1.5,
            ),
            minimumSize: const Size(double.infinity, 56),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(12),
            ),
          ),
          child: widget.isLoading
              ? const SizedBox(
                  height: 24,
                  width: 24,
                  child: CircularProgressIndicator(
                    strokeWidth: 2.5,
                    valueColor: AlwaysStoppedAnimation<Color>(
                      CyberpunkTheme.neonGreen,
                    ),
                  ),
                )
              : Row(
                  mainAxisSize: MainAxisSize.min,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    if (widget.icon != null) ...[
                      Icon(widget.icon, size: 20),
                      const SizedBox(width: 8),
                    ],
                    Text(
                      widget.text,
                      style: const TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
        ),
      ),
    );
  }
}
