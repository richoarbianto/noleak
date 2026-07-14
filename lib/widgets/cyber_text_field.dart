/// CyberTextField - Cyberpunk-Styled Text Input Field
/// 
/// A themed text field with neon glow effects on focus. Automatically
/// integrates with [SecureKeyboard] when enabled in settings to provide
/// anti-keylogger protection for sensitive input.
/// 
/// Features:
/// - Animated glow border on focus
/// - Automatic SecureKeyboard integration
/// - Password visibility toggle support
/// - Error state display
/// 
/// SECURITY: When SecureKeyboard is enabled, the field becomes read-only
/// and all input is handled through the on-screen secure keyboard to
/// prevent keylogger attacks.

import 'package:flutter/material.dart';
import '../theme/cyberpunk_theme.dart';
import '../services/app_settings.dart';
import 'secure_keyboard.dart';

/// Cyberpunk styled text field with neon glow on focus.
/// 
/// Example usage:
/// ```dart
/// CyberTextField(
///   controller: passwordController,
///   labelText: 'Password',
///   obscureText: true,
///   suffixIcon: IconButton(
///     icon: Icon(Icons.visibility),
///     onPressed: toggleVisibility,
///   ),
/// )
/// ```
class CyberTextField extends StatefulWidget {
  final TextEditingController? controller;
  final String? labelText;
  final String? hintText;
  final bool obscureText;
  final Widget? suffixIcon;
  final String? errorText;
  final bool enabled;
  final ValueChanged<String>? onChanged;
  final ValueChanged<String>? onSubmitted;
  final TextInputType? keyboardType;
  final FocusNode? focusNode;
  final int maxLines;
  final bool autofocus;

  const CyberTextField({
    super.key,
    this.controller,
    this.labelText,
    this.hintText,
    this.obscureText = false,
    this.suffixIcon,
    this.errorText,
    this.enabled = true,
    this.onChanged,
    this.onSubmitted,
    this.keyboardType,
    this.focusNode,
    this.maxLines = 1,
    this.autofocus = false,
  });

  @override
  State<CyberTextField> createState() => _CyberTextFieldState();
}

class _CyberTextFieldState extends State<CyberTextField> {
  bool _isFocused = false;
  late TextEditingController _controller;
  bool _ownsController = false;
  bool _isDisposed = false;

  @override
  void initState() {
    super.initState();
    if (widget.controller != null) {
      _controller = widget.controller!;
    } else {
      _controller = TextEditingController();
      _ownsController = true;
    }
  }

  @override
  void didUpdateWidget(CyberTextField oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (_isDisposed) return; // Don't update if disposed
    if (widget.controller != oldWidget.controller) {
      if (_ownsController) {
        _controller.dispose();
        _ownsController = false;
      }
      if (widget.controller != null) {
        _controller = widget.controller!;
      } else {
        _controller = TextEditingController();
        _ownsController = true;
      }
    }
  }

  @override
  void dispose() {
    _isDisposed = true;
    // Clear keyboard target synchronously if this controller was the active target
    // Using direct assignment instead of hide() to avoid callback delay which could
    // cause the controller to be accessed after disposal during rebuilds
    if (SecureKeyboard.target.value?.controller == _controller) {
      // Clear immediately without postFrameCallback delay
      SecureKeyboard.target.value = null;
      SecureKeyboard.visible.value = false;
      SecureKeyboard.inset.value = 0;
    }
    if (_ownsController) {
      _controller.dispose();
    }
    super.dispose();
  }

  void _showSecureKeyboard() {
    if (!widget.enabled || _isDisposed) return;
    if (AppSettings.instance.secureKeyboardEnabled) {
      SecureKeyboard.show(
        context,
        controller: _controller,
        onChanged: widget.onChanged,
        onSubmitted: widget.onSubmitted,
      );
    }
  }

  bool get _useSecureKeyboard => AppSettings.instance.secureKeyboardEnabled;

  @override
  Widget build(BuildContext context) {
    // Don't build if disposed - prevents using disposed controller during rebuild
    if (_isDisposed) {
      return const SizedBox.shrink();
    }
    return AnimatedContainer(
      duration: const Duration(milliseconds: 200),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(12),
        boxShadow: _isFocused
            ? [
                BoxShadow(
                  color: CyberpunkTheme.neonGreen.withOpacity(0.3),
                  blurRadius: 12,
                  spreadRadius: 0,
                ),
              ]
            : null,
      ),
      child: Focus(
        onFocusChange: (focused) {
          if (!mounted || _isDisposed) return;
          setState(() => _isFocused = focused);
          if (focused && _useSecureKeyboard) {
            _showSecureKeyboard();
          }
        },
        child: TextField(
          controller: _controller,
          focusNode: widget.focusNode,
          obscureText: widget.obscureText,
          enabled: widget.enabled,
          readOnly: _useSecureKeyboard, // Only readOnly when using secure keyboard
          onTap: _useSecureKeyboard ? _showSecureKeyboard : null,
          onChanged: _useSecureKeyboard ? null : widget.onChanged,
          onSubmitted: _useSecureKeyboard ? null : widget.onSubmitted,
          maxLines: widget.maxLines,
          showCursor: true,
          enableInteractiveSelection: !_useSecureKeyboard,
          autocorrect: false,
          enableSuggestions: false,
          autofocus: widget.autofocus,
          style: const TextStyle(
            color: CyberpunkTheme.textPrimary,
            fontSize: 16,
          ),
          cursorColor: CyberpunkTheme.neonGreen,
          decoration: InputDecoration(
            labelText: widget.labelText,
            hintText: widget.hintText,
            errorText: widget.errorText,
            suffixIcon: widget.suffixIcon,
            labelStyle: TextStyle(
              color: _isFocused
                  ? CyberpunkTheme.neonGreen
                  : CyberpunkTheme.textSecondary,
            ),
          ),
        ),
      ),
    );
  }
}
