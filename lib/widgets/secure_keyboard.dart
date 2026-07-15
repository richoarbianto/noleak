/// SecureKeyboard - Anti-Keylogger On-Screen Keyboard
///
/// A custom on-screen keyboard that bypasses the system keyboard to
/// prevent keylogger attacks. When enabled, all password input is
/// handled through this secure keyboard instead of the system IME.
///
/// SECURITY FEATURES:
/// - Bypasses system keyboard (no IME access to keystrokes)
/// - No autocomplete or suggestions
/// - Keys are rendered in-app (not accessible to other apps)
/// - Supports shift, caps lock, and symbol modes
/// - Backspace with hold-to-repeat functionality
///
/// The keyboard is displayed as a bottom sheet and integrates with
/// [CyberTextField] automatically when enabled in settings.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import '../theme/cyberpunk_theme.dart';

/// Static controller for the secure keyboard.
///
/// Provides methods to show/hide the keyboard and manages the
/// current target text field. Uses ValueNotifiers for reactive
/// state management.
class SecureKeyboard {
  static const double _fallbackInset = 300;
  static const int _maxInputBytes = 1024;
  static final ValueNotifier<_KeyboardTarget?> _target = ValueNotifier(null);
  static final ValueNotifier<bool> _visible = ValueNotifier(false);
  static final ValueNotifier<double> _inset = ValueNotifier(0);
  static final Expando<_SecureInputBuffer> _inputs =
      Expando<_SecureInputBuffer>('secure keyboard input');

  static ValueNotifier<_KeyboardTarget?> get target => _target;
  static ValueNotifier<bool> get visible => _visible;
  static ValueNotifier<double> get inset => _inset;

  static void show(
    BuildContext context, {
    required TextEditingController controller,
    bool secureInput = false,
    bool obscureText = true,
    ValueChanged<String>? onChanged,
    ValueChanged<String>? onSubmitted,
  }) {
    if (secureInput) {
      _prepareInput(controller, obscureText);
    }
    _target.value = _KeyboardTarget(
      controller: controller,
      secureInput: secureInput,
      onChanged: onChanged,
      onSubmitted: onSubmitted,
    );
    if (_visible.value) return;
    _visible.value = true;
    _inset.value = _fallbackInset;
  }

  static void hide() {
    // Defer to next frame to avoid notifying during widget tree lock
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _visible.value = false;
      _inset.value = 0;
      _target.value = null;
    });
  }

  static Uint8List? copyInput(TextEditingController controller) {
    final input = _inputs[controller];
    if (input == null) return null;
    return Uint8List(input.length)..setRange(0, input.length, input.bytes);
  }

  static int? inputLength(TextEditingController controller) =>
      _inputs[controller]?.length;

  static void setObscured(TextEditingController controller, bool obscureText) {
    final input = _inputs[controller];
    if (input == null) return;
    input.obscured = obscureText;
    _renderSecureInput(controller, input);
  }

  static void clearInput(TextEditingController controller) {
    final input = _inputs[controller];
    if (input == null) return;
    input.bytes.fillRange(0, input.bytes.length, 0);
    input.length = 0;
    _inputs[controller] = null;
  }

  static void _prepareInput(
      TextEditingController controller, bool obscureText) {
    final prepared = _inputs[controller];
    if (prepared != null) {
      prepared.obscured = obscureText;
      _renderSecureInput(controller, prepared);
      return;
    }
    final input = _SecureInputBuffer();
    final existing = utf8.encode(controller.text);
    input.length = existing.length.clamp(0, _maxInputBytes);
    input.bytes.setRange(0, input.length, existing);
    input.obscured = obscureText;
    existing.fillRange(0, existing.length, 0);
    _inputs[controller] = input;
    _renderSecureInput(controller, input);
  }

  static void _renderSecureInput(
      TextEditingController controller, _SecureInputBuffer input) {
    final value = input.obscured
        ? List.filled(input.characterCount, '\u2022').join()
        : utf8.decode(Uint8List.sublistView(input.bytes, 0, input.length));
    controller.value = TextEditingValue(
      text: value,
      selection: TextSelection.collapsed(offset: value.length),
    );
  }

  /// Check if the current target controller is still valid (mounted)
  static void checkTargetValidity() {
    final target = _target.value;
    if (target == null) return;

    // Check if controller is disposed by trying to access its value
    try {
      // ignore: unnecessary_null_comparison
      if (target.controller.text == null) {
        hide();
      }
    } catch (_) {
      // Controller is disposed, hide keyboard
      hide();
    }
  }
}

class SecureKeyboardSheet extends StatefulWidget {
  final ValueNotifier<_KeyboardTarget?> target;

  const SecureKeyboardSheet({super.key, required this.target});

  @override
  State<SecureKeyboardSheet> createState() => _SecureKeyboardSheetState();
}

class _SecureKeyboardSheetState extends State<SecureKeyboardSheet> {
  static const _keyHeight = 54.0;
  static const _keyGap = 1.5;
  static const _keyRadius = 9.0;
  static const _shiftKey = '_shift';
  static const _backspaceKey = '_backspace';
  static const _spaceKey = '_space';
  static const _enterKey = '_enter';
  static const _symbolsKey = '_symbols';
  static const _lettersKey = '_letters';

  static const _letterLayout = [
    ['q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p'],
    ['a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l'],
    [_shiftKey, 'z', 'x', 'c', 'v', 'b', 'n', 'm', _backspaceKey],
    [_symbolsKey, _spaceKey, _enterKey],
  ];

  static const _symbolLayout = [
    ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'],
    ['@', '#', r'$', '%', '&', '*', '-', '+', '(', ')'],
    [_shiftKey, '!', '"', "'", ':', ';', '/', '?', _backspaceKey],
    [_lettersKey, _spaceKey, _enterKey],
  ];

  static const _symbolLayoutAlt = [
    ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'],
    ['[', ']', '{', '}', '<', '>', '=', '_', '\\', '|'],
    [_shiftKey, '~', '`', '^', '.', ',', ':', ';', _backspaceKey],
    [_lettersKey, _spaceKey, _enterKey],
  ];

  _KeyboardTarget? _activeTarget;
  bool _shift = false;
  bool _capsLock = false;
  bool _symbols = false;
  bool _symbolShift = false;
  Timer? _backspaceHoldTimer;
  Timer? _backspaceRepeatTimer;
  bool _backspaceRepeating = false;

  @override
  void initState() {
    super.initState();
    _activeTarget = widget.target.value;
    widget.target.addListener(_handleTargetChange);
    SecureKeyboard.visible.addListener(_handleVisibilityChange);
  }

  @override
  void dispose() {
    SecureKeyboard.visible.removeListener(_handleVisibilityChange);
    _cancelBackspaceTimers();
    widget.target.removeListener(_handleTargetChange);
    super.dispose();
  }

  void _handleTargetChange() {
    final newTarget = widget.target.value;
    if (newTarget == null) {
      // Target was cleared, keyboard should hide
      return;
    }
    _activeTarget = newTarget;
    _resetLayout();
  }

  void _handleVisibilityChange() {
    if (!SecureKeyboard.visible.value) {
      _cancelBackspaceTimers();
      _resetLayout();
    }
  }

  void _resetLayout() {
    if (!mounted) return;
    setState(() {
      _shift = false;
      _capsLock = false;
      _symbols = false;
      _symbolShift = false;
    });
  }

  TextEditingController? get _controller => _activeTarget?.controller;

  void _emitChanged() {
    final controller = _controller;
    if (controller == null) return;
    final target = _activeTarget;
    if (target == null) return;
    final input = SecureKeyboard._inputs[controller];
    final value = target.secureInput && input != null
        ? List.filled(input.characterCount, '\u2022').join()
        : controller.text;
    target.onChanged?.call(value);
  }

  void _insertText(String value) {
    final controller = _controller;
    if (controller == null) return;
    final target = _activeTarget;
    if (target == null) return;
    if (!target.secureInput) {
      final updated = controller.text + value;
      controller.value = TextEditingValue(
        text: updated,
        selection: TextSelection.collapsed(offset: updated.length),
      );
      _emitChanged();
      return;
    }
    final input = SecureKeyboard._inputs[controller];
    if (input == null) return;
    final encoded = utf8.encode(value);
    if (input.length + encoded.length > SecureKeyboard._maxInputBytes) return;
    input.bytes.setRange(input.length, input.length + encoded.length, encoded);
    input.length += encoded.length;
    SecureKeyboard._renderSecureInput(controller, input);
    _emitChanged();
  }

  void _backspace() {
    final controller = _controller;
    if (controller == null) return;
    final target = _activeTarget;
    if (target == null) return;
    if (!target.secureInput) {
      final current = controller.text;
      if (current.isEmpty) return;
      final lastRuneLength = current.runes.last > 0xffff ? 2 : 1;
      final updated = current.substring(0, current.length - lastRuneLength);
      controller.value = TextEditingValue(
        text: updated,
        selection: TextSelection.collapsed(offset: updated.length),
      );
      _emitChanged();
      return;
    }
    final input = SecureKeyboard._inputs[controller];
    if (input == null || input.length == 0) return;
    final oldLength = input.length;
    input.length--;
    while (input.length > 0 && (input.bytes[input.length] & 0xc0) == 0x80) {
      input.length--;
    }
    input.bytes.fillRange(input.length, oldLength, 0);
    SecureKeyboard._renderSecureInput(controller, input);
    _emitChanged();
  }

  void _toggleShift() {
    if (_symbols) {
      setState(() => _symbolShift = !_symbolShift);
      return;
    }
    if (_capsLock) {
      setState(() {
        _capsLock = false;
        _shift = false;
      });
      return;
    }
    if (_shift) {
      setState(() {
        _shift = false;
        _capsLock = true;
      });
      return;
    }
    setState(() => _shift = true);
  }

  void _toggleSymbols() {
    setState(() {
      _symbols = !_symbols;
      _symbolShift = false;
      _shift = false;
      _capsLock = false;
    });
  }

  void _handleKey(String key) {
    if (key == _shiftKey) {
      _toggleShift();
      return;
    }
    if (key == _backspaceKey) {
      _backspace();
      return;
    }
    if (key == _spaceKey) {
      _insertText(' ');
      return;
    }
    if (key == _enterKey) {
      final controller = _controller;
      if (controller != null) {
        final target = _activeTarget;
        final input = SecureKeyboard._inputs[controller];
        final value = target?.secureInput == true && input != null
            ? List.filled(input.characterCount, '\u2022').join()
            : controller.text;
        target?.onSubmitted?.call(value);
      }
      SecureKeyboard.hide();
      return;
    }
    if (key == _symbolsKey || key == _lettersKey) {
      _toggleSymbols();
      return;
    }

    var output = key;
    if (!_symbols && _isLetterKey(key) && (_shift || _capsLock)) {
      output = key.toUpperCase();
    }
    _insertText(output);
    if (!_symbols && _shift && !_capsLock) {
      setState(() => _shift = false);
    }
  }

  void _startBackspaceHold() {
    _cancelBackspaceTimers();
    _backspaceRepeating = false;
    _backspaceHoldTimer = Timer(const Duration(milliseconds: 500), () {
      _backspaceRepeating = true;
      _backspaceRepeatTimer = Timer.periodic(
        const Duration(milliseconds: 60),
        (_) => _backspace(),
      );
    });
  }

  void _stopBackspaceHold({required bool applySingle}) {
    final wasRepeating = _backspaceRepeating;
    _cancelBackspaceTimers();
    if (applySingle && !wasRepeating) {
      _backspace();
    }
  }

  void _cancelBackspaceTimers() {
    _backspaceHoldTimer?.cancel();
    _backspaceRepeatTimer?.cancel();
    _backspaceHoldTimer = null;
    _backspaceRepeatTimer = null;
    _backspaceRepeating = false;
  }

  bool _isLetterKey(String key) {
    return key.length == 1 &&
        key.codeUnitAt(0) >= 97 &&
        key.codeUnitAt(0) <= 122;
  }

  List<List<String>> get _layout {
    if (!_symbols) return _letterLayout;
    return _symbolShift ? _symbolLayoutAlt : _symbolLayout;
  }

  int _keyFlex(String key) {
    if (key == _spaceKey) return 5;
    if (key == _shiftKey || key == _backspaceKey) return 2;
    if (key == _symbolsKey || key == _lettersKey || key == _enterKey) return 2;
    return 1;
  }

  Widget _buildKey(String key) {
    final isAction = key.startsWith('_');
    final flex = _keyFlex(key);
    final isShiftKey = key == _shiftKey;
    final isActiveShift = !_symbols && (isShiftKey && (_shift || _capsLock));
    final isActiveSymbolShift = _symbols && isShiftKey && _symbolShift;
    final bgColor = (isActiveShift || isActiveSymbolShift)
        ? CyberpunkTheme.neonGreen.withOpacity(0.2)
        : (isAction ? CyberpunkTheme.surfaceLight : CyberpunkTheme.surface);

    if (key == _backspaceKey) {
      return Expanded(
        flex: flex,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: _keyGap, vertical: 3),
          child: Material(
            color: bgColor,
            borderRadius: BorderRadius.circular(_keyRadius),
            child: InkWell(
              borderRadius: BorderRadius.circular(_keyRadius),
              onTapDown: (_) => _startBackspaceHold(),
              onTapUp: (_) => _stopBackspaceHold(applySingle: true),
              onTapCancel: () => _stopBackspaceHold(applySingle: false),
              child: const SizedBox(
                height: _keyHeight,
                child: Center(
                  child: Icon(Icons.backspace,
                      color: CyberpunkTheme.textPrimary, size: 20),
                ),
              ),
            ),
          ),
        ),
      );
    }

    Widget label;
    if (key == _shiftKey) {
      label = Icon(Icons.keyboard_arrow_up, color: CyberpunkTheme.textPrimary);
    } else if (key == _spaceKey) {
      label = const Text('SPACE',
          style: TextStyle(color: CyberpunkTheme.textSecondary));
    } else if (key == _enterKey) {
      label = const Icon(Icons.keyboard_return,
          color: CyberpunkTheme.neonGreen, size: 20);
    } else if (key == _symbolsKey) {
      label = const Text('?123',
          style: TextStyle(color: CyberpunkTheme.textPrimary));
    } else if (key == _lettersKey) {
      label = const Text('ABC',
          style: TextStyle(color: CyberpunkTheme.textPrimary));
    } else {
      final display = !_symbols && _isLetterKey(key) && (_shift || _capsLock)
          ? key.toUpperCase()
          : key;
      label = Text(
        display,
        style: const TextStyle(
          color: CyberpunkTheme.textPrimary,
          fontSize: 18,
          fontWeight: FontWeight.w600,
        ),
      );
    }

    return Expanded(
      flex: flex,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: _keyGap, vertical: 3),
        child: Material(
          color: bgColor,
          borderRadius: BorderRadius.circular(_keyRadius),
          child: InkWell(
            borderRadius: BorderRadius.circular(_keyRadius),
            onTap: () => _handleKey(key),
            child: SizedBox(
              height: _keyHeight,
              child: Center(child: label),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildRow(List<String> keys) {
    return Row(
      children: keys.map(_buildKey).toList(),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(8, 6, 8, 10),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Row(
            children: [
              const Icon(Icons.security,
                  color: CyberpunkTheme.neonGreen, size: 14),
              const SizedBox(width: 4),
              const Text(
                'Secure Keyboard',
                style: TextStyle(
                  color: CyberpunkTheme.textSecondary,
                  fontWeight: FontWeight.w500,
                  fontSize: 12,
                ),
              ),
              const Spacer(),
              GestureDetector(
                onTap: () => SecureKeyboard.hide(),
                child: const Padding(
                  padding: EdgeInsets.all(4),
                  child: Icon(Icons.keyboard_hide,
                      color: CyberpunkTheme.textSecondary, size: 18),
                ),
              ),
            ],
          ),
          const SizedBox(height: 4),
          for (final row in _layout) _buildRow(row),
        ],
      ),
    );
  }
}

class _SecureInputBuffer {
  final Uint8List bytes = Uint8List(SecureKeyboard._maxInputBytes);
  int length = 0;
  bool obscured = true;

  int get characterCount {
    var count = 0;
    for (var i = 0; i < length; i++) {
      if ((bytes[i] & 0xc0) != 0x80) count++;
    }
    return count;
  }
}

class _KeyboardTarget {
  final TextEditingController controller;
  final bool secureInput;
  final ValueChanged<String>? onChanged;
  final ValueChanged<String>? onSubmitted;

  const _KeyboardTarget({
    required this.controller,
    required this.secureInput,
    this.onChanged,
    this.onSubmitted,
  });
}

class SecureKeyboardHost extends StatefulWidget {
  final Widget child;

  const SecureKeyboardHost({super.key, required this.child});

  @override
  State<SecureKeyboardHost> createState() => _SecureKeyboardHostState();
}

class _SecureKeyboardHostState extends State<SecureKeyboardHost> {
  final GlobalKey _keyboardKey = GlobalKey();

  @override
  void initState() {
    super.initState();
    SecureKeyboard.visible.addListener(_scheduleInsetUpdate);
  }

  @override
  void dispose() {
    SecureKeyboard.visible.removeListener(_scheduleInsetUpdate);
    super.dispose();
  }

  void _scheduleInsetUpdate() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final visible = SecureKeyboard.visible.value;
      if (!visible) {
        if (SecureKeyboard.inset.value != 0) {
          SecureKeyboard.inset.value = 0;
        }
        return;
      }
      final box = _keyboardKey.currentContext?.findRenderObject() as RenderBox?;
      if (box == null) return;
      final height = box.size.height;
      if (height > 0 && SecureKeyboard.inset.value != height) {
        SecureKeyboard.inset.value = height;
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return WillPopScope(
      onWillPop: () async {
        if (SecureKeyboard.visible.value) {
          SecureKeyboard.hide();
          return false;
        }
        return true;
      },
      child: Stack(
        children: [
          ValueListenableBuilder<double>(
            valueListenable: SecureKeyboard.inset,
            builder: (context, inset, child) {
              return AnimatedPadding(
                duration: const Duration(milliseconds: 220),
                curve: Curves.easeOut,
                padding: EdgeInsets.only(bottom: inset),
                child: child,
              );
            },
            child: widget.child,
          ),
          ValueListenableBuilder<bool>(
            valueListenable: SecureKeyboard.visible,
            builder: (context, visible, _) {
              return IgnorePointer(
                ignoring: !visible,
                child: AnimatedSlide(
                  duration: const Duration(milliseconds: 220),
                  curve: Curves.easeOut,
                  offset: visible ? Offset.zero : const Offset(0, 1),
                  child: Align(
                    alignment: Alignment.bottomCenter,
                    child: Material(
                      key: _keyboardKey,
                      color: CyberpunkTheme.surface,
                      borderRadius:
                          const BorderRadius.vertical(top: Radius.circular(18)),
                      elevation: 8,
                      child: SecureKeyboardSheet(target: SecureKeyboard.target),
                    ),
                  ),
                ),
              );
            },
          ),
        ],
      ),
    );
  }
}
