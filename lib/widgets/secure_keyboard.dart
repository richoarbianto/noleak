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
/// - Supports UTF-8-safe cursor navigation and editing
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
    _captureSelection(controller, input);
    input.obscured = obscureText;
    _renderSecureInput(controller, input);
  }

  static void clearInput(TextEditingController controller) {
    final input = _inputs[controller];
    if (input == null) return;
    input.bytes.fillRange(0, input.bytes.length, 0);
    input.length = 0;
    input.cursor = 0;
    _inputs[controller] = null;
  }

  static void _prepareInput(
      TextEditingController controller, bool obscureText) {
    final prepared = _inputs[controller];
    if (prepared != null) {
      _captureSelection(controller, prepared);
      prepared.obscured = obscureText;
      _renderSecureInput(controller, prepared);
      return;
    }
    final input = _SecureInputBuffer();
    final existing = utf8.encode(controller.text);
    input.length = existing.length.clamp(0, _maxInputBytes);
    input.bytes.setRange(0, input.length, existing);
    input.cursor = _byteOffsetForDisplayOffset(
      controller.text,
      controller.selection.isValid
          ? controller.selection.extentOffset
          : controller.text.length,
    ).clamp(0, input.length);
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
      selection: TextSelection.collapsed(
        offset: input.obscured
            ? input.characterCountBeforeCursor
            : utf8
                .decode(Uint8List.sublistView(input.bytes, 0, input.cursor))
                .length,
      ),
    );
  }

  static void _captureSelection(
      TextEditingController controller, _SecureInputBuffer input) {
    final selection = controller.selection;
    if (!selection.isValid) return;
    if (input.obscured) {
      input.cursor = input.byteOffsetForCharacter(
        selection.extentOffset.clamp(0, input.characterCount),
      );
      return;
    }
    input.cursor = _byteOffsetForDisplayOffset(
      controller.text,
      selection.extentOffset,
    ).clamp(0, input.length);
  }

  static int _byteOffsetForDisplayOffset(String value, int displayOffset) {
    final target = displayOffset.clamp(0, value.length);
    var codeUnits = 0;
    var bytes = 0;
    for (final rune in value.runes) {
      final character = String.fromCharCode(rune);
      if (codeUnits + character.length > target) break;
      codeUnits += character.length;
      bytes += utf8.encode(character).length;
    }
    return bytes;
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
  static const _cursorLeftKey = '_cursor_left';
  static const _cursorRightKey = '_cursor_right';

  static const _letterLayout = [
    ['q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p'],
    ['a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l'],
    [_shiftKey, 'z', 'x', 'c', 'v', 'b', 'n', 'm', _backspaceKey],
    [_symbolsKey, _cursorLeftKey, _spaceKey, _cursorRightKey, _enterKey],
  ];

  static const _symbolLayout = [
    ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'],
    ['@', '#', r'$', '%', '&', '*', '-', '+', '(', ')'],
    [_shiftKey, '!', '"', "'", ':', ';', '/', '?', _backspaceKey],
    [_lettersKey, _cursorLeftKey, _spaceKey, _cursorRightKey, _enterKey],
  ];

  static const _symbolLayoutAlt = [
    ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'],
    ['[', ']', '{', '}', '<', '>', '=', '_', '\\', '|'],
    [_shiftKey, '~', '`', '^', '.', ',', ':', ';', _backspaceKey],
    [_lettersKey, _cursorLeftKey, _spaceKey, _cursorRightKey, _enterKey],
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
      final selection = controller.selection;
      final start =
          selection.isValid ? selection.start : controller.text.length;
      final end = selection.isValid ? selection.end : controller.text.length;
      final updated = controller.text.replaceRange(start, end, value);
      controller.value = TextEditingValue(
        text: updated,
        selection: TextSelection.collapsed(offset: start + value.length),
      );
      _emitChanged();
      return;
    }
    final input = SecureKeyboard._inputs[controller];
    if (input == null) return;
    SecureKeyboard._captureSelection(controller, input);
    final encoded = utf8.encode(value);
    if (input.length + encoded.length > SecureKeyboard._maxInputBytes) {
      encoded.fillRange(0, encoded.length, 0);
      return;
    }
    for (var i = input.length - 1; i >= input.cursor; i--) {
      input.bytes[i + encoded.length] = input.bytes[i];
    }
    input.bytes.setRange(input.cursor, input.cursor + encoded.length, encoded);
    input.length += encoded.length;
    input.cursor += encoded.length;
    encoded.fillRange(0, encoded.length, 0);
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
      final selection = controller.selection;
      final end = selection.isValid ? selection.end : current.length;
      var start = selection.isValid ? selection.start : current.length;
      if (start == end) {
        if (start == 0) return;
        start = _previousCodePointOffset(current, start);
      }
      final updated = current.replaceRange(start, end, '');
      controller.value = TextEditingValue(
        text: updated,
        selection: TextSelection.collapsed(offset: start),
      );
      _emitChanged();
      return;
    }
    final input = SecureKeyboard._inputs[controller];
    if (input == null) return;
    SecureKeyboard._captureSelection(controller, input);
    if (input.cursor == 0) return;
    final oldLength = input.length;
    final deletedEnd = input.cursor;
    var deletedStart = deletedEnd - 1;
    while (deletedStart > 0 && (input.bytes[deletedStart] & 0xc0) == 0x80) {
      deletedStart--;
    }
    final deletedLength = deletedEnd - deletedStart;
    for (var i = deletedEnd; i < oldLength; i++) {
      input.bytes[i - deletedLength] = input.bytes[i];
    }
    input.length -= deletedLength;
    input.cursor = deletedStart;
    input.bytes.fillRange(input.length, oldLength, 0);
    SecureKeyboard._renderSecureInput(controller, input);
    _emitChanged();
  }

  int _previousCodePointOffset(String value, int offset) {
    if (offset <= 0) return 0;
    var result = offset - 1;
    if (result > 0) {
      final current = value.codeUnitAt(result);
      final previous = value.codeUnitAt(result - 1);
      if (current >= 0xdc00 &&
          current <= 0xdfff &&
          previous >= 0xd800 &&
          previous <= 0xdbff) {
        result--;
      }
    }
    return result;
  }

  int _nextCodePointOffset(String value, int offset) {
    if (offset >= value.length) return value.length;
    final current = value.codeUnitAt(offset);
    if (current >= 0xd800 && current <= 0xdbff && offset + 1 < value.length) {
      final next = value.codeUnitAt(offset + 1);
      if (next >= 0xdc00 && next <= 0xdfff) return offset + 2;
    }
    return offset + 1;
  }

  void _moveCursor({required bool left}) {
    final controller = _controller;
    final target = _activeTarget;
    if (controller == null || target == null) return;

    if (!target.secureInput) {
      final selection = controller.selection;
      var offset =
          selection.isValid ? selection.extentOffset : controller.text.length;
      if (!selection.isCollapsed) {
        offset = left ? selection.start : selection.end;
      } else {
        offset = left
            ? _previousCodePointOffset(controller.text, offset)
            : _nextCodePointOffset(controller.text, offset);
      }
      controller.selection = TextSelection.collapsed(offset: offset);
      return;
    }

    final input = SecureKeyboard._inputs[controller];
    if (input == null) return;
    SecureKeyboard._captureSelection(controller, input);
    if (left) {
      if (input.cursor == 0) return;
      input.cursor--;
      while (input.cursor > 0 && (input.bytes[input.cursor] & 0xc0) == 0x80) {
        input.cursor--;
      }
    } else {
      if (input.cursor >= input.length) return;
      input.cursor++;
      while (input.cursor < input.length &&
          (input.bytes[input.cursor] & 0xc0) == 0x80) {
        input.cursor++;
      }
    }
    SecureKeyboard._renderSecureInput(controller, input);
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
    if (key == _cursorLeftKey || key == _cursorRightKey) {
      _moveCursor(left: key == _cursorLeftKey);
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
      label = const Icon(Icons.keyboard_arrow_up,
          color: CyberpunkTheme.textPrimary);
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
    } else if (key == _cursorLeftKey) {
      label = const Icon(Icons.keyboard_arrow_left,
          color: CyberpunkTheme.textPrimary, size: 22);
    } else if (key == _cursorRightKey) {
      label = const Icon(Icons.keyboard_arrow_right,
          color: CyberpunkTheme.textPrimary, size: 22);
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
  int cursor = 0;
  bool obscured = true;

  int get characterCount {
    var count = 0;
    for (var i = 0; i < length; i++) {
      if ((bytes[i] & 0xc0) != 0x80) count++;
    }
    return count;
  }

  int get characterCountBeforeCursor {
    var count = 0;
    for (var i = 0; i < cursor; i++) {
      if ((bytes[i] & 0xc0) != 0x80) count++;
    }
    return count;
  }

  int byteOffsetForCharacter(int characterOffset) {
    if (characterOffset <= 0) return 0;
    var count = 0;
    for (var i = 0; i < length; i++) {
      if ((bytes[i] & 0xc0) == 0x80) continue;
      if (count == characterOffset) return i;
      count++;
    }
    return length;
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
