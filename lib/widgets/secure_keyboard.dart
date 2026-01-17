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

import 'package:flutter/material.dart';
import '../theme/cyberpunk_theme.dart';

/// Static controller for the secure keyboard.
/// 
/// Provides methods to show/hide the keyboard and manages the
/// current target text field. Uses ValueNotifiers for reactive
/// state management.
class SecureKeyboard {
  static const double _fallbackInset = 300;
  static final ValueNotifier<_KeyboardTarget?> _target = ValueNotifier(null);
  static final ValueNotifier<bool> _visible = ValueNotifier(false);
  static final ValueNotifier<double> _inset = ValueNotifier(0);

  static ValueNotifier<_KeyboardTarget?> get target => _target;
  static ValueNotifier<bool> get visible => _visible;
  static ValueNotifier<double> get inset => _inset;

  static void show(
    BuildContext context, {
    required TextEditingController controller,
    ValueChanged<String>? onChanged,
    ValueChanged<String>? onSubmitted,
  }) {
    _target.value = _KeyboardTarget(
      controller: controller,
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
    [_shiftKey, '!', '"', "'", ':', ';', '.', '?', _backspaceKey],
    [_lettersKey, ',', _spaceKey, '/', _enterKey],
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
  }

  @override
  void dispose() {
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
  }

  TextEditingController? get _controller => _activeTarget?.controller;

  void _emitChanged() {
    final controller = _controller;
    if (controller == null) return;
    _activeTarget?.onChanged?.call(controller.text);
  }

  TextSelection _normalizeSelection(TextSelection selection, int textLength) {
    var start = selection.start;
    var end = selection.end;
    if (start < 0 || end < 0) {
      start = textLength;
      end = textLength;
    }
    if (start > textLength) start = textLength;
    if (end > textLength) end = textLength;
    if (start > end) {
      final tmp = start;
      start = end;
      end = tmp;
    }
    return TextSelection(baseOffset: start, extentOffset: end);
  }

  void _insertText(String value) {
    final controller = _controller;
    if (controller == null) return;
    final current = controller.text;
    final selection = _normalizeSelection(controller.selection, current.length);
    final updated = current.replaceRange(selection.start, selection.end, value);
    final newOffset = selection.start + value.length;
    controller.value = controller.value.copyWith(
      text: updated,
      selection: TextSelection.collapsed(offset: newOffset),
      composing: TextRange.empty,
    );
    _emitChanged();
  }

  void _backspace() {
    final controller = _controller;
    if (controller == null) return;
    final current = controller.text;
    if (current.isEmpty) return;
    final selection = _normalizeSelection(controller.selection, current.length);
    if (selection.start != selection.end) {
      final updated = current.replaceRange(selection.start, selection.end, '');
      controller.value = controller.value.copyWith(
        text: updated,
        selection: TextSelection.collapsed(offset: selection.start),
        composing: TextRange.empty,
      );
      _emitChanged();
      return;
    }
    if (selection.start <= 0) return;
    final updated = current.replaceRange(selection.start - 1, selection.start, '');
    final newOffset = selection.start - 1;
    controller.value = controller.value.copyWith(
      text: updated,
      selection: TextSelection.collapsed(offset: newOffset),
      composing: TextRange.empty,
    );
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
        _activeTarget?.onSubmitted?.call(controller.text);
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
    return key.length == 1 && key.codeUnitAt(0) >= 97 && key.codeUnitAt(0) <= 122;
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
          padding: const EdgeInsets.symmetric(horizontal: 3, vertical: 4),
          child: Material(
            color: bgColor,
            borderRadius: BorderRadius.circular(10),
            child: InkWell(
              borderRadius: BorderRadius.circular(10),
              onTapDown: (_) => _startBackspaceHold(),
              onTapUp: (_) => _stopBackspaceHold(applySingle: true),
              onTapCancel: () => _stopBackspaceHold(applySingle: false),
              child: const SizedBox(
                height: 48,
                child: Center(
                  child: Icon(Icons.backspace, color: CyberpunkTheme.textPrimary, size: 20),
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
      label = const Text('SPACE', style: TextStyle(color: CyberpunkTheme.textSecondary));
    } else if (key == _enterKey) {
      label = const Icon(Icons.keyboard_return, color: CyberpunkTheme.neonGreen, size: 20);
    } else if (key == _symbolsKey) {
      label = const Text('?123', style: TextStyle(color: CyberpunkTheme.textPrimary));
    } else if (key == _lettersKey) {
      label = const Text('ABC', style: TextStyle(color: CyberpunkTheme.textPrimary));
    } else {
      final display = !_symbols && _isLetterKey(key) && (_shift || _capsLock)
          ? key.toUpperCase()
          : key;
      label = Text(
        display,
        style: const TextStyle(
          color: CyberpunkTheme.textPrimary,
          fontSize: 16,
          fontWeight: FontWeight.w500,
        ),
      );
    }

    return Expanded(
      flex: flex,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 3, vertical: 4),
        child: Material(
          color: bgColor,
          borderRadius: BorderRadius.circular(10),
          child: InkWell(
            borderRadius: BorderRadius.circular(10),
            onTap: () => _handleKey(key),
            child: SizedBox(
              height: 48,
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
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 12),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Row(
            children: [
              const Icon(Icons.security, color: CyberpunkTheme.neonGreen, size: 14),
              const SizedBox(width: 4),
              const Text(
                'Secure Keyboard',
                style: TextStyle(
                  color: CyberpunkTheme.textSecondary,
                  fontWeight: FontWeight.w500,
                  fontSize: 11,
                ),
              ),
              const Spacer(),
              GestureDetector(
                onTap: () => SecureKeyboard.hide(),
                child: const Padding(
                  padding: EdgeInsets.all(4),
                  child: Icon(Icons.keyboard_hide, color: CyberpunkTheme.textSecondary, size: 18),
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          for (final row in _layout) _buildRow(row),
        ],
      ),
    );
  }
}

class _KeyboardTarget {
  final TextEditingController controller;
  final ValueChanged<String>? onChanged;
  final ValueChanged<String>? onSubmitted;

  const _KeyboardTarget({
    required this.controller,
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
    final bottomPadding = MediaQuery.of(context).padding.bottom;
    
    return Stack(
      children: [
        ValueListenableBuilder<double>(
          valueListenable: SecureKeyboard.inset,
          builder: (context, inset, child) {
            return Padding(
              padding: EdgeInsets.only(bottom: inset),
              child: child,
            );
          },
          child: widget.child,
        ),
        ValueListenableBuilder<bool>(
          valueListenable: SecureKeyboard.visible,
          builder: (context, visible, _) {
            if (!visible) return const SizedBox.shrink();
            return Positioned(
              left: 0,
              right: 0,
              bottom: 0,
              child: Material(
                key: _keyboardKey,
                color: CyberpunkTheme.surface,
                borderRadius: const BorderRadius.vertical(top: Radius.circular(18)),
                elevation: 8,
                child: Padding(
                  padding: EdgeInsets.only(bottom: bottomPadding),
                  child: SecureKeyboardSheet(target: SecureKeyboard.target),
                ),
              ),
            );
          },
        ),
      ],
    );
  }
}
