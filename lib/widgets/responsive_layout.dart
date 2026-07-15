import 'package:flutter/material.dart';

import '../theme/cyberpunk_theme.dart';

class ResponsiveFrame extends StatelessWidget {
  static const maxWidth = 720.0;

  final Widget child;

  const ResponsiveFrame({super.key, required this.child});

  @override
  Widget build(BuildContext context) {
    return ColoredBox(
      color: CyberpunkTheme.background,
      child: Align(
        alignment: Alignment.topCenter,
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: maxWidth),
          child: SizedBox.expand(child: child),
        ),
      ),
    );
  }
}

class ResponsiveScrollView extends StatelessWidget {
  final EdgeInsetsGeometry padding;
  final Widget child;

  const ResponsiveScrollView({
    super.key,
    this.padding = EdgeInsets.zero,
    required this.child,
  });

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final resolvedPadding = padding.resolve(Directionality.of(context));
        final availableHeight =
            constraints.maxHeight - resolvedPadding.vertical;
        return SingleChildScrollView(
          padding: resolvedPadding,
          child: ConstrainedBox(
            constraints: BoxConstraints(
              minHeight: availableHeight > 0 ? availableHeight : 0,
            ),
            child: Center(child: child),
          ),
        );
      },
    );
  }
}
