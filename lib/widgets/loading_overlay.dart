/// LoadingOverlay - Full-Screen Loading Indicator
/// 
/// A modal overlay that blocks user interaction during long-running
/// operations. Displays a cyberpunk-styled loading indicator with
/// optional progress percentage and message.
/// 
/// Features:
/// - Semi-transparent backdrop
/// - Circular progress indicator (determinate or indeterminate)
/// - Optional progress percentage display
/// - Optional status message
/// - Neon glow effect on the loading card

import 'package:flutter/material.dart';
import '../theme/cyberpunk_theme.dart';

/// Global loading overlay with cyberpunk styling.
/// 
/// Example usage:
/// ```dart
/// LoadingOverlay(
///   isLoading: isImporting,
///   message: 'Importing files...',
///   progress: importProgress,
///   child: YourContent(),
/// )
/// ```
class LoadingOverlay extends StatelessWidget {
  final bool isLoading;
  final Widget child;
  final String? message;
  final double? progress;

  const LoadingOverlay({
    super.key,
    required this.isLoading,
    required this.child,
    this.message,
    this.progress,
  });

  @override
  Widget build(BuildContext context) {
    final hasProgress = progress != null;
    final normalized = (progress ?? 0).clamp(0.0, 1.0);
    final percentText = '${(normalized * 100).round()}%';

    return Stack(
      children: [
        child,
        if (isLoading)
          Material(
            color: Colors.transparent,
            child: Container(
              color: Colors.black.withOpacity(0.7),
              child: Center(
                child: Container(
                  padding: const EdgeInsets.all(24),
                  decoration: BoxDecoration(
                    color: CyberpunkTheme.surface,
                    borderRadius: BorderRadius.circular(16),
                    border: Border.all(
                      color: CyberpunkTheme.neonGreen.withOpacity(0.3),
                    ),
                    boxShadow: [
                      BoxShadow(
                        color: CyberpunkTheme.neonGreen.withOpacity(0.2),
                        blurRadius: 30,
                        spreadRadius: 5,
                      ),
                    ],
                  ),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      SizedBox(
                        width: 64,
                        height: 64,
                        child: Stack(
                          alignment: Alignment.center,
                          children: [
                            CircularProgressIndicator(
                              strokeWidth: 3,
                              value: hasProgress ? normalized : null,
                              valueColor: const AlwaysStoppedAnimation<Color>(
                                CyberpunkTheme.neonGreen,
                              ),
                              backgroundColor: CyberpunkTheme.surfaceBorder,
                            ),
                            if (hasProgress)
                              Text(
                                percentText,
                                style: const TextStyle(
                                  color: CyberpunkTheme.textPrimary,
                                  fontSize: 12,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                          ],
                        ),
                      ),
                      if (message != null) ...[
                        const SizedBox(height: 16),
                        Text(
                          message!,
                          style: const TextStyle(
                            color: CyberpunkTheme.textSecondary,
                            fontSize: 14,
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ],
                    ],
                  ),
                ),
              ),
            ),
          ),
      ],
    );
  }
}

/// Show a loading dialog
Future<void> showLoadingDialog(BuildContext context, {String? message}) {
  return showDialog(
    context: context,
    barrierDismissible: false,
    barrierColor: Colors.black.withOpacity(0.7),
    builder: (context) => WillPopScope(
      onWillPop: () async => false,
      child: Center(
        child: Container(
          padding: const EdgeInsets.all(24),
          decoration: BoxDecoration(
            color: CyberpunkTheme.surface,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(
              color: CyberpunkTheme.neonGreen.withOpacity(0.3),
            ),
            boxShadow: [
              BoxShadow(
                color: CyberpunkTheme.neonGreen.withOpacity(0.2),
                blurRadius: 30,
                spreadRadius: 5,
              ),
            ],
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const SizedBox(
                width: 48,
                height: 48,
                child: CircularProgressIndicator(
                  strokeWidth: 3,
                  valueColor: AlwaysStoppedAnimation<Color>(
                    CyberpunkTheme.neonGreen,
                  ),
                ),
              ),
              if (message != null) ...[
                const SizedBox(height: 16),
                Text(
                  message,
                  style: const TextStyle(
                    color: CyberpunkTheme.textSecondary,
                    fontSize: 14,
                  ),
                  textAlign: TextAlign.center,
                ),
              ],
            ],
          ),
        ),
      ),
    ),
  );
}

/// Hide loading dialog
void hideLoadingDialog(BuildContext context) {
  Navigator.of(context, rootNavigator: true).pop();
}
