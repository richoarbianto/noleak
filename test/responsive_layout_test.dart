import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:noleak/screens/app_lock_screen.dart';
import 'package:noleak/screens/vault_info_screen.dart';
import 'package:noleak/theme/cyberpunk_theme.dart';
import 'package:noleak/widgets/responsive_layout.dart';

void main() {
  testWidgets('layout scrolls on compact screens and caps tablet width',
      (tester) async {
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);

    tester.view.physicalSize = const Size(320, 360);
    await tester.pumpWidget(
      MaterialApp(
        theme: CyberpunkTheme.themeData,
        builder: (context, child) => ResponsiveFrame(child: child!),
        home: AppLockScreen(onRetry: () async => false),
      ),
    );
    expect(tester.takeException(), isNull);
    expect(find.byType(SingleChildScrollView), findsOneWidget);

    tester.view.physicalSize = const Size(1200, 800);
    await tester.pumpWidget(
      MaterialApp(
        builder: (context, child) => ResponsiveFrame(child: child!),
        home: const SizedBox.expand(key: Key('content')),
      ),
    );
    await tester.pump();
    expect(tester.getSize(find.byKey(const Key('content'))).width, 720);
  });

  testWidgets('security info presents the native KDF profile clearly',
      (tester) async {
    const channel = MethodChannel('com.noleak.vault');
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'getKdfInfo') {
        return <String, Object>{
          'memoryMiB': 256,
          'opslimit': 3,
          'parallelism': 1,
          'storedParallelism': 1,
          'storedProfile': false,
        };
      }
      return null;
    });
    addTearDown(() => messenger.setMockMethodCallHandler(channel, null));
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(320, 640);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);

    await tester.pumpWidget(
      MaterialApp(
        theme: CyberpunkTheme.themeData,
        home: const VaultInfoScreen(),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('Security Advantages'), findsOneWidget);

    await tester.tap(find.text('Cryptography'));
    await tester.pump();
    expect(find.text('256 MB'), findsOneWidget);
    expect(find.textContaining('Next new vault'), findsNothing);

    await tester.tap(find.text('Protection'));
    await tester.pump();
    expect(find.text('Important Limits'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}
