import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:noleak/services/vault_channel.dart';
import 'package:noleak/screens/text_viewer_screen.dart';
import 'package:noleak/utils/secure_passphrase.dart';
import 'package:noleak/widgets/secure_keyboard.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('passphrases use canonical UTF-8 bytes on MethodChannel', () async {
    const channel = MethodChannel('com.noleak.vault');
    MethodCall? received;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      received = call;
      return true;
    });

    final bytes = SecurePassphrase.toSecureBytes('kata sandi 🔐 123!');
    try {
      await VaultChannel.openVault(bytes);
      final sent = (received!.arguments as Map)['passphrase'];
      expect(sent, isA<Uint8List>());
      expect(sent, utf8.encode('kata sandi 🔐 123!'));
    } finally {
      SecurePassphrase.zeroize(bytes);
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null);
    }
  });

  test('rate-limit errors are not flattened into wrong-password results',
      () async {
    const channel = MethodChannel('com.noleak.vault');
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(channel, (_) async {
      throw PlatformException(
        code: 'RATE_LIMITED',
        message: 'Try again later',
        details: const {'remainingSeconds': 60},
      );
    });
    final bytes = Uint8List.fromList(List.filled(12, 0x61));
    try {
      await expectLater(
        VaultChannel.verifyPassword(bytes),
        throwsA(isA<PlatformException>().having(
          (error) => error.code,
          'code',
          'RATE_LIMITED',
        )),
      );
    } finally {
      SecurePassphrase.zeroize(bytes);
      messenger.setMockMethodCallHandler(channel, null);
    }
  });

  test('vault import returns KDF compatibility metadata', () async {
    const channel = MethodChannel('com.noleak.vault');
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(
        channel,
        (_) async => {
              'id': 'vault-id',
              'kdfMemoryMiB': 256,
              'deviceKdfMemoryMiB': 128,
              'kdfOpslimit': 3,
              'deviceKdfOpslimit': 3,
              'kdfExceedsDevice': true,
            });
    addTearDown(() => messenger.setMockMethodCallHandler(channel, null));

    final result = await VaultChannel.importVaultFromUri('content://vault');
    expect(result?['kdfExceedsDevice'], isTrue);
    expect(result?['kdfMemoryMiB'], 256);
  });

  test('vault import errors are visible to the caller', () async {
    const channel = MethodChannel('com.noleak.vault');
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(channel, (_) async {
      throw PlatformException(
        code: 'IMPORT_FAILED',
        message: 'Vault file is invalid or corrupted',
      );
    });
    addTearDown(() => messenger.setMockMethodCallHandler(channel, null));

    await expectLater(
      VaultChannel.importVaultFromUri('content://vault'),
      throwsA(isA<PlatformException>().having(
        (error) => error.code,
        'code',
        'IMPORT_FAILED',
      )),
    );
  });

  test('raw preview is sanitized, bounded, and keeps Unicode intact', () {
    final bytes = Uint8List.fromList([
      ...utf8.encode('start\u0000\u202e'),
      ...utf8.encode(List.filled(5000, '🔐').join()),
    ]);
    final preview = buildSafeRawPreview(bytes);

    expect(preview.runes.length, rawPreviewMaxCharacters);
    expect(preview, startsWith('start��'));
    expect(preview, isNot(contains('\u0000')));
    expect(preview, isNot(contains('\u202e')));
    expect(preview.runes.last, 0x1f510);
  });

  testWidgets('secure keyboard reveals input only while requested',
      (tester) async {
    final controller = TextEditingController(text: 'Secret123!');
    addTearDown(controller.dispose);
    late BuildContext context;
    await tester.pumpWidget(MaterialApp(
      home: Builder(builder: (value) {
        context = value;
        return const SizedBox();
      }),
    ));

    SecureKeyboard.show(
      context,
      controller: controller,
      secureInput: true,
    );
    expect(controller.text, isNot(contains('Secret')));

    SecureKeyboard.setObscured(controller, false);
    expect(controller.text, 'Secret123!');

    SecureKeyboard.setObscured(controller, true);
    expect(controller.text, isNot(contains('Secret')));

    final bytes = SecureKeyboard.copyInput(controller)!;
    expect(bytes, utf8.encode('Secret123!'));
    SecurePassphrase.zeroize(bytes);
    SecurePassphrase.clearController(controller);
    expect(controller.text, isEmpty);
    SecureKeyboard.hide();
    await tester.pump();
  });

  testWidgets('secure keyboard keeps normal form input readable',
      (tester) async {
    final controller = TextEditingController(text: 'Folder name');
    addTearDown(controller.dispose);
    late BuildContext context;
    await tester.pumpWidget(MaterialApp(
      home: Builder(builder: (value) {
        context = value;
        return const SizedBox();
      }),
    ));

    SecureKeyboard.show(context, controller: controller);
    expect(controller.text, 'Folder name');
    expect(SecureKeyboard.copyInput(controller), isNull);

    SecureKeyboard.hide();
    await tester.pump();
  });

  testWidgets('secure keyboard backspace removes a complete UTF-8 character',
      (tester) async {
    final controller = TextEditingController(text: '🔐a');
    addTearDown(controller.dispose);
    late BuildContext context;
    await tester.pumpWidget(MaterialApp(
      home: SecureKeyboardHost(
        child: Builder(builder: (value) {
          context = value;
          return const SizedBox();
        }),
      ),
    ));

    SecureKeyboard.show(
      context,
      controller: controller,
      secureInput: true,
    );
    await tester.pump();
    await tester.pumpAndSettle();

    await tester.tap(find.byIcon(Icons.backspace));
    await tester.pump();
    final afterAscii = SecureKeyboard.copyInput(controller)!;
    expect(afterAscii, utf8.encode('🔐'));
    SecurePassphrase.zeroize(afterAscii);

    await tester.tap(find.byIcon(Icons.backspace));
    await tester.pump();
    final empty = SecureKeyboard.copyInput(controller)!;
    expect(empty, isEmpty);
    SecurePassphrase.zeroize(empty);

    SecurePassphrase.clearController(controller);
    SecureKeyboard.hide();
    await tester.pump();
  });
}
