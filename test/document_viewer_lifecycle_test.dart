import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:noleak/models/vault_state.dart';
import 'package:noleak/screens/document_viewer_screen.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('PDF page buffers are zeroized on replacement and dispose',
      (tester) async {
    const channel = MethodChannel('com.noleak.vault');
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    final markerPng = base64Decode(
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
    );
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'checkEnvironment') return {'ok': true};
      if (call.method == 'renderPdfPage') {
        final pageIndex = (call.arguments as Map)['pageIndex'] as int;
        return {
          'png': Uint8List.fromList(markerPng),
          'pageIndex': pageIndex,
          'pageCount': 2,
        };
      }
      throw PlatformException(code: 'UNEXPECTED_METHOD');
    });
    addTearDown(() => messenger.setMockMethodCallHandler(channel, null));

    final entry = VaultEntry(
      fileId: List<int>.filled(16, 1),
      name: 'marker.pdf',
      type: 1,
      size: markerPng.length,
      createdAt: DateTime.fromMillisecondsSinceEpoch(0),
      mimeType: 'application/pdf',
    );
    await tester
        .pumpWidget(MaterialApp(home: DocumentViewerScreen(entry: entry)));
    await tester.pumpAndSettle();

    final firstPage =
        (tester.widget<Image>(find.byType(Image)).image as MemoryImage).bytes;
    expect(firstPage, contains(isNot(0)));

    await tester.tap(find.byIcon(Icons.chevron_right));
    await tester.pumpAndSettle();
    expect(firstPage, everyElement(0));

    final secondPage =
        (tester.widget<Image>(find.byType(Image)).image as MemoryImage).bytes;
    expect(secondPage, contains(isNot(0)));

    await tester.pumpWidget(const MaterialApp(home: SizedBox()));
    await tester.pump();
    expect(secondPage, everyElement(0));
  });
}
