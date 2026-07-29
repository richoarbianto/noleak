import 'dart:convert';
import 'dart:typed_data';

import 'package:archive/archive.dart';
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

  testWidgets('Office preview caps actual decompressed entry size',
      (tester) async {
    const channel = MethodChannel('com.noleak.vault');
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    final bomb = _docxWithSpoofedUncompressedSize();
    expect(ZipDecoder().decodeBytes(bomb).files.single.size, 1);
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'checkEnvironment') return {'ok': true};
      if (call.method == 'readFile') return bomb;
      throw PlatformException(code: 'UNEXPECTED_METHOD');
    });
    addTearDown(() => messenger.setMockMethodCallHandler(channel, null));

    final entry = VaultEntry(
      fileId: List<int>.filled(16, 2),
      name: 'bomb.docx',
      type: 1,
      size: bomb.length,
      createdAt: DateTime.fromMillisecondsSinceEpoch(0),
    );
    await tester
        .pumpWidget(MaterialApp(home: DocumentViewerScreen(entry: entry)));
    await tester.pumpAndSettle();

    expect(find.text('Document preview failed.'), findsOneWidget);
  });
}

Uint8List _docxWithSpoofedUncompressedSize() {
  const maxEntryBytes = 5 * 1024 * 1024;
  final prefix = utf8.encode(
    '<w:document xmlns:w="urn:test"><w:body><w:p><w:t>',
  );
  final suffix = utf8.encode('</w:t></w:p></w:body></w:document>');
  final xml = Uint8List(maxEntryBytes + 1);
  xml.setRange(0, prefix.length, prefix);
  xml.fillRange(prefix.length, xml.length - suffix.length, 0x41);
  xml.setRange(xml.length - suffix.length, xml.length, suffix);

  final archive = Archive()
    ..addFile(ArchiveFile('word/document.xml', xml.length, xml));
  final encoded = Uint8List.fromList(ZipEncoder().encode(archive)!);
  final data = ByteData.sublistView(encoded);
  for (var i = 0; i <= encoded.length - 4; i++) {
    final isLocalHeader = encoded[i] == 0x50 &&
        encoded[i + 1] == 0x4b &&
        encoded[i + 2] == 0x03 &&
        encoded[i + 3] == 0x04;
    final isCentralHeader = encoded[i] == 0x50 &&
        encoded[i + 1] == 0x4b &&
        encoded[i + 2] == 0x01 &&
        encoded[i + 3] == 0x02;
    if (isLocalHeader) {
      data.setUint32(i + 22, 1, Endian.little);
    } else if (isCentralHeader) {
      data.setUint32(i + 24, 1, Endian.little);
    }
  }
  return encoded;
}
