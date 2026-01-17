/// DocumentViewerScreen - Secure Document Display
/// 
/// Displays encrypted documents from the vault including:
/// - PDF files (using pdfx library)
/// - Microsoft Word (.docx)
/// - Microsoft PowerPoint (.pptx)
/// - Microsoft Excel (.xlsx)
/// - CSV files
/// 
/// For Office documents, text content is extracted and displayed
/// as a preview. Full formatting is not preserved.
/// 
/// SECURITY:
/// - Documents decrypted in memory only
/// - Raw bytes zeroized on dispose
/// - Preview truncated at 200,000 characters for safety
/// - Environment check before display

import 'dart:convert';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:flutter/material.dart';
import 'package:pdfx/pdfx.dart';
import 'package:xml/xml.dart';

import '../models/vault_state.dart';
import '../services/vault_channel.dart';
import '../utils/secure_passphrase.dart';

/// Secure document viewer for PDF and Office files.
/// 
/// Extracts and displays text content from encrypted documents.
class DocumentViewerScreen extends StatefulWidget {
  final VaultEntry entry;

  const DocumentViewerScreen({super.key, required this.entry});

  @override
  State<DocumentViewerScreen> createState() => _DocumentViewerScreenState();
}

class _DocumentViewerScreenState extends State<DocumentViewerScreen> {
  static const int _maxPreviewChars = 200000;

  bool _isLoading = true;
  String? _error;
  String? _textContent;
  bool _truncated = false;
  PdfControllerPinch? _pdfController;
  Uint8List? _rawBytes;

  @override
  void initState() {
    super.initState();
    _checkSecurityAndLoad();
  }

  @override
  void dispose() {
    _pdfController?.dispose();
    SecurePassphrase.zeroize(_rawBytes);
    _rawBytes = null;
    super.dispose();
  }

  Future<void> _checkSecurityAndLoad() async {
    try {
      final isSecure = await VaultChannel.checkEnvironment();
      if (!isSecure) {
        if (mounted) {
          Navigator.pop(context);
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Environment not supported')),
          );
        }
        return;
      }

      await _loadDocument();
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e.toString();
          _isLoading = false;
        });
      }
    }
  }

  Future<void> _loadDocument() async {
    Uint8List? data;
    try {
      data = await VaultChannel.readFile(widget.entry.fileId);
      if (widget.entry.isPdf) {
        _pdfController = PdfControllerPinch(document: PdfDocument.openData(data));
        _rawBytes = data;
      } else {
        final text = _extractText(data);
        _textContent = text;
        SecurePassphrase.zeroize(data);
      }
    } catch (e) {
      SecurePassphrase.zeroize(data);
      _error = e.toString();
    }

    if (mounted) {
      setState(() {
        _isLoading = false;
      });
    }
  }

  String _extractText(Uint8List data) {
    if (widget.entry.isDocx) {
      return _extractDocxText(data);
    }
    if (widget.entry.isPptx) {
      return _extractPptxText(data);
    }
    if (widget.entry.isXlsx) {
      return _extractXlsxText(data);
    }
    return _decodePlainText(data);
  }

  String _decodePlainText(Uint8List data) {
    try {
      return utf8.decode(data, allowMalformed: true);
    } catch (_) {
      return String.fromCharCodes(data);
    }
  }

  String _extractDocxText(Uint8List data) {
    final archive = ZipDecoder().decodeBytes(data, verify: true);
    final file = _findArchiveFile(archive, 'word/document.xml');
    if (file == null) return 'No preview data.';

    final document = _withArchiveBytes(
      file,
      (bytes) => XmlDocument.parse(utf8.decode(bytes)),
    );
    final buffer = StringBuffer();
    for (final paragraph in document.findAllElements('w:p')) {
      final text = paragraph.findAllElements('w:t').map((e) => e.text).join();
      if (text.isEmpty) continue;
      _appendLine(buffer, text);
      if (_truncated) break;
    }
    return buffer.toString();
  }

  String _extractPptxText(Uint8List data) {
    final archive = ZipDecoder().decodeBytes(data, verify: true);
    final slideFiles = archive.files
        .where((f) => f.name.startsWith('ppt/slides/slide') && f.name.endsWith('.xml'))
        .toList()
      ..sort((a, b) => a.name.compareTo(b.name));

    if (slideFiles.isEmpty) return 'No preview data.';

    final buffer = StringBuffer();
    for (var i = 0; i < slideFiles.length; i++) {
      final slide = slideFiles[i];
      buffer.writeln('Slide ${i + 1}');
      final document = _withArchiveBytes(
        slide,
        (bytes) => XmlDocument.parse(utf8.decode(bytes)),
      );
      final texts = document.findAllElements('a:t').map((e) => e.text).toList();
      for (final line in texts) {
        if (line.trim().isEmpty) continue;
        _appendLine(buffer, line);
        if (_truncated) break;
      }
      if (_truncated) break;
      buffer.writeln();
    }
    return buffer.toString();
  }

  String _extractXlsxText(Uint8List data) {
    final archive = ZipDecoder().decodeBytes(data, verify: true);
    final shared = _loadSharedStrings(archive);
    final sheets = archive.files
        .where((f) => f.name.startsWith('xl/worksheets/sheet') && f.name.endsWith('.xml'))
        .toList()
      ..sort((a, b) => a.name.compareTo(b.name));

    if (sheets.isEmpty) return 'No preview data.';

    final buffer = StringBuffer();
    for (var i = 0; i < sheets.length; i++) {
      buffer.writeln('Sheet ${i + 1}');
      final document = _withArchiveBytes(
        sheets[i],
        (bytes) => XmlDocument.parse(utf8.decode(bytes)),
      );
      for (final row in document.findAllElements('row')) {
        final rowValues = <String>[];
        for (final cell in row.findAllElements('c')) {
          final type = cell.getAttribute('t');
          String? value;
          if (type == 's') {
            final idxText = cell.findElements('v').map((e) => e.text).firstOrNull;
            if (idxText != null) {
              final idx = int.tryParse(idxText);
              if (idx != null && idx >= 0 && idx < shared.length) {
                value = shared[idx];
              }
            }
          } else if (type == 'inlineStr') {
            value = cell.findAllElements('t').map((e) => e.text).join();
          } else {
            value = cell.findElements('v').map((e) => e.text).firstOrNull;
          }
          if (value != null && value.trim().isNotEmpty) {
            rowValues.add(value.trim());
          }
        }
        if (rowValues.isNotEmpty) {
          _appendLine(buffer, rowValues.join(' | '));
          if (_truncated) break;
        }
      }
      if (_truncated) break;
      buffer.writeln();
    }
    return buffer.toString();
  }

  List<String> _loadSharedStrings(Archive archive) {
    final file = _findArchiveFile(archive, 'xl/sharedStrings.xml');
    if (file == null) return const [];
    return _withArchiveBytes(
      file,
      (bytes) {
        final document = XmlDocument.parse(utf8.decode(bytes));
        return document.findAllElements('t').map((e) => e.text).toList();
      },
    );
  }

  ArchiveFile? _findArchiveFile(Archive archive, String name) {
    for (final file in archive.files) {
      if (file.name == name) return file;
    }
    return null;
  }

  Uint8List _archiveFileBytes(ArchiveFile file) {
    final content = file.content;
    if (content is Uint8List) return content;
    if (content is List<int>) return Uint8List.fromList(content);
    return Uint8List(0);
  }

  T _withArchiveBytes<T>(ArchiveFile file, T Function(Uint8List bytes) action) {
    final bytes = _archiveFileBytes(file);
    try {
      return action(bytes);
    } finally {
      SecurePassphrase.zeroize(bytes);
    }
  }

  void _appendLine(StringBuffer buffer, String line) {
    if (_truncated) return;
    if (buffer.length + line.length + 1 >= _maxPreviewChars) {
      final remaining = _maxPreviewChars - buffer.length - 1;
      if (remaining > 0) {
        buffer.write(line.substring(0, remaining));
      }
      _truncated = true;
      return;
    }
    buffer.writeln(line);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.grey[900],
      appBar: AppBar(
        title: Text(
          widget.entry.name,
          style: const TextStyle(fontSize: 16),
        ),
        backgroundColor: Colors.transparent,
        elevation: 0,
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_isLoading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_error != null) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.error_outline, size: 64, color: Colors.red[400]),
            const SizedBox(height: 16),
            Text(
              'Failed to load document',
              style: TextStyle(color: Colors.grey[300], fontSize: 18),
            ),
            const SizedBox(height: 8),
            Text(
              _error!,
              style: TextStyle(color: Colors.grey[500], fontSize: 14),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      );
    }

    if (widget.entry.isPdf && _pdfController != null) {
      return PdfViewPinch(
        controller: _pdfController!,
        backgroundDecoration: const BoxDecoration(color: Colors.black),
      );
    }

    final content = _textContent ?? '';
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (_truncated)
            Container(
              margin: const EdgeInsets.only(bottom: 12),
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.grey[850],
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Text(
                'Preview truncated for safety.',
                style: TextStyle(color: Colors.amberAccent, fontSize: 12),
              ),
            ),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Colors.grey[850],
              borderRadius: BorderRadius.circular(12),
            ),
            child: Text(
              content.isEmpty ? 'No preview data.' : content,
              style: TextStyle(
                color: Colors.grey[200],
                fontSize: 14,
                height: 1.5,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

extension _XmlIterableFirstOrNull on Iterable<XmlElement> {
  XmlElement? get firstOrNull => isEmpty ? null : first;
}

extension _StringIterableFirstOrNull on Iterable<String> {
  String? get firstOrNull => isEmpty ? null : first;
}
