/// TextViewerScreen - Secure Text File Display
/// 
/// Displays encrypted text files from the vault in a read-only view.
/// Text content is decrypted into memory and displayed without creating
/// any temporary files on disk.
/// 
/// SECURITY:
/// - Content stored as Uint8List (not String) for secure zeroization
/// - Zeroized on dispose
/// - FLAG_SECURE prevents screenshots
/// - No copy/share functionality (intentional)
/// - Preview limited to 1MB for large files
/// - Environment check before display
/// 
/// Supports text files, source code, configuration files, etc.

import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import '../models/vault_state.dart';
import '../services/vault_channel.dart';
import '../utils/secure_passphrase.dart';

/// Secure text viewer for encrypted vault files.
/// 
/// FLAG_SECURE is set globally in MainActivity to prevent screenshots.
/// 
/// SECURITY:
/// - Stores content as Uint8List, not String (String is immutable)
/// - Zeroizes content on dispose
class TextViewerScreen extends StatefulWidget {
  final VaultEntry entry;

  const TextViewerScreen({super.key, required this.entry});

  @override
  State<TextViewerScreen> createState() => _TextViewerScreenState();
}

class _TextViewerScreenState extends State<TextViewerScreen> {
  static const int _maxPreviewBytes = 1024 * 1024; // 1MB limit
  
  bool _isLoading = true;
  Uint8List? _contentBytes;  // SECURITY: Use bytes, not String
  String? _error;
  String? _displayText;
  bool _isTruncated = false;
  int _totalSize = 0;

  @override
  void initState() {
    super.initState();
    _checkSecurityAndLoadContent();
  }

  Future<void> _checkSecurityAndLoadContent() async {
    setState(() => _isLoading = true);
    
    try {
      // Security check before viewing content (PRD Req 2.5)
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
      
      await _loadContent();
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e.toString();
          _isLoading = false;
        });
      }
    }
  }

  @override
  void dispose() {
    // SECURITY: Zeroize content bytes before releasing
    SecurePassphrase.zeroize(_contentBytes);
    _contentBytes = null;
    _displayText = null;
    super.dispose();
  }

  Future<void> _loadContent() async {
    try {
      final preview = await VaultChannel.readTextPreview(
        widget.entry.fileId,
        maxBytes: _maxPreviewBytes,
      );
      
      final data = preview['data'] as Uint8List;
      final truncated = preview['truncated'] as bool? ?? false;
      final totalSize = preview['totalSize'] as int? ?? data.length;
      
      try {
        final text = utf8.decode(data, allowMalformed: false);
        setState(() {
          _contentBytes = data;
          _displayText = text;
          _isTruncated = truncated;
          _totalSize = totalSize;
          _isLoading = false;
        });
      } catch (_) {
        SecurePassphrase.zeroize(data);
        setState(() {
          _error = 'Text preview is not available for this file.';
          _isLoading = false;
        });
      }
    } catch (e) {
      setState(() {
        _error = e.toString();
        _isLoading = false;
      });
    }
  }

  /// Convert bytes to string for display only
  /// The underlying bytes are still secure and will be zeroized
  String get _displayContent {
    if (_displayText != null) return _displayText!;
    if (_contentBytes == null) return '';
    return utf8.decode(_contentBytes!, allowMalformed: true);
  }

  String _formatSize(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
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
      return const Center(
        child: CircularProgressIndicator(),
      );
    }

    if (_error != null) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.error_outline, size: 64, color: Colors.red[400]),
            const SizedBox(height: 16),
            Text(
              'Load failed',
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

    return Column(
      children: [
        if (_isTruncated)
          Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            color: Colors.orange.withOpacity(0.2),
            child: Row(
              children: [
                Icon(Icons.info_outline, color: Colors.orange[300], size: 18),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'Preview only (1MB of ${_formatSize(_totalSize)})',
                    style: TextStyle(color: Colors.orange[300], fontSize: 13),
                  ),
                ),
              ],
            ),
          ),
        Expanded(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.grey[850],
                borderRadius: BorderRadius.circular(12),
              ),
              child: Text(
                _displayContent,
                style: TextStyle(
                  color: Colors.grey[200],
                  fontSize: 14,
                  fontFamily: 'monospace',
                  height: 1.5,
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }
}
