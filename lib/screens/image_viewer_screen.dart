/// ImageViewerScreen - Secure Image Display
/// 
/// Displays encrypted images from the vault with zoom and pan support.
/// Images are decrypted into memory and displayed without creating
/// any temporary files on disk.
/// 
/// SECURITY:
/// - Image data decrypted in memory only
/// - Zeroized on dispose
/// - FLAG_SECURE prevents screenshots
/// - No share functionality (intentional)
/// - Environment check before display
/// 
/// Supports common image formats: JPEG, PNG, GIF, WebP, etc.

import 'dart:typed_data';
import 'package:flutter/material.dart';
import '../models/vault_state.dart';
import '../services/vault_channel.dart';

/// Secure image viewer with zoom/pan support.
/// 
/// FLAG_SECURE is set globally in MainActivity to prevent screenshots.
class ImageViewerScreen extends StatefulWidget {
  final VaultEntry entry;

  const ImageViewerScreen({super.key, required this.entry});

  @override
  State<ImageViewerScreen> createState() => _ImageViewerScreenState();
}

class _ImageViewerScreenState extends State<ImageViewerScreen> {
  bool _isLoading = true;
  Uint8List? _imageData;
  String? _error;
  final TransformationController _transformationController =
      TransformationController();

  @override
  void initState() {
    super.initState();
    _checkSecurityAndLoadImage();
  }

  Future<void> _checkSecurityAndLoadImage() async {
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
      
      await _loadImage();
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
    _transformationController.dispose();
    // Zeroize image data
    if (_imageData != null) {
      for (int i = 0; i < _imageData!.length; i++) {
        _imageData![i] = 0;
      }
    }
    super.dispose();
  }

  Future<void> _loadImage() async {
    try {
      final data = await VaultChannel.readFile(widget.entry.fileId);
      setState(() {
        _imageData = data;
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _isLoading = false;
      });
    }
  }

  void _resetZoom() {
    _transformationController.value = Matrix4.identity();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: Text(
          widget.entry.name,
          style: const TextStyle(fontSize: 16),
        ),
        backgroundColor: Colors.transparent,
        elevation: 0,
        actions: [
          if (_imageData != null)
            IconButton(
              icon: const Icon(Icons.zoom_out_map),
              tooltip: 'Reset Zoom',
              onPressed: _resetZoom,
            ),
        ],
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
            Icon(Icons.broken_image, size: 64, color: Colors.red[400]),
            const SizedBox(height: 16),
            Text(
              'Failed to load image',
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

    return InteractiveViewer(
      transformationController: _transformationController,
      minScale: 0.5,
      maxScale: 4.0,
      child: Center(
        child: Image.memory(
          _imageData!,
          fit: BoxFit.contain,
          errorBuilder: (context, error, stackTrace) {
            return Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(Icons.broken_image, size: 64, color: Colors.red[400]),
                const SizedBox(height: 16),
                Text(
                  'Could not decode image',
                  style: TextStyle(color: Colors.grey[300]),
                ),
              ],
            );
          },
        ),
      ),
    );
  }
}
