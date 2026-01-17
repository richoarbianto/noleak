/// AudioPlayerScreen - Secure Audio Playback
/// 
/// Plays encrypted audio files directly from the vault without creating
/// any temporary decrypted files on disk. Audio data is decrypted in
/// memory and streamed to the audio player.
/// 
/// SECURITY:
/// - No plaintext files created on disk
/// - Audio data decrypted in memory only
/// - Activity tracking for session timeout
/// - Environment check before playback
/// 
/// Supports common audio formats: MP3, M4A, WAV, etc.

import 'dart:async';

import 'package:flutter/material.dart';

import '../models/vault_state.dart';
import '../services/vault_channel.dart';

/// Secure audio player for encrypted vault files.
/// 
/// The [entry] parameter specifies which vault file to play.
/// The optional [onActivity] callback is called periodically during
/// playback to reset the session timeout timer.
class AudioPlayerScreen extends StatefulWidget {
  final VaultEntry entry;
  final VoidCallback? onActivity;

  const AudioPlayerScreen({super.key, required this.entry, this.onActivity});

  @override
  State<AudioPlayerScreen> createState() => _AudioPlayerScreenState();
}

class _AudioPlayerScreenState extends State<AudioPlayerScreen> {
  int? _audioHandle;
  int _durationMs = 0;
  int _positionMs = 0;
  bool _isPlaying = false;
  bool _isLoading = true;
  bool _hasError = false;
  String _errorMessage = '';
  Timer? _positionTimer;
  Timer? _activityTimer;

  @override
  void initState() {
    super.initState();
    _checkSecurityAndOpenAudio();
  }

  @override
  void dispose() {
    _positionTimer?.cancel();
    _activityTimer?.cancel();
    _closeAudio();
    super.dispose();
  }

  Future<void> _checkSecurityAndOpenAudio() async {
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

      await _openAudio();
    } catch (e) {
      if (mounted) {
        setState(() {
          _hasError = true;
          _errorMessage = 'Security check failed: $e';
          _isLoading = false;
        });
      }
    }
  }

  Future<void> _openAudio() async {
    try {
      final result = await VaultChannel.openAudio(
        fileId: widget.entry.fileId,
        mimeType: widget.entry.mimeType,
      );
      setState(() {
        _audioHandle = result['handle'] as int;
        _durationMs = (result['durationMs'] as int?) ?? 0;
        _isLoading = false;
      });
      _startPositionPolling();
    } catch (e) {
      if (mounted) {
        setState(() {
          _hasError = true;
          _errorMessage = 'Failed to open audio: $e';
          _isLoading = false;
        });
      }
    }
  }

  Future<void> _closeAudio() async {
    _positionTimer?.cancel();
    if (_audioHandle != null) {
      await VaultChannel.closeAudio(_audioHandle!);
    }
  }

  void _startPositionPolling() {
    _positionTimer = Timer.periodic(const Duration(milliseconds: 500), (_) async {
      if (_audioHandle == null) return;
      final playing = await VaultChannel.isAudioPlaying(_audioHandle!);
      final position = await VaultChannel.getAudioPosition(_audioHandle!);
      if (mounted) {
        setState(() {
          _isPlaying = playing;
          _positionMs = position;
        });
      }
      _updateActivityPing(playing);
    });
  }

  Future<void> _togglePlayPause() async {
    if (_audioHandle == null) return;
    final ok = _isPlaying
        ? await VaultChannel.pauseAudio(_audioHandle!)
        : await VaultChannel.playAudio(_audioHandle!);
    if (ok && mounted) {
      setState(() => _isPlaying = !_isPlaying);
    }
    _updateActivityPing(_isPlaying);
  }

  Future<void> _seekTo(double value) async {
    if (_audioHandle == null) return;
    widget.onActivity?.call();
    final target = value.round();
    await VaultChannel.seekAudio(_audioHandle!, target);
    if (mounted) {
      setState(() => _positionMs = target);
    }
  }

  void _updateActivityPing(bool playing) {
    if (playing) {
      _activityTimer ??= Timer.periodic(const Duration(seconds: 5), (_) {
        widget.onActivity?.call();
      });
    } else {
      _activityTimer?.cancel();
      _activityTimer = null;
    }
  }

  String _formatMs(int value) {
    final duration = Duration(milliseconds: value);
    final minutes = duration.inMinutes.remainder(60).toString().padLeft(2, '0');
    final seconds = duration.inSeconds.remainder(60).toString().padLeft(2, '0');
    return '$minutes:$seconds';
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
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_isLoading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_hasError) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.error_outline, size: 64, color: Colors.red[400]),
            const SizedBox(height: 16),
            Text(
              'Failed to load audio',
              style: TextStyle(color: Colors.grey[300], fontSize: 18),
            ),
            const SizedBox(height: 8),
            Text(
              _errorMessage,
              style: TextStyle(color: Colors.grey[500], fontSize: 14),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      );
    }

    final maxMs = _durationMs > 0 ? _durationMs.toDouble() : 1.0;
    final positionMs = _positionMs.clamp(0, _durationMs).toDouble();

    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.graphic_eq, size: 64, color: Colors.greenAccent[200]),
          const SizedBox(height: 24),
          Text(
            widget.entry.name,
            style: TextStyle(color: Colors.grey[200], fontSize: 16),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 24),
          Slider(
            value: maxMs == 1.0 ? 0.0 : positionMs,
            max: maxMs,
            onChanged: (value) => _seekTo(value),
          ),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(_formatMs(_positionMs), style: TextStyle(color: Colors.grey[400])),
              Text(_formatMs(_durationMs), style: TextStyle(color: Colors.grey[400])),
            ],
          ),
          const SizedBox(height: 24),
          IconButton(
            iconSize: 64,
            color: Colors.greenAccent[200],
            icon: Icon(_isPlaying ? Icons.pause_circle_filled : Icons.play_circle_fill),
            onPressed: _togglePlayPause,
          ),
        ],
      ),
    );
  }
}
