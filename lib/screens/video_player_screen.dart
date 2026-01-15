/// VideoPlayerScreen - Secure Video Playback
/// 
/// Plays encrypted video files directly from the vault using a custom
/// MediaDataSource that decrypts chunks on-demand. No temporary files
/// are created on disk.
/// 
/// SECURITY:
/// - Chunk-based decryption (64KB chunks)
/// - No plaintext files on disk
/// - FLAG_SECURE prevents screen recording
/// - Environment check before playback
/// 
/// SEEK BEHAVIOR:
/// - Seek tolerance: ±1 second due to chunk-based decryption
/// - Debounced seeking to prevent excessive decryption operations
/// 
/// Supports common video formats: MP4, MKV, WebM, etc.

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../models/vault_state.dart';
import '../services/vault_channel.dart';
import '../utils/secure_logger.dart';

/// Secure video player for encrypted vault files.
/// 
/// Uses Flutter's Texture widget to display video frames rendered
/// by the native ExoPlayer with a custom encrypted data source.
/// 
/// FLAG_SECURE is set globally in MainActivity to prevent recording.
class VideoPlayerScreen extends StatefulWidget {
  final VaultEntry entry;
  final VoidCallback? onActivity;

  const VideoPlayerScreen({
    super.key,
    required this.entry,
    this.onActivity,
  });

  @override
  State<VideoPlayerScreen> createState() => _VideoPlayerScreenState();
}

class _VideoPlayerScreenState extends State<VideoPlayerScreen> {
  int? _videoHandle;
  int? _textureId;
  int _durationMs = 0;
  int _videoWidth = 0;
  int _videoHeight = 0;
  int _positionMs = 0;
  bool _isPlaying = false;
  bool _isLoading = true;
  bool _hasError = false;
  String _errorMessage = '';
  bool _showControls = true;
  Timer? _hideControlsTimer;
  Timer? _positionTimer;
  Timer? _seekDebounceTimer;
  Timer? _activityTimer;
  bool _isSeeking = false;
  int _pendingSeekMs = -1;

  @override
  void initState() {
    super.initState();
    SystemChrome.setEnabledSystemUIMode(SystemUiMode.immersiveSticky);
    _checkSecurityAndOpenVideo();
  }

  Future<void> _checkSecurityAndOpenVideo() async {
    try {
      // Security check before playing video (PRD Req 2.6)
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
      
      await _openVideo();
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

  @override
  void dispose() {
    _hideControlsTimer?.cancel();
    _positionTimer?.cancel();
    _seekDebounceTimer?.cancel();
    _stopActivityPing();
    _closeVideo();
    SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
    super.dispose();
  }

  Future<void> _openVideo() async {
    try {
      // Calculate chunk count from file size (1MB per chunk)
      // Use chunkCount from entry if available, otherwise calculate from size
      final chunkCount = widget.entry.chunkCount > 0
          ? widget.entry.chunkCount
          : ((widget.entry.size + (1024 * 1024) - 1) ~/ (1024 * 1024)); // Ceiling division
      
      SecureLogger.d('VideoPlayer', 'Opening video "${widget.entry.name}"');
      SecureLogger.d('VideoPlayer', 'size=${widget.entry.size}, chunkCount=$chunkCount');
      
      if (chunkCount == 0) {
        setState(() {
          _hasError = true;
          _errorMessage = 'Invalid video file: no chunks';
          _isLoading = false;
        });
        return;
      }

      final result = await VaultChannel.openVideo(
        fileId: widget.entry.fileId,
        chunkCount: chunkCount,
        size: widget.entry.size,
      );

      SecureLogger.d('VideoPlayer', 'Opened successfully');
      SecureLogger.d('VideoPlayer', 'handle=${result['handle']}, textureId=${result['textureId']}');
      SecureLogger.d('VideoPlayer', '${result['width']}x${result['height']}, duration=${result['durationMs']}ms');

      setState(() {
        _videoHandle = result['handle'] as int;
        _textureId = result['textureId'] as int;
        _durationMs = (result['durationMs'] as int?) ?? 0;
        _videoWidth = (result['width'] as int?) ?? 0;
        _videoHeight = (result['height'] as int?) ?? 0;
        _isLoading = false;
      });

      // Start position polling
      _startPositionPolling();
    } catch (e, stackTrace) {
      SecureLogger.e('VideoPlayer', 'Failed to open video', e);
      setState(() {
        _hasError = true;
        _errorMessage = 'Failed to open video: $e';
        _isLoading = false;
      });
    }
  }

  Future<void> _closeVideo() async {
    _positionTimer?.cancel();
    if (_videoHandle != null) {
      await VaultChannel.closeVideo(_videoHandle!);
    }
  }

  void _startPositionPolling() {
    _positionTimer = Timer.periodic(const Duration(milliseconds: 500), (_) async {
      if (_videoHandle == null) return;

      final playing = await VaultChannel.isVideoPlaying(_videoHandle!);
      final position = await VaultChannel.getVideoPosition(_videoHandle!);
      final wasPlaying = _isPlaying;

      if (mounted) {
        setState(() {
          _isPlaying = playing;
          _positionMs = position;
        });
      }

      if (playing != wasPlaying) {
        _updateActivityPing(playing);
      }
    });
  }

  Future<void> _togglePlayPause() async {
    if (_videoHandle == null) return;

    try {
      bool ok = false;
      if (_isPlaying) {
        SecureLogger.d('VideoPlayer', 'Pausing');
        ok = await VaultChannel.pauseVideo(_videoHandle!);
      } else {
        SecureLogger.d('VideoPlayer', 'Playing');
        ok = await VaultChannel.playVideo(_videoHandle!);
      }

      SecureLogger.d('VideoPlayer', 'Toggle result: $ok');
      
      if (ok && mounted) {
        setState(() => _isPlaying = !_isPlaying);
      }
    } catch (e) {
      SecureLogger.e('VideoPlayer', 'Toggle error', e);
    }
    _updateActivityPing(_isPlaying);
    _resetHideControlsTimer();
  }

  /// Debounced seek - waits for user to stop dragging before actually seeking
  void _seekTo(int positionMs) {
    if (_videoHandle == null) return;
    
    // Update UI immediately for responsiveness
    setState(() => _positionMs = positionMs);
    
    // Cancel any pending seek
    _seekDebounceTimer?.cancel();
    _pendingSeekMs = positionMs;
    
    // Debounce: wait 200ms after last seek request before executing
    _seekDebounceTimer = Timer(const Duration(milliseconds: 200), () {
      _executeSeek(_pendingSeekMs);
    });
  }
  
  /// Actually execute the seek after debounce
  Future<void> _executeSeek(int positionMs) async {
    if (_videoHandle == null || _isSeeking) return;
    
    _isSeeking = true;
    SecureLogger.d('VideoPlayer', 'Seeking to ${positionMs}ms');
    
    try {
      final ok = await VaultChannel.seekVideo(_videoHandle!, positionMs);
      SecureLogger.d('VideoPlayer', 'Seek result: $ok');
      
      // Update position after seek completes
      if (mounted && ok) {
        final actualPos = await VaultChannel.getVideoPosition(_videoHandle!);
        setState(() => _positionMs = actualPos);
      }
    } catch (e) {
      SecureLogger.e('VideoPlayer', 'Seek error', e);
    } finally {
      _isSeeking = false;
    }
  }

  void _onTap() {
    setState(() => _showControls = !_showControls);
    if (_showControls) {
      _resetHideControlsTimer();
    }
  }

  void _resetHideControlsTimer() {
    _hideControlsTimer?.cancel();
    _hideControlsTimer = Timer(const Duration(seconds: 3), () {
      if (mounted && _isPlaying) {
        setState(() => _showControls = false);
      }
    });
  }

  void _updateActivityPing(bool playing) {
    if (playing) {
      _startActivityPing();
    } else {
      _stopActivityPing();
    }
  }

  void _startActivityPing() {
    if (_activityTimer?.isActive == true) return;
    widget.onActivity?.call();
    _activityTimer = Timer.periodic(const Duration(seconds: 5), (_) {
      widget.onActivity?.call();
    });
  }

  void _stopActivityPing() {
    _activityTimer?.cancel();
    _activityTimer = null;
  }

  String _formatDuration(int ms) {
    final duration = Duration(milliseconds: ms);
    final minutes = duration.inMinutes.remainder(60).toString().padLeft(2, '0');
    final seconds = duration.inSeconds.remainder(60).toString().padLeft(2, '0');
    return '$minutes:$seconds';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      body: GestureDetector(
        onTap: _onTap,
        child: Stack(
          fit: StackFit.expand,
          children: [
            // Video display
            _buildVideoDisplay(),
            
            // Controls overlay
            if (_showControls) _buildControlsOverlay(),
            
            // Loading indicator
            if (_isLoading)
              const Center(
                child: CircularProgressIndicator(color: Colors.white),
              ),
            
            // Error display
            if (_hasError) _buildErrorDisplay(),
          ],
        ),
      ),
    );
  }

  Widget _buildVideoDisplay() {
    if (_textureId == null) {
      return const SizedBox.expand(
        child: ColoredBox(color: Colors.black),
      );
    }

    // Use FittedBox to maintain aspect ratio properly
    // The Texture will be sized based on video dimensions
    // FittedBox.contain will scale it to fit within available space
    return Center(
      child: FittedBox(
        fit: BoxFit.contain,
        child: SizedBox(
          width: _videoWidth > 0 ? _videoWidth.toDouble() : 1920,
          height: _videoHeight > 0 ? _videoHeight.toDouble() : 1080,
          child: Texture(textureId: _textureId!),
        ),
      ),
    );
  }

  Widget _buildControlsOverlay() {
    return Container(
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [
            Colors.black.withOpacity(0.7),
            Colors.transparent,
            Colors.transparent,
            Colors.black.withOpacity(0.7),
          ],
          stops: const [0.0, 0.2, 0.8, 1.0],
        ),
      ),
      child: SafeArea(
        child: Column(
          children: [
            // Top bar
            _buildTopBar(),
            
            const Spacer(),
            
            // Center play button
            _buildCenterPlayButton(),
            
            const Spacer(),
            
            // Bottom controls
            _buildBottomControls(),
          ],
        ),
      ),
    );
  }

  Widget _buildTopBar() {
    return Padding(
      padding: const EdgeInsets.all(8.0),
      child: Row(
        children: [
          IconButton(
            icon: const Icon(Icons.arrow_back, color: Colors.white),
            onPressed: () => Navigator.of(context).pop(),
          ),
          Expanded(
            child: Text(
              widget.entry.name,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 16,
                fontWeight: FontWeight.w500,
              ),
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCenterPlayButton() {
    return IconButton(
      iconSize: 72,
      icon: Icon(
        _isPlaying ? Icons.pause_circle_filled : Icons.play_circle_filled,
        color: Colors.white.withOpacity(0.9),
      ),
      onPressed: _togglePlayPause,
    );
  }

  Widget _buildBottomControls() {
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Progress bar
          SliderTheme(
            data: SliderTheme.of(context).copyWith(
              trackHeight: 4,
              thumbShape: const RoundSliderThumbShape(enabledThumbRadius: 6),
              overlayShape: const RoundSliderOverlayShape(overlayRadius: 12),
              activeTrackColor: Colors.blue,
              inactiveTrackColor: Colors.white30,
              thumbColor: Colors.blue,
            ),
            child: Slider(
              value: _positionMs.toDouble().clamp(0, _durationMs > 0 ? _durationMs.toDouble() : 1),
              min: 0,
              max: _durationMs > 0 ? _durationMs.toDouble() : 1,
              onChanged: (value) {
                // Just update UI during drag - don't seek yet
                setState(() => _positionMs = value.toInt());
              },
              onChangeEnd: (value) {
                // Only seek when user releases the slider
                _seekTo(value.toInt());
              },
            ),
          ),
          
          // Time display
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16.0),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  _formatDuration(_positionMs),
                  style: const TextStyle(color: Colors.white, fontSize: 12),
                ),
                Text(
                  _formatDuration(_durationMs),
                  style: const TextStyle(color: Colors.white, fontSize: 12),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildErrorDisplay() {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Icon(Icons.error_outline, color: Colors.red, size: 48),
          const SizedBox(height: 16),
          Text(
            _errorMessage,
            style: const TextStyle(color: Colors.white),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 16),
          ElevatedButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }
}
