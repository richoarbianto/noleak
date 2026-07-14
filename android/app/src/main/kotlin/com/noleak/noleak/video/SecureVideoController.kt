package com.noleak.noleak.video

import android.media.MediaExtractor
import android.media.MediaFormat
import android.media.MediaPlayer
import android.os.Build
import android.view.Surface
import com.noleak.noleak.vault.VaultBridge
import com.noleak.noleak.security.SecureLog
import java.util.concurrent.atomic.AtomicBoolean

/**
 * SecureVideoController - Plays video from encrypted vault chunks with audio.
 *
 * Key features:
 * - Uses MediaPlayer + custom MediaDataSource (no temp files, RAM only)
 * - Decrypts chunk-by-chunk (1MB) via VaultMediaDataSource
 * - Cached chunks are zeroized on close/replacement and after 60s max
 * - Thread-safe with proper state management
 */
class SecureVideoController(
    private val vaultBridge: VaultBridge
) {
    companion object {
        private const val TAG = "SecureVideoController"
    }
    
    private var mediaPlayer: MediaPlayer? = null
    private var dataSource: VaultMediaDataSource? = null
    private var surface: Surface? = null
    private var fileId: ByteArray? = null
    private var chunkCount: Int = 0
    private var fileSize: Long = 0
    private var videoDurationMs: Long = 0
    private var videoWidth: Int = 0
    private var videoHeight: Int = 0
    private var videoRotation: Int = 0
    private var lastError: String? = null
    private val isPrepared = AtomicBoolean(false)
    private val playingFlag = AtomicBoolean(false)
    private val isSeeking = AtomicBoolean(false)
    private var playPending = false
    private var pendingSeekMs: Long? = null

    var onPositionChanged: ((Long) -> Unit)? = null
    var onPlaybackComplete: (() -> Unit)? = null
    var onError: ((String) -> Unit)? = null
    var onPrepared: ((Int, Int, Long) -> Unit)? = null

    /**
     * Open video for playback
     */
    suspend fun open(
        fileId: ByteArray,
        surface: Surface,
        chunkCount: Int,
        durationMs: Long = 0,
        width: Int = 0,
        height: Int = 0,
        size: Long = 0
    ): Boolean {
        SecureLog.i(TAG, "=== Opening video ===")
        SecureLog.i(TAG, "chunkCount=$chunkCount, size=$size, durationMs=$durationMs, ${width}x${height}")
        
        this.fileId = fileId
        this.surface = surface
        this.chunkCount = chunkCount
        this.fileSize = size

        try {
            // Calculate actual file size
            val actualSize = if (size > 0) size else chunkCount * VaultMediaDataSource.CHUNK_SIZE
            SecureLog.i(TAG, "Using fileSize=$actualSize")

            // Step 1: Probe metadata using a separate DataSource
            probeVideoMetadata(fileId, chunkCount, actualSize, width, height, durationMs)
            
            SecureLog.i(TAG, "After probe: ${videoWidth}x${videoHeight}, duration=${videoDurationMs}ms")

            // Step 2: Create fresh DataSource for MediaPlayer
            SecureLog.i(TAG, "Creating MediaDataSource for MediaPlayer...")
            dataSource = VaultMediaDataSource(
                vaultBridge = vaultBridge,
                fileId = fileId,
                chunkCount = chunkCount,
                fileSize = actualSize
            )

            // Step 3: Create and configure MediaPlayer
            SecureLog.i(TAG, "Creating MediaPlayer...")
            mediaPlayer = MediaPlayer().apply {
                setOnVideoSizeChangedListener { _, w, h ->
                    SecureLog.i(TAG, "VIDEO_SIZE: ${w}x${h}, rotation=$videoRotation")
                    // Only update if we don't have rotation-corrected dimensions
                    if (videoRotation == 90 || videoRotation == 270) {
                        // Keep swapped dimensions
                    } else if (w > 0 && h > 0) {
                        this@SecureVideoController.videoWidth = w
                        this@SecureVideoController.videoHeight = h
                    }
                }
                
                setOnCompletionListener {
                    SecureLog.i(TAG, "onCompletion")
                    playingFlag.set(false)
                    onPlaybackComplete?.invoke()
                }
                
                setOnErrorListener { _, what, extra ->
                    val errorMsg = "MediaPlayer error: what=$what, extra=$extra (${getErrorDescription(what, extra)})"
                    SecureLog.e(TAG, errorMsg)
                    recordError(errorMsg)
                    // Return false to let onCompletion be called
                    false
                }
                
                setOnInfoListener { _, what, extra ->
                    // Only log important events
                    when(what) {
                        MediaPlayer.MEDIA_INFO_VIDEO_RENDERING_START -> SecureLog.i(TAG, "VIDEO_RENDER_START")
                        MediaPlayer.MEDIA_INFO_BUFFERING_START -> SecureLog.i(TAG, "BUFFERING_START")
                        MediaPlayer.MEDIA_INFO_BUFFERING_END -> SecureLog.i(TAG, "BUFFERING_END")
                    }
                    true
                }
                
                setOnSeekCompleteListener {
                    val pos = this@SecureVideoController.getCurrentPosition()
                    SecureLog.i(TAG, "SEEK_DONE: pos=$pos")
                    isSeeking.set(false)
                    
                    // Apply pending seek if any
                    pendingSeekMs?.let { nextPos ->
                        pendingSeekMs = null
                        applySeek(nextPos)
                        return@setOnSeekCompleteListener
                    }
                    
                    onPositionChanged?.invoke(pos)
                }
                
                setOnBufferingUpdateListener { _, percent ->
                    if (percent % 25 == 0) {
                        SecureLog.d(TAG, "Buffering: $percent%")
                    }
                }
                
                setOnPreparedListener { mp ->
                    SecureLog.i(TAG, "=== onPrepared ===")
                    isPrepared.set(true)
                    
                    // Get actual values from MediaPlayer
                    val mpWidth = mp.videoWidth
                    val mpHeight = mp.videoHeight
                    val mpDuration = mp.duration.toLong()
                    
                    SecureLog.i(TAG, "MediaPlayer reports: ${mpWidth}x${mpHeight}, duration=${mpDuration}ms, rotation=${videoRotation}°")
                    
                    // Only use MediaPlayer dimensions if we don't have rotation-corrected values
                    if (this@SecureVideoController.videoWidth == 0 && mpWidth > 0) {
                        // Apply rotation swap if needed
                        if (videoRotation == 90 || videoRotation == 270) {
                            this@SecureVideoController.videoWidth = mpHeight
                            this@SecureVideoController.videoHeight = mpWidth
                        } else {
                            this@SecureVideoController.videoWidth = mpWidth
                            this@SecureVideoController.videoHeight = mpHeight
                        }
                    }
                    if (this@SecureVideoController.videoDurationMs == 0L && mpDuration > 0) {
                        this@SecureVideoController.videoDurationMs = mpDuration
                    }
                    
                    SecureLog.i(TAG, "Final: ${this@SecureVideoController.videoWidth}x${this@SecureVideoController.videoHeight}, duration=${this@SecureVideoController.videoDurationMs}ms, rotation=${videoRotation}°")
                    
                    // Apply pending seek
                    pendingSeekMs?.let { seekPos ->
                        SecureLog.d(TAG, "Applying pending seek to $seekPos")
                        applySeek(seekPos)
                        pendingSeekMs = null
                    }
                    
                    // Start if play was pending
                    if (playPending) {
                        SecureLog.d(TAG, "Starting pending play")
                        safeStart()
                        playPending = false
                    }
                    
                    onPrepared?.invoke(
                        mpWidth,
                        mpHeight,
                        this@SecureVideoController.videoDurationMs
                    )
                }
            }
            
            // Set data source and surface
            SecureLog.i(TAG, "Setting DataSource...")
            mediaPlayer?.setDataSource(dataSource!!)
            
            SecureLog.i(TAG, "Setting Surface...")
            mediaPlayer?.setSurface(surface)
            
            // Start async prepare
            SecureLog.i(TAG, "Calling prepareAsync()...")
            mediaPlayer?.prepareAsync()

            return true
        } catch (e: Exception) {
            val errorMsg = "Failed to open video: ${e.message}"
            SecureLog.e(TAG, errorMsg, e)
            recordError(errorMsg)
            cleanup()
            return false
        }
    }
    
    /**
     * Probe video metadata using a separate DataSource
     */
    private fun probeVideoMetadata(
        fileId: ByteArray,
        chunkCount: Int,
        fileSize: Long,
        hintWidth: Int,
        hintHeight: Int,
        hintDuration: Long
    ) {
        // Use hints first
        if (hintWidth > 0) videoWidth = hintWidth
        if (hintHeight > 0) videoHeight = hintHeight
        if (hintDuration > 0) videoDurationMs = hintDuration
        
        // Try to probe for actual values
        var probeDataSource: VaultMediaDataSource? = null
        try {
            SecureLog.d(TAG, "Probing metadata with separate DataSource...")
            probeDataSource = VaultMediaDataSource(
                vaultBridge = vaultBridge,
                fileId = fileId,
                chunkCount = chunkCount,
                fileSize = fileSize
            )
            
            val extractor = MediaExtractor()
            extractor.setDataSource(probeDataSource)
            
            SecureLog.d(TAG, "Probe: ${extractor.trackCount} tracks found")
            
            for (i in 0 until extractor.trackCount) {
                val format = extractor.getTrackFormat(i)
                val mime = format.getString(MediaFormat.KEY_MIME) ?: continue
                
                SecureLog.d(TAG, "Probe track $i: mime=$mime")
                
                if (mime.startsWith("video/")) {
                    var rawWidth = 0
                    var rawHeight = 0
                    var rotation = 0
                    
                    if (format.containsKey(MediaFormat.KEY_WIDTH)) {
                        rawWidth = format.getInteger(MediaFormat.KEY_WIDTH)
                    }
                    if (format.containsKey(MediaFormat.KEY_HEIGHT)) {
                        rawHeight = format.getInteger(MediaFormat.KEY_HEIGHT)
                    }
                    if (format.containsKey(MediaFormat.KEY_DURATION)) {
                        videoDurationMs = format.getLong(MediaFormat.KEY_DURATION) / 1000
                    }
                    // Read rotation - KEY_ROTATION available from API 23
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        if (format.containsKey(MediaFormat.KEY_ROTATION)) {
                            rotation = format.getInteger(MediaFormat.KEY_ROTATION)
                        }
                    }
                    
                    SecureLog.d(TAG, "Probe raw: ${rawWidth}x${rawHeight}, rotation=${rotation}°")
                    
                    // If rotation is 90 or 270, swap width and height for display
                    videoRotation = rotation
                    if (rotation == 90 || rotation == 270) {
                        videoWidth = rawHeight
                        videoHeight = rawWidth
                        SecureLog.d(TAG, "Swapped for portrait: ${videoWidth}x${videoHeight}")
                    } else {
                        videoWidth = rawWidth
                        videoHeight = rawHeight
                    }
                    
                    SecureLog.d(TAG, "Probe result: ${videoWidth}x${videoHeight}, duration=${videoDurationMs}ms, rotation=${rotation}°")
                    break
                } else if (mime.startsWith("audio/") && videoDurationMs == 0L) {
                    if (format.containsKey(MediaFormat.KEY_DURATION)) {
                        videoDurationMs = format.getLong(MediaFormat.KEY_DURATION) / 1000
                    }
                }
            }
            extractor.release()
        } catch (e: Exception) {
            SecureLog.w(TAG, "Probe failed: ${e.message}")
        } finally {
            probeDataSource?.close()
        }
    }
    
    private fun getErrorDescription(what: Int, extra: Int): String {
        val whatStr = when (what) {
            MediaPlayer.MEDIA_ERROR_UNKNOWN -> "UNKNOWN"
            MediaPlayer.MEDIA_ERROR_SERVER_DIED -> "SERVER_DIED"
            else -> "CODE_$what"
        }
        val extraStr = when (extra) {
            MediaPlayer.MEDIA_ERROR_IO -> "IO_ERROR"
            MediaPlayer.MEDIA_ERROR_MALFORMED -> "MALFORMED"
            MediaPlayer.MEDIA_ERROR_UNSUPPORTED -> "UNSUPPORTED"
            MediaPlayer.MEDIA_ERROR_TIMED_OUT -> "TIMED_OUT"
            -2147483648 -> "UNKNOWN_GENERIC"
            else -> "EXTRA_$extra"
        }
        return "$whatStr/$extraStr"
    }

    fun play() {
        SecureLog.d(TAG, "play() isPrepared=${isPrepared.get()}")
        if (!isPrepared.get()) {
            playPending = true
            return
        }
        safeStart()
    }

    fun pause() {
        SecureLog.d(TAG, "pause()")
        try {
            if (mediaPlayer?.isPlaying == true) {
                mediaPlayer?.pause()
                playingFlag.set(false)
            }
        } catch (e: Exception) {
            SecureLog.w(TAG, "Error pausing: ${e.message}")
        }
    }

    fun seek(positionMs: Long): Boolean {
        SecureLog.d(TAG, "seek($positionMs) isPrepared=${isPrepared.get()}, isSeeking=${isSeeking.get()}")
        
        if (!isPrepared.get()) {
            pendingSeekMs = positionMs
            return true
        }
        
        // If already seeking, just update pending position (will be applied when current seek completes)
        if (isSeeking.get()) {
            SecureLog.d(TAG, "Already seeking, updating pending seek to $positionMs")
            pendingSeekMs = positionMs
            return true
        }
        
        applySeek(positionMs)
        return true
    }

    fun getCurrentPosition(): Long {
        return try {
            mediaPlayer?.currentPosition?.toLong() ?: 0L
        } catch (e: Exception) {
            0L
        }
    }

    fun getDuration(): Long {
        if (videoDurationMs > 0) return videoDurationMs
        return try {
            mediaPlayer?.duration?.toLong() ?: 0L
        } catch (e: Exception) {
            0L
        }
    }

    fun isPlaying(): Boolean = playingFlag.get() && (mediaPlayer?.isPlaying == true)

    fun getWidth(): Int = videoWidth
    fun getHeight(): Int = videoHeight
    fun getRotation(): Int = videoRotation
    
    fun close() {
        SecureLog.i(TAG, "close()")
        playingFlag.set(false)
        isPrepared.set(false)
        
        try {
            mediaPlayer?.stop()
        } catch (e: Exception) {
            SecureLog.w(TAG, "Error stopping: ${e.message}")
        }
        
        try {
            mediaPlayer?.release()
        } catch (e: Exception) {
            SecureLog.w(TAG, "Error releasing MediaPlayer: ${e.message}")
        }
        mediaPlayer = null
        
        try {
            dataSource?.close()
        } catch (e: Exception) {
            SecureLog.w(TAG, "Error closing DataSource: ${e.message}")
        }
        dataSource = null
        
        cleanup()
    }

    private fun safeStart() {
        mediaPlayer?.let {
            try {
                SecureLog.d(TAG, "safeStart()")
                it.start()
                playingFlag.set(true)
            } catch (e: IllegalStateException) {
                SecureLog.e(TAG, "safeStart failed: ${e.message}")
                recordError("Play failed: ${e.message}")
            }
        }
    }

    private fun applySeek(positionMs: Long) {
        try {
            isSeeking.set(true)
            SecureLog.i(TAG, "SEEK: to $positionMs")
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                mediaPlayer?.seekTo(positionMs, MediaPlayer.SEEK_PREVIOUS_SYNC)
            } else {
                mediaPlayer?.seekTo(positionMs.toInt())
            }
        } catch (e: Exception) {
            SecureLog.e(TAG, "SEEK_ERROR: ${e.message}")
            isSeeking.set(false)
        }
    }

    private fun cleanup() {
        surface = null
        // SECURITY: Zeroize fileId before releasing
        fileId?.let { 
            java.security.SecureRandom().nextBytes(it)
            it.fill(0)
        }
        fileId = null
        chunkCount = 0
        fileSize = 0
        videoRotation = 0
        videoWidth = 0
        videoHeight = 0
        videoDurationMs = 0
    }

    fun getLastError(): String? = lastError

    private fun recordError(message: String) {
        lastError = message
        onError?.invoke(message)
    }
}
