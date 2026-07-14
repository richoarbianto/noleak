package com.noleak.noleak.video

import android.view.Surface
import com.noleak.noleak.vault.VaultBridge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * VideoPlayerManager - Manages multiple video player instances
 * 
 * Provides handle-based access to video controllers for Flutter integration.
 */
class VideoPlayerManager private constructor(
    private val vaultBridge: VaultBridge
) {
    companion object {
        @Volatile
        private var instance: VideoPlayerManager? = null
        
        fun getInstance(vaultBridge: VaultBridge): VideoPlayerManager {
            return instance ?: synchronized(this) {
                instance ?: VideoPlayerManager(vaultBridge).also {
                    instance = it
                }
            }
        }
    }
    
    private val handleCounter = AtomicInteger(0)
    private val controllers = ConcurrentHashMap<Int, SecureVideoController>()
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    
    /**
     * Open a video and return a handle
     */
    suspend fun openVideo(
        fileId: ByteArray,
        surface: Surface,
        chunkCount: Int,
        durationMs: Long = 0,
        width: Int = 0,
        height: Int = 0,
        size: Long = 0
    ): VideoOpenResult {
        val handle = handleCounter.incrementAndGet()
        val controller = SecureVideoController(vaultBridge)
        
        val success = controller.open(fileId, surface, chunkCount, durationMs, width, height, size)
        
        return if (success) {
            controllers[handle] = controller
            VideoOpenResult.Success(
                handle = handle,
                width = controller.getWidth().takeIf { it > 0 } ?: width.takeIf { it > 0 } ?: 1920,
                height = controller.getHeight().takeIf { it > 0 } ?: height.takeIf { it > 0 } ?: 1080,
                durationMs = controller.getDuration().takeIf { it > 0 } ?: if (durationMs > 0) durationMs else chunkCount * 1000L
            )
        } else {
            VideoOpenResult.Error(controller.getLastError() ?: "Failed to open video")
        }
    }
    
    /**
     * Play video by handle
     */
    fun play(handle: Int): Boolean {
        val controller = controllers[handle] ?: return false
        controller.play()
        return true
    }
    
    /**
     * Pause video by handle
     */
    fun pause(handle: Int): Boolean {
        val controller = controllers[handle] ?: return false
        controller.pause()
        return true
    }
    
    /**
     * Seek video by handle
     */
    fun seek(handle: Int, positionMs: Long): Boolean {
        val controller = controllers[handle] ?: return false
        controller.seek(positionMs)
        return true
    }
    
    /**
     * Get current position
     */
    fun getPosition(handle: Int): Long {
        return controllers[handle]?.getCurrentPosition() ?: 0
    }
    
    /**
     * Get duration
     */
    fun getDuration(handle: Int): Long {
        return controllers[handle]?.getDuration() ?: 0
    }
    
    /**
     * Check if playing
     */
    fun isPlaying(handle: Int): Boolean {
        return controllers[handle]?.isPlaying() ?: false
    }
    
    /**
     * Set callbacks for a video handle
     */
    fun setCallbacks(
        handle: Int,
        onPositionChanged: ((Long) -> Unit)?,
        onPlaybackComplete: (() -> Unit)?,
        onError: ((String) -> Unit)?
    ) {
        val controller = controllers[handle] ?: return
        controller.onPositionChanged = onPositionChanged
        controller.onPlaybackComplete = onPlaybackComplete
        controller.onError = onError
    }

    /**
     * Set prepared callback for a video handle
     */
    fun setOnPrepared(handle: Int, onPrepared: ((Int, Int, Long) -> Unit)?) {
        controllers[handle]?.onPrepared = onPrepared
    }
    
    /**
     * Close video by handle
     */
    fun close(handle: Int): Boolean {
        val controller = controllers.remove(handle) ?: return false
        controller.close()
        return true
    }
    
    /**
     * Close all videos
     */
    fun closeAll() {
        controllers.values.forEach { it.close() }
        controllers.clear()
    }
}

/**
 * Result of opening a video
 */
sealed class VideoOpenResult {
    data class Success(
        val handle: Int,
        val width: Int,
        val height: Int,
        val durationMs: Long
    ) : VideoOpenResult()
    
    data class Error(val message: String) : VideoOpenResult()
}
