package com.noleak.noleak.audio

import com.noleak.noleak.vault.VaultBridge
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * AudioPlayerManager - Manages multiple audio player instances
 * 
 * Provides handle-based access to audio controllers for Flutter integration.
 * Similar to VideoPlayerManager but optimized for audio playback.
 * 
 * SECURITY:
 * - Audio data is decrypted in memory only during playback
 * - All audio data is securely zeroized on close
 * - Thread-safe handle management with ConcurrentHashMap
 */
class AudioPlayerManager private constructor(
    private val vaultBridge: VaultBridge
) {
    companion object {
        @Volatile
        private var instance: AudioPlayerManager? = null

        fun getInstance(vaultBridge: VaultBridge): AudioPlayerManager {
            return instance ?: synchronized(this) {
                instance ?: AudioPlayerManager(vaultBridge).also { instance = it }
            }
        }
    }

    private val handleCounter = AtomicInteger(0)
    private val controllers = ConcurrentHashMap<Int, SecureAudioController>()

    suspend fun openAudio(fileId: ByteArray): AudioOpenResult {
        val handle = handleCounter.incrementAndGet()
        val controller = SecureAudioController(vaultBridge)
        val success = controller.open(fileId)
        return if (success) {
            controllers[handle] = controller
            AudioOpenResult.Success(handle = handle, durationMs = controller.getDuration())
        } else {
            AudioOpenResult.Error(controller.getLastError() ?: "Failed to open audio")
        }
    }

    fun play(handle: Int): Boolean {
        val controller = controllers[handle] ?: return false
        controller.play()
        return true
    }

    fun pause(handle: Int): Boolean {
        val controller = controllers[handle] ?: return false
        controller.pause()
        return true
    }

    fun seek(handle: Int, positionMs: Long): Boolean {
        val controller = controllers[handle] ?: return false
        controller.seek(positionMs)
        return true
    }

    fun getPosition(handle: Int): Long = controllers[handle]?.getCurrentPosition() ?: 0

    fun getDuration(handle: Int): Long = controllers[handle]?.getDuration() ?: 0

    fun isPlaying(handle: Int): Boolean = controllers[handle]?.isPlaying() ?: false

    fun close(handle: Int): Boolean {
        val controller = controllers.remove(handle) ?: return false
        controller.close()
        return true
    }

    fun closeAll() {
        controllers.values.forEach { it.close() }
        controllers.clear()
    }
}

sealed class AudioOpenResult {
    data class Success(
        val handle: Int,
        val durationMs: Long
    ) : AudioOpenResult()

    data class Error(val message: String) : AudioOpenResult()
}
