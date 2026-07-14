package com.noleak.noleak.audio

import android.media.AudioAttributes
import android.media.MediaPlayer
import com.noleak.noleak.security.SecureLog
import com.noleak.noleak.vault.VaultBridge
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.SecureRandom

/**
 * SecureAudioController - Plays audio from encrypted vault
 * 
 * Uses MediaPlayer with custom MediaDataSource for in-memory playback.
 * Audio data is decrypted once and held in RAM during playback.
 * 
 * SECURITY:
 * - Audio data is decrypted from vault on open
 * - Data is held in memory only during playback session
 * - All buffers are securely zeroized on close
 * - No temp files are created on disk
 */
class SecureAudioController(
    private val vaultBridge: VaultBridge
) {
    companion object {
        private const val TAG = "SecureAudioController"
        private val secureRandom = SecureRandom()

        private fun secureZeroize(buffer: ByteArray?) {
            if (buffer == null || buffer.isEmpty()) return
            secureRandom.nextBytes(buffer)
            buffer.fill(0)
        }
    }

    private var mediaPlayer: MediaPlayer? = null
    private var dataSource: VaultAudioDataSource? = null
    private var audioData: ByteArray? = null
    private var lastError: String? = null

    suspend fun open(fileId: ByteArray): Boolean = withContext(Dispatchers.IO) {
        try {
            val dataResult = vaultBridge.readFile(fileId)
            if (dataResult.isFailure) {
                val msg = dataResult.exceptionOrNull()?.message ?: "Failed to read audio"
                recordError(msg)
                return@withContext false
            }
            audioData = dataResult.getOrThrow()
            dataSource = VaultAudioDataSource(audioData!!)

            mediaPlayer = MediaPlayer().apply {
                setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_MEDIA)
                        .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
                        .build()
                )
                setDataSource(dataSource!!)
                prepare()
            }
            true
        } catch (e: Exception) {
            val msg = "Failed to open audio: ${e.message}"
            SecureLog.e(TAG, msg, e)
            recordError(msg)
            cleanup()
            false
        }
    }

    fun play() {
        mediaPlayer?.start()
    }

    fun pause() {
        if (mediaPlayer?.isPlaying == true) {
            mediaPlayer?.pause()
        }
    }

    fun seek(positionMs: Long) {
        mediaPlayer?.seekTo(positionMs.toInt())
    }

    fun getCurrentPosition(): Long = mediaPlayer?.currentPosition?.toLong() ?: 0

    fun getDuration(): Long = mediaPlayer?.duration?.toLong() ?: 0

    fun isPlaying(): Boolean = mediaPlayer?.isPlaying ?: false

    fun getLastError(): String? = lastError

    fun close() {
        cleanup()
    }

    private fun cleanup() {
        try {
            mediaPlayer?.stop()
        } catch (_: Exception) {}
        mediaPlayer?.release()
        mediaPlayer = null
        dataSource?.close()
        dataSource = null
        secureZeroize(audioData)
        audioData = null
    }

    private fun recordError(message: String) {
        lastError = message
    }
}
