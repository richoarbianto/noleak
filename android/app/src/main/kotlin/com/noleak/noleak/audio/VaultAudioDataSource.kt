package com.noleak.noleak.audio

import android.media.MediaDataSource
import java.security.SecureRandom

/**
 * VaultAudioDataSource - MediaDataSource wrapper for in-memory audio data
 * 
 * Provides MediaPlayer access to decrypted audio data without writing to disk.
 * 
 * SECURITY:
 * - Audio data is held in memory only
 * - Data is securely zeroized on close
 * - No disk I/O for audio content
 */
class VaultAudioDataSource(private var data: ByteArray) : MediaDataSource() {
    companion object {
        private val secureRandom = SecureRandom()

        private fun secureZeroize(buffer: ByteArray?) {
            if (buffer == null || buffer.isEmpty()) return
            secureRandom.nextBytes(buffer)
            buffer.fill(0)
        }
    }

    override fun readAt(position: Long, buffer: ByteArray, offset: Int, size: Int): Int {
        if (position >= data.size) return -1
        val length = minOf(size, data.size - position.toInt())
        System.arraycopy(data, position.toInt(), buffer, offset, length)
        return length
    }

    override fun getSize(): Long = data.size.toLong()

    override fun close() {
        secureZeroize(data)
        data = ByteArray(0)
    }
}
