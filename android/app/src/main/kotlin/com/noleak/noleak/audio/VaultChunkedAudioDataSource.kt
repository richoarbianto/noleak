package com.noleak.noleak.audio

import android.media.MediaDataSource
import com.noleak.noleak.security.SecureLog
import com.noleak.noleak.vault.StreamingConstants
import com.noleak.noleak.vault.VaultBridge
import com.noleak.noleak.vault.VaultEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.util.concurrent.atomic.AtomicBoolean

/**
 * VaultChunkedAudioDataSource - Stream audio chunks on-demand.
 *
 * Uses VaultBridge.readChunk to decrypt per-chunk and keeps only one chunk
 * cached in memory to reduce RAM usage for large audio files.
 */
class VaultChunkedAudioDataSource(
    private val vaultBridge: VaultBridge,
    private val fileId: ByteArray,
    private val chunkCount: Int,
    private val fileSize: Long
) : MediaDataSource() {

    companion object {
        private const val TAG = "VaultChunkedAudioDataSource"
        private const val LEGACY_CHUNK_SIZE = 1024L * 1024L
    }

    private val closed = AtomicBoolean(false)
    private var cachedIndex = -1
    private var cachedChunk: ByteArray? = null
    private val chunkSizeBytes: Long = detectChunkSize(fileSize, chunkCount)

    private fun detectChunkSize(totalSize: Long, count: Int): Long {
        if (totalSize <= 0 || count <= 0) return LEGACY_CHUNK_SIZE

        val legacyCount = (totalSize + LEGACY_CHUNK_SIZE - 1) / LEGACY_CHUNK_SIZE
        if (legacyCount == count.toLong()) return LEGACY_CHUNK_SIZE

        val streamingSize = StreamingConstants.CHUNK_SIZE.toLong()
        val streamingCount = (totalSize + streamingSize - 1) / streamingSize
        if (streamingCount == count.toLong()) return streamingSize

        val estimated = (totalSize + count - 1L) / count.toLong()
        SecureLog.w(TAG, "Unknown chunk layout, using estimated chunkSize=${estimated}B")
        return maxOf(1L, estimated)
    }

    @Synchronized
    override fun readAt(position: Long, buffer: ByteArray, offset: Int, size: Int): Int {
        if (closed.get()) return -1
        if (position < 0 || position >= fileSize) return -1

        val toRead = minOf(size.toLong(), fileSize - position).toInt()
        var remaining = toRead
        var destOffset = offset
        var pos = position

        while (remaining > 0) {
            val chunkIndex = (pos / chunkSizeBytes).toInt()
            val chunkOffset = (pos % chunkSizeBytes).toInt()
            val chunk = loadChunk(chunkIndex) ?: return -1

            val available = chunk.size - chunkOffset
            if (available <= 0) return -1

            val copyLen = minOf(remaining, available)
            System.arraycopy(chunk, chunkOffset, buffer, destOffset, copyLen)
            destOffset += copyLen
            pos += copyLen
            remaining -= copyLen
        }

        return toRead
    }

    @Synchronized
    override fun getSize(): Long = fileSize

    @Synchronized
    override fun close() {
        if (closed.getAndSet(true)) return
        cachedChunk?.let { VaultEngine.secureZeroize(it) }
        cachedChunk = null
        cachedIndex = -1
    }

    @Synchronized
    private fun loadChunk(index: Int): ByteArray? {
        if (index == cachedIndex && cachedChunk != null) return cachedChunk

        val chunkResult = runBlocking(Dispatchers.IO) {
            vaultBridge.readChunk(fileId, index)
        }
        val chunk = chunkResult.getOrNull() ?: return null

        cachedChunk?.let { VaultEngine.secureZeroize(it) }
        cachedChunk = chunk
        cachedIndex = index
        return chunk
    }
}
