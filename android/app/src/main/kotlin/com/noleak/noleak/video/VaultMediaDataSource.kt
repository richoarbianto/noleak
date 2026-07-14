package com.noleak.noleak.video

import android.media.MediaDataSource
import android.os.SystemClock
import com.noleak.noleak.security.SecureLog
import com.noleak.noleak.vault.StreamingConstants
import com.noleak.noleak.vault.VaultBridge
import kotlinx.coroutines.*
import java.io.IOException
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * VaultMediaDataSource - Optimized windowed cache video playback.
 * 
 * FIXED v3: Streaming-imported videos (4MB chunks) now play in windowed cache.
 * - Detect actual chunk size (1MB vs 4MB) and size buffers accordingly
 * - Scale cache/prefetch by memory budget to avoid over-allocation
 * - Retains v2 improvements for cache stability and retry behavior
 * 
 * FEATURES:
 * - 150MB RAM Preload (Hybrid Mode)
 * - Safe Synchronized Copy (No reading freed buffers)
 * - Buffer Pooling
 * - Async Prefetch
 * - Seek Cancellation
 */
class VaultMediaDataSource(
    private val vaultBridge: VaultBridge,
    private val fileId: ByteArray,
    private val chunkCount: Int,
    private val fileSize: Long
) : MediaDataSource() {

    companion object {
        const val CHUNK_SIZE: Long = 1024L * 1024L // Default/legacy chunk size (1MB)
        private const val TAG = "VaultMediaDataSource"
        private const val PRELOAD_TIMEOUT_MS = 60_000L
        
        // Threshold: 150MB - files below this are fully preloaded
        private const val MAX_PRELOAD_SIZE = 150L * 1024L * 1024L 
        private const val MAX_VIDEO_SIZE = 50L * 1024L * 1024L * 1024L // 50GB max
        
        // Cache settings (base counts assume 1MB chunks)
        private const val CACHE_CHUNK_COUNT_SMALL = 32  // For files < 500MB
        private const val CACHE_CHUNK_COUNT_LARGE = 64  // For files >= 500MB
        private const val PREFETCH_AHEAD_DEFAULT = 12
        private const val BUFFER_POOL_SIZE_DEFAULT = 80
        
        // Retry settings
        private const val MAX_LOAD_RETRIES = 3
        private const val CHUNK_LOAD_TIMEOUT_MS = 10_000L  // Increased from 5s to 10s
        
        private val secureRandom = SecureRandom()
        
        private fun secureZeroize(data: ByteArray?) {
            if (data == null || data.isEmpty()) return
            secureRandom.nextBytes(data)
            data.fill(0)
        }
    }

    private val closed = AtomicBoolean(false)
    private var videoData: ByteArray? = null
    private var preloadOk = false
    private var useWindowedCache = false
    private var lastSeekPosition = -1L
    
    // Detect actual chunk size (1MB legacy vs 4MB streaming) from metadata
    private val chunkSizeBytes: Long = detectChunkSize(fileSize, chunkCount)
    private val chunkSizeInt: Int = chunkSizeBytes.toInt()
    
    // Dynamic cache sizing based on file size and actual chunk size
    private val cacheChunkCount: Int = computeCacheChunkCount()
    private val prefetchAhead: Int = computePrefetchAhead()
    private val bufferPoolSize: Int = computeBufferPoolSize()
    
    // Cache guarded by lock
    private val chunkCache = LinkedHashMap<Int, CachedChunk>(cacheChunkCount, 0.75f, true)
    private val cacheLock = Object()
    
    // Track recently loaded chunks to protect from immediate eviction
    private val recentlyLoaded = ConcurrentHashMap<Int, Long>()
    private val RECENT_PROTECTION_MS = 2000L  // Protect for 2 seconds
    
    private val bufferPool = ConcurrentLinkedQueue<ByteArray>()
    
    private val prefetchScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val prefetchingChunks = ConcurrentHashMap.newKeySet<Int>()
    
    // Stats for debugging
    private val cacheHits = AtomicInteger(0)
    private val cacheMisses = AtomicInteger(0)
    
    // Use inner class to hold data + valid flag
    private data class CachedChunk(
        val data: ByteArray,
        val size: Int,
        val loadedAt: Long = SystemClock.elapsedRealtime()
    )

    init {
        if (fileSize > MAX_VIDEO_SIZE) {
            SecureLog.e(TAG, "INIT: File too large (${fileSize / 1024 / 1024}MB > ${MAX_VIDEO_SIZE / 1024 / 1024 / 1024}GB)")
            preloadOk = false
        } else if (fileSize > MAX_PRELOAD_SIZE) {
            SecureLog.i(
                TAG,
                "INIT: Large video (${fileSize / 1024 / 1024}MB), chunkSize=${chunkSizeBytes / 1024 / 1024}MB, cacheChunks=$cacheChunkCount"
            )
            useWindowedCache = true
            preloadOk = true
            initBufferPool()
        } else {
            preloadToRam()
        }
    }

    private fun detectChunkSize(fileSize: Long, chunkCount: Int): Long {
        if (fileSize <= 0 || chunkCount <= 0) return CHUNK_SIZE

        val legacyCount = (fileSize + CHUNK_SIZE - 1) / CHUNK_SIZE
        if (legacyCount == chunkCount.toLong()) {
            return CHUNK_SIZE
        }

        val streamingSize = StreamingConstants.CHUNK_SIZE.toLong()
        val streamingCount = (fileSize + streamingSize - 1) / streamingSize
        if (streamingCount == chunkCount.toLong()) {
            return streamingSize
        }

        val estimated = (fileSize + chunkCount - 1L) / chunkCount.toLong()
        SecureLog.w(TAG, "INIT: Unrecognized chunk layout, using estimated chunkSize=${estimated}B")
        return maxOf(1L, estimated)
    }

    private fun computeCacheChunkCount(): Int {
        val baseCount = if (fileSize >= 500L * 1024L * 1024L) {
            CACHE_CHUNK_COUNT_LARGE
        } else {
            CACHE_CHUNK_COUNT_SMALL
        }
        val targetBytes = baseCount.toLong() * CHUNK_SIZE
        val computed = maxOf(2L, targetBytes / chunkSizeBytes).toInt()
        return if (chunkCount > 0) minOf(computed, chunkCount) else computed
    }

    private fun computePrefetchAhead(): Int {
        val targetBytes = PREFETCH_AHEAD_DEFAULT.toLong() * CHUNK_SIZE
        val computed = maxOf(2L, targetBytes / chunkSizeBytes).toInt()
        return if (chunkCount > 0) minOf(computed, chunkCount) else computed
    }

    private fun computeBufferPoolSize(): Int {
        val targetBytes = BUFFER_POOL_SIZE_DEFAULT.toLong() * CHUNK_SIZE
        val computed = maxOf(4L, targetBytes / chunkSizeBytes).toInt()
        val limit = if (chunkCount > 0) chunkCount + 10 else computed
        return minOf(computed, limit)
    }
    
    private fun initBufferPool() {
        val size = minOf(bufferPoolSize, chunkCount + 10)
        repeat(size) {
            bufferPool.offer(ByteArray(chunkSizeInt))
        }
        SecureLog.d(TAG, "Buffer pool initialized with $size buffers of ${chunkSizeBytes / 1024 / 1024}MB")
    }
    
    private fun acquireBuffer(minSize: Int = chunkSizeInt): ByteArray {
        val pooled = bufferPool.poll()
        return if (pooled != null && pooled.size >= minSize) {
            pooled
        } else {
            ByteArray(maxOf(minSize, chunkSizeInt))
        }
    }
    
    private fun releaseBuffer(buffer: ByteArray) {
        secureZeroize(buffer)
        if (buffer.size == chunkSizeInt && bufferPool.size < bufferPoolSize * 2) {
            bufferPool.offer(buffer)
        }
    }

    private fun cancelAllPrefetch() {
        prefetchScope.coroutineContext.cancelChildren()
        prefetchingChunks.clear()
    }

    private fun preloadToRam() {
        if (fileSize > Int.MAX_VALUE || fileSize <= 0 || chunkCount <= 0) {
            preloadOk = false
            return
        }
        var data: ByteArray? = null
        try {
            data = ByteArray(fileSize.toInt())
            var offset = 0
            runBlocking(Dispatchers.IO) {
                withTimeout(PRELOAD_TIMEOUT_MS) {
                    for (i in 0 until chunkCount) {
                        val chunk = vaultBridge.readChunk(fileId, i).getOrNull() ?: throw IOException("Chunk $i")
                        val copySize = minOf(chunk.size, data!!.size - offset)
                        System.arraycopy(chunk, 0, data, offset, copySize)
                        offset += copySize
                        secureZeroize(chunk)
                    }
                }
            }
            videoData = data
            preloadOk = true
        } catch (e: Exception) {
            SecureLog.e(TAG, "PRELOAD: FAILED")
            secureZeroize(data)
            videoData = null
            preloadOk = false
        }
    }
    
    /**
     * Safely copy data from cache to destination with retry mechanism
     * Ensures we don't read from an evicted (zeroized) buffer
     */
    private fun copyChunkData(chunkIndex: Int, chunkOffset: Int, dest: ByteArray, destOffset: Int, length: Int): Boolean {
        if (closed.get()) return false

        repeat(MAX_LOAD_RETRIES) { attempt ->
            // 1. Try Cache Hit
            synchronized(cacheLock) {
                val cached = chunkCache[chunkIndex]
                if (cached != null) {
                    // HOLD LOCK while copying to prevent eviction zeroing data
                    if (chunkOffset + length <= cached.size) {
                        System.arraycopy(cached.data, chunkOffset, dest, destOffset, length)
                        cacheHits.incrementAndGet()
                        
                        // Trigger prefetch (fire and forget, non-blocking)
                        triggerPrefetch(chunkIndex)
                        return true
                    }
                }
            }
            
            // 2. Cache Miss - Load Blocking with retry
            cacheMisses.incrementAndGet()
            val loaded = loadChunkBlocking(chunkIndex)
            
            if (loaded != null) {
                synchronized(cacheLock) {
                    // Re-check cache - chunk should be there now
                    val currentCached = chunkCache[chunkIndex]
                    if (currentCached != null && chunkOffset + length <= currentCached.size) {
                        System.arraycopy(currentCached.data, chunkOffset, dest, destOffset, length)
                        triggerPrefetch(chunkIndex)
                        return true
                    }
                }
            }
            
            // Small delay before retry
            if (attempt < MAX_LOAD_RETRIES - 1) {
                Thread.sleep(50)
            }
        }
        
        SecureLog.e(TAG, "copyChunkData FAILED after $MAX_LOAD_RETRIES retries for chunk $chunkIndex")
        return false
    }

    private fun loadChunkBlocking(chunkIndex: Int): CachedChunk? {
        if (closed.get()) return null
        try {
            val rawData = runBlocking(Dispatchers.IO) {
                withTimeoutOrNull(CHUNK_LOAD_TIMEOUT_MS) {
                    vaultBridge.readChunk(fileId, chunkIndex).getOrNull()
                }
            }
            
            if (rawData == null) {
                SecureLog.e(TAG, "loadChunkBlocking: chunk $chunkIndex returned null or timeout")
                return null
            }
            
            val buffer = acquireBuffer(rawData.size)
            val size = rawData.size
            System.arraycopy(rawData, 0, buffer, 0, size)
            secureZeroize(rawData)
            
            val cached = CachedChunk(buffer, size)
            val now = SystemClock.elapsedRealtime()
            
            synchronized(cacheLock) {
                // Smart eviction - avoid evicting recently loaded chunks
                while (chunkCache.size >= cacheChunkCount) {
                    val iterator = chunkCache.iterator()
                    var evicted = false
                    while (iterator.hasNext() && !evicted) {
                        val entry = iterator.next()
                        val chunkIdx = entry.key
                        val loadedAt = recentlyLoaded[chunkIdx] ?: 0L
                        
                        // Don't evict if loaded within protection window
                        if (now - loadedAt > RECENT_PROTECTION_MS) {
                            releaseBuffer(entry.value.data)
                            iterator.remove()
                            recentlyLoaded.remove(chunkIdx)
                            evicted = true
                        }
                    }
                    
                    // If all chunks are protected, force evict the oldest
                    if (!evicted && chunkCache.isNotEmpty()) {
                        val firstEntry = chunkCache.entries.first()
                        releaseBuffer(firstEntry.value.data)
                        chunkCache.remove(firstEntry.key)
                        recentlyLoaded.remove(firstEntry.key)
                    }
                }
                
                chunkCache[chunkIndex] = cached
                recentlyLoaded[chunkIndex] = now
            }
            return cached
        } catch (e: Exception) {
            SecureLog.e(TAG, "loadChunkBlocking exception for chunk $chunkIndex: ${e.message}")
            return null
        }
    }
    
    private fun triggerPrefetch(currentChunk: Int) {
        prefetchScope.launch {
            for (i in 1..prefetchAhead) {
                val next = currentChunk + i
                if (next >= chunkCount) break
                
                // Double-checked locking optimization
                if (prefetchingChunks.contains(next)) continue
                
                val alreadyCached = synchronized(cacheLock) { chunkCache.containsKey(next) }
                if (alreadyCached) continue

                if (prefetchingChunks.add(next)) {
                    try {
                        loadChunkBlocking(next)
                    } finally {
                        prefetchingChunks.remove(next)
                    }
                }
            }
        }
    }

    override fun readAt(position: Long, buffer: ByteArray?, offset: Int, size: Int): Int {
        if (buffer == null || size <= 0) return 0
        if (closed.get() || position >= fileSize) return -1

        // Detect seek and cancel prefetch if needed
        if (kotlin.math.abs(position - lastSeekPosition) > chunkSizeBytes * 4) {
            cancelAllPrefetch()
            // Log stats periodically
            if (cacheMisses.get() > 0 && cacheMisses.get() % 50 == 0) {
                SecureLog.d(TAG, "Cache stats: hits=${cacheHits.get()}, misses=${cacheMisses.get()}")
            }
        }
        lastSeekPosition = position

        return if (useWindowedCache) {
            readAtWindowed(position, buffer, offset, size)
        } else {
            readAtPreloaded(position, buffer, offset, size)
        }
    }
    
    private fun readAtPreloaded(position: Long, buffer: ByteArray, offset: Int, size: Int): Int {
        val data = videoData ?: return -1
        val startPos = position.toInt()
        val available = data.size - startPos
        if (available <= 0) return -1
        val toRead = minOf(size, available)
        System.arraycopy(data, startPos, buffer, offset, toRead)
        return toRead
    }
    
    private fun readAtWindowed(position: Long, buffer: ByteArray, offset: Int, size: Int): Int {
        var bytesRead = 0
        var currentPos = position
        var bufferOffset = offset
        var remaining = size
        
        while (remaining > 0 && currentPos < fileSize) {
            val chunkIndex = (currentPos / chunkSizeBytes).toInt()
            val chunkOffset = (currentPos % chunkSizeBytes).toInt()
            
            // Calculate actual bytes available in this chunk
            val chunkStartByte = chunkIndex.toLong() * chunkSizeBytes
            val chunkEndByte = minOf(chunkStartByte + chunkSizeBytes, fileSize)
            val bytesAvailableInChunk = (chunkEndByte - currentPos).toInt()
            
            val toRead = minOf(remaining, bytesAvailableInChunk)
            if (toRead <= 0) break
            
            val success = copyChunkData(chunkIndex, chunkOffset, buffer, bufferOffset, toRead)
            if (!success) {
                SecureLog.w(TAG, "readAtWindowed: copyChunkData failed at chunk $chunkIndex, pos=$currentPos")
                return if (bytesRead > 0) bytesRead else -1
            }
            
            bytesRead += toRead
            currentPos += toRead
            bufferOffset += toRead
            remaining -= toRead
        }
        return if (bytesRead > 0) bytesRead else -1
    }

    override fun getSize(): Long = fileSize

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        
        SecureLog.d(TAG, "Closing: cache hits=${cacheHits.get()}, misses=${cacheMisses.get()}")
        
        prefetchScope.cancel()
        secureZeroize(videoData)
        videoData = null
        
        synchronized(cacheLock) {
            chunkCache.values.forEach { releaseBuffer(it.data) }
            chunkCache.clear()
        }
        recentlyLoaded.clear()
        
        var buf = bufferPool.poll()
        while (buf != null) {
            secureZeroize(buf)
            buf = bufferPool.poll()
        }
    }
}
