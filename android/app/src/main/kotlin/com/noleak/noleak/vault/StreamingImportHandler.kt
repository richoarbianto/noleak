package com.noleak.noleak.vault

import android.content.Context
import android.net.Uri
import com.noleak.noleak.security.SecureLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.security.SecureRandom

/**
 * StreamingImportHandler - Handles memory-efficient import of large files
 * 
 * SECURITY:
 * - Never holds more than 2 chunks in memory (double buffering)
 * - Zeroizes plaintext immediately after encryption
 * - Supports resume for interrupted imports
 * - Progress tracking for UI feedback
 */
class StreamingImportHandler(private val context: Context) {
    
    companion object {
        private const val TAG = "StreamingImportHandler"
        private val secureRandom = SecureRandom()
        
        fun secureZeroize(data: ByteArray?) {
            if (data == null || data.isEmpty()) return
            secureRandom.nextBytes(data)
            data.fill(0)
        }
    }
    
    private val vaultEngine = VaultEngine.getInstance(context)
    private val safFileHandler = SafFileHandler(context)

    private fun skipFully(input: InputStream, byteCount: Long): Boolean {
        var remaining = byteCount
        val discard = ByteArray(64 * 1024)
        return try {
            while (remaining > 0) {
                val skipped = input.skip(remaining)
                if (skipped > 0) {
                    remaining -= skipped
                    continue
                }
                val read = input.read(discard, 0, minOf(discard.size.toLong(), remaining).toInt())
                if (read <= 0) return false
                remaining -= read
            }
            true
        } finally {
            secureZeroize(discard)
        }
    }
    
    /**
     * Import progress data class
     */
    data class ImportProgress(
        val importId: ByteArray,
        val bytesWritten: Long,
        val totalBytes: Long,
        val chunksCompleted: Int,
        val totalChunks: Int,
        val isComplete: Boolean = false,
        val fileId: ByteArray? = null,
        val error: String? = null
    ) {
        val percentage: Float get() = if (totalBytes > 0) bytesWritten.toFloat() / totalBytes * 100 else 0f
    }
    
    /**
     * Import a file using streaming with progress updates
     * Returns a Flow of ImportProgress for UI updates
     */
    fun importFileStreaming(uri: Uri, targetName: String? = null): Flow<ImportProgress> = flow {
        SecureLog.d(TAG, "Starting streaming import for $uri (target: $targetName)")
        
        // Validate file
        val validation = safFileHandler.validateFile(uri)
        if (validation !is SafFileHandler.FileValidationResult.Valid) {
            val error = when (validation) {
                is SafFileHandler.FileValidationResult.TooLarge -> 
                    "File too large: ${validation.size} bytes"
                SafFileHandler.FileValidationResult.UnknownSize ->
                    "File size could not be determined"
                SafFileHandler.FileValidationResult.Empty -> 
                    "File is empty"
                else -> "Invalid file"
            }
            emit(ImportProgress(ByteArray(16), 0, 0, 0, 0, error = error))
            return@flow
        }
        
        // Check file size limit (50GB)
        if (validation.size > StreamingConstants.MAX_FILE_SIZE) {
            emit(ImportProgress(ByteArray(16), 0, validation.size, 0, 0, 
                error = "File exceeds 50GB limit"))
            return@flow
        }

        
        // Compute source hash for resume verification
        val sourceHash = computeSourceHash(uri, validation.size)
        if (sourceHash == null) {
            emit(ImportProgress(ByteArray(16), 0, validation.size, 0, 0, 
                error = "Failed to compute source hash"))
            return@flow
        }
        
        // Start or resume streaming import
        val startResult = vaultEngine.streamingStart(
            sourceUri = uri.toString(),
            sourceHash = sourceHash,
            name = targetName ?: validation.name,
            mime = validation.mimeType,
            type = validation.fileType,
            fileSize = validation.size
        )
        
        if (startResult.isFailure) {
            emit(ImportProgress(ByteArray(16), 0, validation.size, 0, 0, 
                error = "Failed to start import: ${startResult.exceptionOrNull()?.message}"))
            return@flow
        }
        
        val (importId, resumeFromChunk) = startResult.getOrThrow()
        val totalChunks = ((validation.size + StreamingConstants.CHUNK_SIZE - 1) / StreamingConstants.CHUNK_SIZE).toInt()
        
        SecureLog.d(TAG, "Import started: resumeFrom=$resumeFromChunk, totalChunks=$totalChunks")
        
        // Emit initial progress
        val initialBytesWritten = resumeFromChunk.toLong() * StreamingConstants.CHUNK_SIZE
        emit(ImportProgress(importId, initialBytesWritten, validation.size, resumeFromChunk, totalChunks))
        
        // Open input stream and skip to resume position
        var inputStream: InputStream? = null
        try {
            inputStream = context.contentResolver.openInputStream(uri)
            if (inputStream == null) {
                emit(ImportProgress(importId, 0, validation.size, 0, totalChunks, 
                    error = "Failed to open file"))
                return@flow
            }
            
            // Skip to resume position
            if (resumeFromChunk > 0) {
                val skipBytes = resumeFromChunk.toLong() * StreamingConstants.CHUNK_SIZE
                if (!skipFully(inputStream, skipBytes)) {
                    vaultEngine.streamingAbort(importId)
                    emit(ImportProgress(importId, 0, validation.size, 0, totalChunks,
                        error = "Source file ended before the resume position"))
                    return@flow
                }
                SecureLog.d(TAG, "Skipped $skipBytes bytes for resume")
            }
            
            // Read and write chunks
            val buffer = ByteArray(StreamingConstants.CHUNK_SIZE)
            var chunkIndex = resumeFromChunk
            var bytesWritten = initialBytesWritten
            
            while (chunkIndex < totalChunks) {
                // Read chunk
                var bytesRead = 0
                while (bytesRead < StreamingConstants.CHUNK_SIZE) {
                    val read = inputStream.read(buffer, bytesRead, StreamingConstants.CHUNK_SIZE - bytesRead)
                    if (read <= 0) break
                    bytesRead += read
                }
                
                if (bytesRead == 0) break
                
                // Create chunk data (may be smaller than buffer for last chunk)
                val chunkData = if (bytesRead == StreamingConstants.CHUNK_SIZE) {
                    buffer.copyOf()
                } else {
                    buffer.copyOf(bytesRead)
                }
                
                val writeResult = try {
                    vaultEngine.streamingWriteChunk(importId, chunkData, chunkIndex)
                } finally {
                    secureZeroize(chunkData)
                    secureZeroize(buffer)
                }
                
                if (writeResult.isFailure) {
                    SecureLog.e(TAG, "Failed to write chunk $chunkIndex: ${writeResult.exceptionOrNull()?.message}")
                    emit(ImportProgress(importId, bytesWritten, validation.size, chunkIndex, totalChunks,
                        error = "Failed to write chunk $chunkIndex: ${writeResult.exceptionOrNull()?.message}"))
                    return@flow
                }
                
                bytesWritten += bytesRead
                chunkIndex++
                
                // Log progress every 10 chunks
                if (chunkIndex % 10 == 0 || chunkIndex == totalChunks) {
                    SecureLog.d(TAG, "Chunk progress: $chunkIndex/$totalChunks, bytesWritten=$bytesWritten")
                }
                
                // Emit progress every chunk
                emit(ImportProgress(importId, bytesWritten, validation.size, chunkIndex, totalChunks))
            }

            if (chunkIndex != totalChunks || bytesWritten != validation.size) {
                vaultEngine.streamingAbort(importId)
                emit(ImportProgress(importId, bytesWritten, validation.size, chunkIndex, totalChunks,
                    error = "Source file size changed during import"))
                return@flow
            }

            
            // Finalize import
            SecureLog.d(TAG, "All chunks written, finalizing import... (totalChunks=$totalChunks, bytesWritten=$bytesWritten)")
            val finishResult = vaultEngine.streamingFinish(importId)
            
            if (finishResult.isFailure) {
                SecureLog.e(TAG, "streamingFinish FAILED: ${finishResult.exceptionOrNull()?.message}")
                emit(ImportProgress(importId, bytesWritten, validation.size, chunkIndex, totalChunks,
                    error = "Failed to finalize import: ${finishResult.exceptionOrNull()?.message}"))
                return@flow
            }
            
            val fileId = finishResult.getOrThrow()
            SecureLog.d(TAG, "Import complete SUCCESS: fileId=${fileId.toList()}")
            
            emit(ImportProgress(importId, validation.size, validation.size, totalChunks, totalChunks,
                isComplete = true, fileId = fileId))
            
        } catch (e: Exception) {
            SecureLog.e(TAG, "Import failed with exception: ${e.message}", e)
            emit(ImportProgress(importId, 0, validation.size, 0, totalChunks,
                error = "Import failed: ${e.message}"))
        } finally {
            try {
                inputStream?.close()
            } catch (_: Exception) {}
        }
    }.flowOn(Dispatchers.IO)
    
    /**
     * Compute source hash for resume verification
     * Hash = SHA256(first 1MB || last 1MB || file_size)
     */
    private suspend fun computeSourceHash(uri: Uri, fileSize: Long): ByteArray? = withContext(Dispatchers.IO) {
        val firstMb = ByteArray(minOf(StreamingConstants.HASH_SAMPLE_SIZE.toLong(), fileSize).toInt())
        var lastMb: ByteArray? = null
        try {
            val sampleSize = StreamingConstants.HASH_SAMPLE_SIZE.toLong()
            val firstInput = context.contentResolver.openInputStream(uri) ?: return@withContext null
            firstInput.use { input ->
                var read = 0
                while (read < firstMb.size) {
                    val r = input.read(firstMb, read, firstMb.size - read)
                    if (r <= 0) break
                    read += r
                }
                if (read != firstMb.size) return@withContext null
            }
            
            if (fileSize > sampleSize * 2) {
                val lastBuffer = ByteArray(sampleSize.toInt())
                lastMb = lastBuffer
                val lastInput = context.contentResolver.openInputStream(uri)
                    ?: return@withContext null
                lastInput.use { input ->
                    if (!skipFully(input, fileSize - sampleSize)) {
                        return@withContext null
                    }
                    var read = 0
                    while (read < lastBuffer.size) {
                        val r = input.read(lastBuffer, read, lastBuffer.size - read)
                        if (r <= 0) break
                        read += r
                    }
                    if (read != lastBuffer.size) return@withContext null
                }
            }

            vaultEngine.streamingComputeSourceHash(firstMb, lastMb, fileSize)
        } catch (e: Exception) {
            SecureLog.e(TAG, "Failed to compute source hash: ${e.message}")
            null
        } finally {
            secureZeroize(firstMb)
            secureZeroize(lastMb)
        }
    }
    
    /**
     * Get list of pending imports that can be resumed
     */
    fun getPendingImports(): List<StreamingImportState> {
        return vaultEngine.streamingListPending()
    }
    
    /**
     * Abort a pending import
     */
    fun abortImport(importId: ByteArray): Result<Unit> {
        return vaultEngine.streamingAbort(importId)
    }
    
    /**
     * Resume a pending import
     * User must provide the same source file URI
     */
    fun resumeImport(importId: ByteArray, uri: Uri): Flow<ImportProgress> = flow {
        val state = vaultEngine.streamingGetState(importId)
        if (state == null) {
            emit(ImportProgress(importId, 0, 0, 0, 0, error = "Import not found"))
            return@flow
        }
        
        // Verify source file hasn't changed
        val currentHash = computeSourceHash(uri, state.fileSize)
        if (currentHash == null) {
            emit(ImportProgress(importId, 0, state.fileSize, 0, state.totalChunks,
                error = "Failed to verify source file"))
            return@flow
        }
        
        // Continue with normal import flow - it will auto-resume
        importFileStreaming(uri).collect { emit(it) }
    }.flowOn(Dispatchers.IO)
}
