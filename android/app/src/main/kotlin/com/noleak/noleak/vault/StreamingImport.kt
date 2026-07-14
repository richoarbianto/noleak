package com.noleak.noleak.vault

/**
 * Result from streaming_start - contains import ID and resume position
 */
data class StreamingStartResult(
    val importId: ByteArray,
    val resumeFromChunk: Int
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as StreamingStartResult
        return importId.contentEquals(other.importId) && resumeFromChunk == other.resumeFromChunk
    }
    override fun hashCode(): Int = importId.contentHashCode()
}

/**
 * State of a streaming import (for resume and progress tracking)
 */
data class StreamingImportState(
    val importId: ByteArray,
    val fileId: ByteArray,
    val fileName: String?,
    val mimeType: String?,
    val sourceUri: String?,
    val fileType: Int,
    val fileSize: Long,
    val totalChunks: Int,
    val completedChunks: Int,
    val chunkSize: Int,
    val createdAt: Long,
    val updatedAt: Long
) {
    val progress: Float get() = if (totalChunks > 0) completedChunks.toFloat() / totalChunks else 0f
    val bytesWritten: Long get() = completedChunks.toLong() * chunkSize
    val isComplete: Boolean get() = completedChunks >= totalChunks
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as StreamingImportState
        return importId.contentEquals(other.importId)
    }
    override fun hashCode(): Int = importId.contentHashCode()
}

/**
 * Progress callback interface for streaming imports
 */
interface StreamingProgressCallback {
    fun onProgress(
        importId: ByteArray,
        bytesWritten: Long,
        totalBytes: Long,
        chunksCompleted: Int,
        totalChunks: Int
    )
    fun onError(importId: ByteArray, error: String)
    fun onComplete(importId: ByteArray, fileId: ByteArray)
}

/**
 * Streaming import constants
 */
object StreamingConstants {
    const val CHUNK_SIZE = 4 * 1024 * 1024  // 4MB
    const val MAX_FILE_SIZE = 50L * 1024 * 1024 * 1024  // 50GB
    const val HASH_SAMPLE_SIZE = 1024 * 1024  // 1MB for source hash
    
    // Error codes
    const val OK = 0
    const val ERR_INVALID_PARAM = -1
    const val ERR_MEMORY = -2
    const val ERR_IO = -3
    const val ERR_CRYPTO = -4
    const val ERR_NOT_FOUND = -5
    const val ERR_ALREADY_EXISTS = -6
    const val ERR_SOURCE_CHANGED = -7
    const val ERR_DISK_FULL = -8
    const val ERR_VAULT_NOT_OPEN = -9
    const val ERR_CHUNK_CORRUPTED = -10
    const val ERR_FILE_TOO_LARGE = -11
}
