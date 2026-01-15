package com.noleak.noleak.vault

import android.content.Context
import com.noleak.noleak.security.SecureLog
import com.noleak.noleak.security.SecurityManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.security.SecureRandom

/**
 * VaultBridge - Thread-safe wrapper for vault operations with security enforcement
 */
class VaultBridge private constructor(private val context: Context) {
    
    private val vaultEngine = VaultEngine.getInstance(context)
    private val securityManager = SecurityManager.getInstance(context)
    private val mutex = Mutex()
    
    companion object {
        @Volatile
        private var instance: VaultBridge? = null
        
        fun getInstance(context: Context): VaultBridge {
            return instance ?: synchronized(this) {
                instance ?: VaultBridge(context.applicationContext).also {
                    instance = it
                }
            }
        }
    }
    
    /**
     * Initialize vault engine
     */
    suspend fun initialize(): Result<Unit> = withContext(Dispatchers.IO) {
        mutex.withLock {
            vaultEngine.initialize()
        }
    }
    
    /**
     * Check if environment is secure
     */
    fun checkEnvironment(): Boolean {
        return securityManager.isEnvironmentSecure()
    }
    
    /**
     * Check if vault exists
     */
    fun vaultExists(): Boolean {
        return vaultEngine.vaultExists()
    }
    
    /**
     * Check if vault is open
     */
    fun isVaultOpen(): Boolean {
        return vaultEngine.isOpen()
    }
    
    /**
     * Create a new vault (with security check)
     */
    suspend fun createVault(passphrase: String): Result<Unit> = withContext(Dispatchers.IO) {
        if (!checkEnvironment()) {
            return@withContext Result.failure(SecurityException("Environment not supported"))
        }
        
        mutex.withLock {
            vaultEngine.create(passphrase)
        }
    }
    
    /**
     * Open vault (with security check)
     */
    suspend fun openVault(passphrase: String): Result<Unit> = withContext(Dispatchers.IO) {
        if (!checkEnvironment()) {
            return@withContext Result.failure(SecurityException("Environment not supported"))
        }
        
        mutex.withLock {
            val result = vaultEngine.open(passphrase)
            if (result.isSuccess) {
                // SECURITY: Cleanup stale pending imports (older than 24 hours)
                // These are encrypted chunks from interrupted imports
                val cleaned = vaultEngine.streamingCleanupOld(24 * 60 * 60 * 1000L)
                if (cleaned > 0) {
                    SecureLog.i("VaultBridge", "Cleaned up $cleaned stale pending imports")
                }
            }
            result
        }
    }
    
    /**
     * Close vault
     */
    suspend fun closeVault() = withContext(Dispatchers.IO) {
        mutex.withLock {
            vaultEngine.close()
        }
    }
    
    /**
     * Cleanup stale pending imports (older than 1 hour by default)
     * Call this before starting new import operations to prevent state corruption
     * @return Number of imports cleaned up
     */
    fun cleanupStalePendingImports(maxAgeMs: Long = 60 * 60 * 1000L): Int {
        return try {
            vaultEngine.streamingCleanupOld(maxAgeMs)
        } catch (e: Exception) {
            SecureLog.e("VaultBridge", "Failed to cleanup stale imports: ${e.message}")
            0
        }
    }
    
    /**
     * Import file (with security check)
     */
    suspend fun importFile(
        data: ByteArray,
        type: Int,
        name: String,
        mime: String? = null
    ): Result<ByteArray> = withContext(Dispatchers.IO) {
        if (!checkEnvironment()) {
            return@withContext Result.failure(SecurityException("Environment not supported"))
        }
        
        mutex.withLock {
            vaultEngine.importFile(data, type, name, mime)
        }
    }

    /**
     * Copy file (re-encrypts to new file ID)
     */
    suspend fun copyFile(fileId: ByteArray): Result<ByteArray> = withContext(Dispatchers.IO) {
        if (!checkEnvironment()) {
            return@withContext Result.failure(SecurityException("Environment not supported"))
        }

        mutex.withLock {
            val entriesResult = vaultEngine.listFiles()
            if (entriesResult.isFailure) {
                return@withLock Result.failure(entriesResult.exceptionOrNull() ?: VaultException("List failed", VaultEngine.VAULT_ERR_IO))
            }
            val entry = entriesResult.getOrNull()
                ?.firstOrNull { it.fileId.contentEquals(fileId) }
                ?: return@withLock Result.failure(VaultException("File not found", VaultEngine.VAULT_ERR_NOT_FOUND))

            // FIX: Check if file is chunked first, not just file type
            // Large files imported via streaming are chunked regardless of type
            // Chunked files must use streaming copy (readFile rejects them)
            val isChunked = entry.chunkCount > 0

            if (!isChunked) {
                // Non-chunked file: read all data and re-import
                val dataResult = vaultEngine.readFile(fileId)
                if (dataResult.isFailure) {
                    return@withLock Result.failure(dataResult.exceptionOrNull() ?: VaultException("Read failed", VaultEngine.VAULT_ERR_IO))
                }
                val data = dataResult.getOrThrow()
                val importResult = vaultEngine.importFile(data, entry.type, entry.name, entry.mimeType)
                VaultEngine.secureZeroize(data)
                return@withLock importResult
            }

            // Chunked file: use streaming copy
            if (entry.size <= 0) {
                return@withLock Result.failure(VaultException("Invalid chunked entry", VaultEngine.VAULT_ERR_INVALID_PARAM))
            }

            val sourceHash = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val sourceUri = "vault://copy/${fileIdToHex(fileId)}/${System.currentTimeMillis()}"
            val startResult = vaultEngine.streamingStart(
                sourceUri = sourceUri,
                sourceHash = sourceHash,
                name = entry.name,
                mime = entry.mimeType,
                type = entry.type,
                fileSize = entry.size
            )
            if (startResult.isFailure) {
                return@withLock Result.failure(startResult.exceptionOrNull() ?: VaultException("Copy start failed", StreamingConstants.ERR_IO))
            }
            val importId = startResult.getOrThrow().importId

            val buffer = ByteArray(StreamingConstants.CHUNK_SIZE)
            var buffered = 0
            var targetChunkIndex = 0
            try {
                for (i in 0 until entry.chunkCount) {
                    val chunkResult = vaultEngine.readChunk(fileId, i)
                    if (chunkResult.isFailure) {
                        vaultEngine.streamingAbort(importId)
                        return@withLock Result.failure(chunkResult.exceptionOrNull() ?: VaultException("Chunk read failed", VaultEngine.VAULT_ERR_IO))
                    }
                    val chunk = chunkResult.getOrThrow()
                    var offset = 0
                    while (offset < chunk.size) {
                        val remaining = StreamingConstants.CHUNK_SIZE - buffered
                        val toCopy = minOf(remaining, chunk.size - offset)
                        System.arraycopy(chunk, offset, buffer, buffered, toCopy)
                        buffered += toCopy
                        offset += toCopy
                        if (buffered == StreamingConstants.CHUNK_SIZE) {
                            val outChunk = buffer.copyOf(buffered)
                            val writeResult = vaultEngine.streamingWriteChunk(importId, outChunk, targetChunkIndex)
                            VaultEngine.secureZeroize(outChunk)
                            if (writeResult.isFailure) {
                                vaultEngine.streamingAbort(importId)
                                return@withLock Result.failure(writeResult.exceptionOrNull() ?: VaultException("Chunk write failed", StreamingConstants.ERR_IO))
                            }
                            targetChunkIndex++
                            buffered = 0
                        }
                    }
                    VaultEngine.secureZeroize(chunk)
                }

                if (buffered > 0) {
                    val outChunk = buffer.copyOf(buffered)
                    val writeResult = vaultEngine.streamingWriteChunk(importId, outChunk, targetChunkIndex)
                    VaultEngine.secureZeroize(outChunk)
                    if (writeResult.isFailure) {
                        vaultEngine.streamingAbort(importId)
                        return@withLock Result.failure(writeResult.exceptionOrNull() ?: VaultException("Chunk write failed", StreamingConstants.ERR_IO))
                    }
                }

                return@withLock vaultEngine.streamingFinish(importId)
            } finally {
                VaultEngine.secureZeroize(buffer)
            }
        }
    }

    private fun fileIdToHex(fileId: ByteArray): String {
        val sb = StringBuilder(fileId.size * 2)
        for (b in fileId) {
            sb.append(String.format("%02x", b))
        }
        return sb.toString()
    }
    
    /**
     * Read file (with security check)
     * Handles both regular files and chunked files (from streaming import)
     */
    suspend fun readFile(fileId: ByteArray): Result<ByteArray> = withContext(Dispatchers.IO) {
        if (!checkEnvironment()) {
            return@withContext Result.failure(SecurityException("Environment not supported"))
        }
        
        mutex.withLock {
            // Try regular read first
            val result = vaultEngine.readFile(fileId)
            if (result.isSuccess) {
                return@withLock result
            }
            
            // If failed, check if it's a chunked file
            val entriesResult = vaultEngine.listFiles()
            if (entriesResult.isFailure) {
                return@withLock result // Return original error
            }
            
            val entry = entriesResult.getOrNull()
                ?.firstOrNull { it.fileId.contentEquals(fileId) }
                ?: return@withLock result // Return original error
            
            // If not chunked, return original error
            if (entry.chunkCount <= 0) {
                return@withLock result
            }
            
            // Read all chunks and combine
            try {
                val chunks = mutableListOf<ByteArray>()
                var totalSize = 0
                
                for (i in 0 until entry.chunkCount) {
                    val chunkResult = vaultEngine.readChunk(fileId, i)
                    if (chunkResult.isFailure) {
                        // Zeroize already read chunks
                        chunks.forEach { VaultEngine.secureZeroize(it) }
                        return@withLock Result.failure(
                            chunkResult.exceptionOrNull() 
                                ?: VaultException("Failed to read chunk $i", VaultEngine.VAULT_ERR_IO)
                        )
                    }
                    val chunk = chunkResult.getOrThrow()
                    chunks.add(chunk)
                    totalSize += chunk.size
                }
                
                // Combine all chunks
                val combined = ByteArray(totalSize)
                var offset = 0
                for (chunk in chunks) {
                    System.arraycopy(chunk, 0, combined, offset, chunk.size)
                    offset += chunk.size
                    VaultEngine.secureZeroize(chunk)
                }
                
                Result.success(combined)
            } catch (e: Exception) {
                Result.failure(VaultException("Failed to read chunked file: ${e.message}", VaultEngine.VAULT_ERR_IO))
            }
        }
    }

    /**
     * Data class for text preview result
     */
    data class TextPreviewResult(
        val data: ByteArray,
        val truncated: Boolean,
        val totalSize: Long
    )

    /**
     * Read text preview with size limit (for large files)
     * Only reads up to maxBytes to prevent OOM on large files
     */
    suspend fun readTextPreview(fileId: ByteArray, maxBytes: Int): Result<TextPreviewResult> = withContext(Dispatchers.IO) {
        if (!checkEnvironment()) {
            return@withContext Result.failure(SecurityException("Environment not supported"))
        }
        
        mutex.withLock {
            // Get file entry to check size and chunk info
            val entriesResult = vaultEngine.listFiles()
            if (entriesResult.isFailure) {
                return@withLock Result.failure(entriesResult.exceptionOrNull() ?: VaultException("List failed", VaultEngine.VAULT_ERR_IO))
            }
            
            val entry = entriesResult.getOrNull()
                ?.firstOrNull { it.fileId.contentEquals(fileId) }
                ?: return@withLock Result.failure(VaultException("File not found", VaultEngine.VAULT_ERR_NOT_FOUND))
            
            val totalSize = entry.size
            
            // If file is small enough, read normally
            if (totalSize <= maxBytes) {
                // Try regular read first
                val result = vaultEngine.readFile(fileId)
                if (result.isSuccess) {
                    return@withLock Result.success(TextPreviewResult(
                        data = result.getOrThrow(),
                        truncated = false,
                        totalSize = totalSize
                    ))
                }
                
                // If chunked, read all chunks
                if (entry.chunkCount > 0) {
                    try {
                        val chunks = mutableListOf<ByteArray>()
                        var readSize = 0
                        
                        for (i in 0 until entry.chunkCount) {
                            val chunkResult = vaultEngine.readChunk(fileId, i)
                            if (chunkResult.isFailure) {
                                chunks.forEach { VaultEngine.secureZeroize(it) }
                                return@withLock Result.failure(chunkResult.exceptionOrNull() ?: VaultException("Chunk read failed", VaultEngine.VAULT_ERR_IO))
                            }
                            val chunk = chunkResult.getOrThrow()
                            chunks.add(chunk)
                            readSize += chunk.size
                        }
                        
                        val combined = ByteArray(readSize)
                        var offset = 0
                        for (chunk in chunks) {
                            System.arraycopy(chunk, 0, combined, offset, chunk.size)
                            offset += chunk.size
                            VaultEngine.secureZeroize(chunk)
                        }
                        
                        return@withLock Result.success(TextPreviewResult(
                            data = combined,
                            truncated = false,
                            totalSize = totalSize
                        ))
                    } catch (e: Exception) {
                        return@withLock Result.failure(VaultException("Read failed: ${e.message}", VaultEngine.VAULT_ERR_IO))
                    }
                }
                
                return@withLock Result.failure(result.exceptionOrNull() ?: VaultException("Read failed", VaultEngine.VAULT_ERR_IO))
            }
            
            // File is larger than maxBytes - read only first chunks up to limit
            if (entry.chunkCount > 0) {
                try {
                    val chunks = mutableListOf<ByteArray>()
                    var readSize = 0
                    
                    for (i in 0 until entry.chunkCount) {
                        if (readSize >= maxBytes) break
                        
                        val chunkResult = vaultEngine.readChunk(fileId, i)
                        if (chunkResult.isFailure) {
                            chunks.forEach { VaultEngine.secureZeroize(it) }
                            return@withLock Result.failure(chunkResult.exceptionOrNull() ?: VaultException("Chunk read failed", VaultEngine.VAULT_ERR_IO))
                        }
                        val chunk = chunkResult.getOrThrow()
                        chunks.add(chunk)
                        readSize += chunk.size
                    }
                    
                    // Combine and truncate to maxBytes
                    val actualSize = minOf(readSize, maxBytes)
                    val combined = ByteArray(actualSize)
                    var offset = 0
                    for (chunk in chunks) {
                        val toCopy = minOf(chunk.size, actualSize - offset)
                        if (toCopy > 0) {
                            System.arraycopy(chunk, 0, combined, offset, toCopy)
                            offset += toCopy
                        }
                        VaultEngine.secureZeroize(chunk)
                        if (offset >= actualSize) break
                    }
                    
                    return@withLock Result.success(TextPreviewResult(
                        data = combined,
                        truncated = true,
                        totalSize = totalSize
                    ))
                } catch (e: Exception) {
                    return@withLock Result.failure(VaultException("Read failed: ${e.message}", VaultEngine.VAULT_ERR_IO))
                }
            }
            
            // Non-chunked large file - shouldn't happen normally, but handle it
            return@withLock Result.failure(VaultException("File too large for preview", VaultEngine.VAULT_ERR_IO))
        }
    }
    
    /**
     * Read video chunk (with security check)
     */
    suspend fun readChunk(fileId: ByteArray, chunkIndex: Int): Result<ByteArray> = withContext(Dispatchers.IO) {
        if (!checkEnvironment()) {
            return@withContext Result.failure(SecurityException("Environment not supported"))
        }
        
        mutex.withLock {
            vaultEngine.readChunk(fileId, chunkIndex)
        }
    }
    
    /**
     * Delete file
     */
    suspend fun deleteFile(fileId: ByteArray): Result<Unit> = withContext(Dispatchers.IO) {
        if (!checkEnvironment()) {
            return@withContext Result.failure(SecurityException("Environment not supported"))
        }
        mutex.withLock {
            vaultEngine.deleteFile(fileId)
        }
    }

    /**
     * Rename a file
     */
    suspend fun renameFile(fileId: ByteArray, newName: String): Result<Unit> = withContext(Dispatchers.IO) {
        if (!checkEnvironment()) {
            return@withContext Result.failure(SecurityException("Environment not supported"))
        }
        mutex.withLock {
            vaultEngine.renameFile(fileId, newName)
        }
    }
    
    /**
     * Compact vault
     */
    suspend fun compact(): Result<Unit> = withContext(Dispatchers.IO) {
        if (!checkEnvironment()) {
            return@withContext Result.failure(SecurityException("Environment not supported"))
        }
        mutex.withLock {
            vaultEngine.compact()
        }
    }
    
    /**
     * Get entry count
     */
    fun getEntryCount(): Int {
        if (!checkEnvironment()) return 0
        return vaultEngine.getEntryCount()
    }
    
    /**
     * List all files in vault
     */
    suspend fun listFiles(): Result<List<VaultFileEntry>> = withContext(Dispatchers.IO) {
        if (!checkEnvironment()) {
            return@withContext Result.failure(SecurityException("Environment not supported"))
        }
        mutex.withLock {
            vaultEngine.listFiles()
        }
    }

    /**
     * Verify password without opening vault
     */
    suspend fun verifyPassword(password: String): Boolean = withContext(Dispatchers.IO) {
        if (!checkEnvironment()) {
            return@withContext false
        }
        mutex.withLock {
            vaultEngine.verifyPassword(password)
        }
    }

    /**
     * Change vault password (vault must be open)
     */
    suspend fun changePassword(currentPassword: String, newPassword: String): Boolean = withContext(Dispatchers.IO) {
        if (!checkEnvironment()) {
            return@withContext false
        }
        mutex.withLock {
            vaultEngine.changePassword(currentPassword, newPassword)
        }
    }

    // ========== Multi-Vault Methods ==========

    /**
     * Create a vault at a specific path (for multi-vault support)
     */
    suspend fun createVaultAtPath(path: String, passphrase: String): Result<Unit> = withContext(Dispatchers.IO) {
        if (!checkEnvironment()) {
            return@withContext Result.failure(SecurityException("Environment not supported"))
        }
        
        mutex.withLock {
            vaultEngine.createAtPath(path, passphrase)
        }
    }

    /**
     * Open a vault at a specific path (for multi-vault support)
     */
    suspend fun openVaultAtPath(path: String, passphrase: String): Result<Unit> = withContext(Dispatchers.IO) {
        if (!checkEnvironment()) {
            return@withContext Result.failure(SecurityException("Environment not supported"))
        }
        
        mutex.withLock {
            vaultEngine.openAtPath(path, passphrase)
        }
    }
}
