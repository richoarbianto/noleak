package com.noleak.noleak.vault

import android.content.Context
import java.io.File
import com.noleak.noleak.security.SecureLog

/**
 * VaultEngine - Kotlin wrapper for native vault operations
 * 
 * All cryptographic operations are performed in native code (C/libsodium)
 */
class VaultEngine private constructor(private val context: Context) {
    
    companion object {
        // Error codes (must match vault_engine.h)
        const val VAULT_OK = 0
        const val VAULT_ERR_INVALID_PARAM = -1
        const val VAULT_ERR_MEMORY = -2
        const val VAULT_ERR_IO = -3
        const val VAULT_ERR_CRYPTO = -4
        const val VAULT_ERR_AUTH_FAIL = -5
        const val VAULT_ERR_CORRUPTED = -6
        const val VAULT_ERR_NOT_FOUND = -7
        const val VAULT_ERR_ALREADY_EXISTS = -8
        const val VAULT_ERR_NOT_OPEN = -9
        const val VAULT_ERR_PASSPHRASE_TOO_SHORT = -10
        
        // File types
        const val FILE_TYPE_TXT = 1
        const val FILE_TYPE_IMG = 2
        const val FILE_TYPE_VIDEO = 3
        
        // Minimum passphrase length
        const val MIN_PASSPHRASE_LENGTH = 12
        
        // SECURITY: Secure random for zeroization
        private val secureRandom = java.security.SecureRandom()
        
        /**
         * SECURITY: Securely zeroize a byte array
         * Overwrites with random data then zeros
         */
        fun secureZeroize(data: ByteArray?) {
            if (data == null || data.isEmpty()) return
            secureRandom.nextBytes(data)
            data.fill(0)
        }
        
        init {
            System.loadLibrary("vault_engine")
        }
        
        @Volatile
        private var instance: VaultEngine? = null
        
        fun getInstance(context: Context): VaultEngine {
            return instance ?: synchronized(this) {
                instance ?: VaultEngine(context.applicationContext).also {
                    instance = it
                }
            }
        }
    }
    
    // Native methods
    private external fun nativeInit(): Int
    private external fun nativeSetKdfProfile(totalRamMb: Long)
    private external fun nativeCreate(path: String, passphrase: ByteArray): Int
    private external fun nativeOpen(path: String, passphrase: ByteArray): Int
    private external fun nativeClose()
    private external fun nativeIsOpen(): Boolean
    private external fun nativeImportFile(data: ByteArray, type: Int, name: String, mime: String?): ByteArray?
    private external fun nativeReadFile(fileId: ByteArray): ByteArray?
    private external fun nativeReadChunk(fileId: ByteArray, chunkIndex: Int): ByteArray?
    private external fun nativeDeleteFile(fileId: ByteArray): Int
    private external fun nativeRenameFile(fileId: ByteArray, name: String): Int
    private external fun nativeCompact(): Int
    private external fun nativeGetEntryCount(): Int
    private external fun nativeListFiles(): Array<VaultFileEntry>?
    private external fun nativeChangePassword(oldPassphrase: ByteArray, newPassphrase: ByteArray): Int
    private external fun nativeSecureWipeFile(path: String): Boolean
    
    // Streaming import native methods
    private external fun nativeStreamingInit(): Int
    private external fun nativeStreamingComputeSourceHash(firstMb: ByteArray, lastMb: ByteArray?, fileSize: Long): ByteArray?
    private external fun nativeStreamingStart(sourceUri: String, sourceHash: ByteArray, name: String, mime: String?, type: Int, fileSize: Long): StreamingStartResult?
    private external fun nativeStreamingWriteChunk(importId: ByteArray, plaintext: ByteArray, chunkIndex: Int): Int
    private external fun nativeStreamingFinish(importId: ByteArray): ByteArray?
    private external fun nativeStreamingAbort(importId: ByteArray): Int
    private external fun nativeStreamingGetState(importId: ByteArray): StreamingImportState?
    private external fun nativeStreamingListPending(): Array<StreamingImportState>?
    private external fun nativeStreamingCleanupOld(maxAgeMs: Long): Int
    
    private var initialized = false
    
    // Track the currently open vault path for multi-vault support
    private var currentVaultPath: String? = null
    
    /**
     * Initialize the vault engine
     * SECURITY: Sets adaptive KDF profile based on device RAM
     */
    fun initialize(): Result<Unit> {
        if (initialized) return Result.success(Unit)
        
        // SECURITY: Set adaptive KDF profile based on device RAM BEFORE init
        // This ensures proper memory settings even if init has issues
        val totalRamMb = getTotalRamMb()
        nativeSetKdfProfile(totalRamMb)
        SecureLog.i("VaultEngine", "Set KDF profile for ${totalRamMb}MB RAM device")
        
        val result = nativeInit()
        if (result != VAULT_OK) {
            return Result.failure(VaultException("Failed to initialize vault engine", result))
        }
        
        initialized = true
        SecureLog.i("VaultEngine", "Vault engine initialized")
        return Result.success(Unit)
    }
    
    /**
     * Get device total RAM in megabytes
     */
    private fun getTotalRamMb(): Long {
        return try {
            val activityManager = context.getSystemService(android.content.Context.ACTIVITY_SERVICE) as android.app.ActivityManager
            val memInfo = android.app.ActivityManager.MemoryInfo()
            activityManager.getMemoryInfo(memInfo)
            memInfo.totalMem / (1024 * 1024)
        } catch (e: Exception) {
            // Default to high profile if we can't detect
            4096
        }
    }
    
    /**
     * Get the vault file path
     */
    fun getVaultPath(): String {
        val vaultDir = File(context.filesDir, "vault")
        if (!vaultDir.exists()) {
            vaultDir.mkdirs()
        }
        return File(vaultDir, "vault.dat").absolutePath
    }
    
    /**
     * Check if vault exists
     */
    fun vaultExists(): Boolean {
        return File(getVaultPath()).exists()
    }
    
    /**
     * Create a new vault
     * SECURITY: Passphrase bytes are zeroized after use
     */
    fun create(passphrase: String): Result<Unit> {
        
        val passBytes = passphrase.toByteArray(Charsets.UTF_8)
        return try {
            val result = nativeCreate(getVaultPath(), passBytes)
            if (result == VAULT_OK) {
                Result.success(Unit)
            } else {
                Result.failure(VaultException.fromCode(result))
            }
        } finally {
            secureZeroize(passBytes)
        }
    }
    
    /**
     * Open an existing vault (legacy single-vault mode)
     * SECURITY: Passphrase bytes are zeroized after use
     */
    fun open(passphrase: String): Result<Unit> {
        
        val path = getVaultPath()
        val passBytes = passphrase.toByteArray(Charsets.UTF_8)
        return try {
            val result = nativeOpen(path, passBytes)
            if (result == VAULT_OK) {
                currentVaultPath = path
                Result.success(Unit)
            } else {
                Result.failure(VaultException.fromCode(result))
            }
        } finally {
            secureZeroize(passBytes)
        }
    }

    /**
     * Create a vault at a specific path (for multi-vault support)
     * SECURITY: Passphrase bytes are zeroized after use
     */
    fun createAtPath(path: String, passphrase: String): Result<Unit> {
        
        val passBytes = passphrase.toByteArray(Charsets.UTF_8)
        return try {
            val result = nativeCreate(path, passBytes)
            if (result == VAULT_OK) {
                Result.success(Unit)
            } else {
                Result.failure(VaultException.fromCode(result))
            }
        } finally {
            secureZeroize(passBytes)
        }
    }

    /**
     * Open a vault at a specific path (for multi-vault support)
     * SECURITY: Passphrase bytes are zeroized after use
     */
    fun openAtPath(path: String, passphrase: String): Result<Unit> {
        
        val passBytes = passphrase.toByteArray(Charsets.UTF_8)
        return try {
            val result = nativeOpen(path, passBytes)
            if (result == VAULT_OK) {
                currentVaultPath = path
                Result.success(Unit)
            } else {
                Result.failure(VaultException.fromCode(result))
            }
        } finally {
            secureZeroize(passBytes)
        }
    }
    
    /**
     * Close the vault
     */
    fun close() {
        nativeClose()
        currentVaultPath = null  // Clear tracked path
    }
    
    /**
     * Get the currently open vault path (null if no vault is open)
     */
    fun getCurrentVaultPath(): String? = currentVaultPath
    
    /**
     * Check if vault is open
     */
    fun isOpen(): Boolean {
        return nativeIsOpen()
    }
    
    /**
     * Import a file into the vault
     */
    fun importFile(data: ByteArray, type: Int, name: String, mime: String? = null): Result<ByteArray> {
        val fileId = nativeImportFile(data, type, name, mime)
        return if (fileId != null) {
            Result.success(fileId)
        } else {
            Result.failure(VaultException("Failed to import file", VAULT_ERR_IO))
        }
    }
    
    /**
     * Read a file from the vault
     */
    fun readFile(fileId: ByteArray): Result<ByteArray> {
        val data = nativeReadFile(fileId)
        return if (data != null) {
            Result.success(data)
        } else {
            Result.failure(VaultException("Failed to read file", VAULT_ERR_NOT_FOUND))
        }
    }
    
    /**
     * Read a video chunk from the vault
     */
    fun readChunk(fileId: ByteArray, chunkIndex: Int): Result<ByteArray> {
        val data = nativeReadChunk(fileId, chunkIndex)
        return if (data != null) {
            Result.success(data)
        } else {
            Result.failure(VaultException("Failed to read chunk", VAULT_ERR_NOT_FOUND))
        }
    }
    
    /**
     * Delete a file from the vault
     */
    fun deleteFile(fileId: ByteArray): Result<Unit> {
        val result = nativeDeleteFile(fileId)
        return if (result == VAULT_OK) {
            Result.success(Unit)
        } else {
            Result.failure(VaultException.fromCode(result))
        }
    }

    /**
     * Rename a file in the vault
     */
    fun renameFile(fileId: ByteArray, name: String): Result<Unit> {
        val result = nativeRenameFile(fileId, name)
        return if (result == VAULT_OK) {
            Result.success(Unit)
        } else {
            Result.failure(VaultException.fromCode(result))
        }
    }
    
    /**
     * Compact the vault
     */
    fun compact(): Result<Unit> {
        val result = nativeCompact()
        return if (result == VAULT_OK) {
            Result.success(Unit)
        } else {
            Result.failure(VaultException.fromCode(result))
        }
    }
    
    /**
     * Get number of entries in vault
     */
    fun getEntryCount(): Int {
        return nativeGetEntryCount()
    }
    
    /**
     * List all files in vault
     */
    fun listFiles(): Result<List<VaultFileEntry>> {
        val entries = nativeListFiles()
        return if (entries != null) {
            Result.success(entries.toList())
        } else {
            Result.failure(VaultException("Failed to list files", VAULT_ERR_NOT_OPEN))
        }
    }

    /**
     * Verify password without changing vault state
     * If vault is already open, this will temporarily close and reopen
     * Uses the currently tracked vault path for multi-vault support
     * SECURITY: Password bytes are zeroized after use
     */
    fun verifyPassword(password: String): Boolean {

        val wasOpen = nativeIsOpen()
        val pathToVerify = currentVaultPath ?: getVaultPath()
        val passBytes = password.toByteArray(Charsets.UTF_8)
        
        SecureLog.d("VaultEngine", "verifyPassword: wasOpen=$wasOpen")
        
        return try {
            if (wasOpen) {
                nativeClose()
                val result = nativeOpen(pathToVerify, passBytes)
                if (result == VAULT_OK) {
                    currentVaultPath = pathToVerify
                    true
                } else {
                    false
                }
            } else {
                val result = nativeOpen(pathToVerify, passBytes)
                if (result == VAULT_OK) {
                    nativeClose()
                    true
                } else {
                    false
                }
            }
        } finally {
            secureZeroize(passBytes)
        }
    }

    /**
     * Change vault password
     * Verifies old password, re-encrypts master key with new password, updates vault file
     * SECURITY: Password bytes are zeroized after use
     */
    fun changePassword(currentPassword: String, newPassword: String): Boolean {
        if (!nativeIsOpen()) {
            SecureLog.e("VaultEngine", "changePassword: Vault not open")
            return false
        }
        
        val currentBytes = currentPassword.toByteArray(Charsets.UTF_8)
        val newBytes = newPassword.toByteArray(Charsets.UTF_8)
        
        return try {
            SecureLog.i("VaultEngine", "changePassword: Processing...")
            val result = nativeChangePassword(currentBytes, newBytes)
            SecureLog.i("VaultEngine", "changePassword: Complete")
            result == VAULT_OK
        } finally {
            secureZeroize(currentBytes)
            secureZeroize(newBytes)
        }
    }
    
    /**
     * Securely wipe a file by overwriting with random data before deletion
     * SECURITY: Prevents forensic recovery of temp files
     * @param path Path to file to wipe
     * @return true if successful
     */
    fun secureWipeFile(path: String): Boolean {
        return try {
            val result = nativeSecureWipeFile(path)
            if (result) {
                // Delete file after wiping
                java.io.File(path).delete()
            }
            result
        } catch (e: Exception) {
            SecureLog.e("VaultEngine", "secureWipeFile failed")
            // Fallback: at least delete the file
            try {
                java.io.File(path).delete()
            } catch (_: Exception) {}
            false
        }
    }
    
    // ========================================================================
    // Streaming Import API (for large files up to 50GB)
    // ========================================================================
    
    /**
     * Initialize streaming import subsystem
     * Called automatically when needed
     */
    fun streamingInit(): Result<Unit> {
        val result = nativeStreamingInit()
        return if (result == StreamingConstants.OK) {
            Result.success(Unit)
        } else {
            Result.failure(VaultException("Failed to init streaming", result))
        }
    }
    
    /**
     * Compute source file hash for resume verification
     * Hash = SHA256(first 1MB || last 1MB || file_size)
     */
    fun streamingComputeSourceHash(firstMb: ByteArray, lastMb: ByteArray?, fileSize: Long): ByteArray? {
        return nativeStreamingComputeSourceHash(firstMb, lastMb, fileSize)
    }
    
    /**
     * Start a new streaming import or resume an existing one
     * @return StreamingStartResult with importId and resumeFromChunk
     */
    fun streamingStart(
        sourceUri: String,
        sourceHash: ByteArray,
        name: String,
        mime: String?,
        type: Int,
        fileSize: Long
    ): Result<StreamingStartResult> {
        val result = nativeStreamingStart(sourceUri, sourceHash, name, mime, type, fileSize)
        return if (result != null) {
            Result.success(result)
        } else {
            Result.failure(VaultException("Failed to start streaming import", StreamingConstants.ERR_IO))
        }
    }
    
    /**
     * Write a single chunk of data
     * SECURITY: plaintext is zeroized after encryption
     */
    fun streamingWriteChunk(importId: ByteArray, plaintext: ByteArray, chunkIndex: Int): Result<Unit> {
        val result = nativeStreamingWriteChunk(importId, plaintext, chunkIndex)
        return if (result == StreamingConstants.OK) {
            Result.success(Unit)
        } else {
            Result.failure(VaultException("Failed to write chunk", result))
        }
    }
    
    /**
     * Finalize streaming import
     * @return fileId of the imported file
     */
    fun streamingFinish(importId: ByteArray): Result<ByteArray> {
        val fileId = nativeStreamingFinish(importId)
        return if (fileId != null) {
            Result.success(fileId)
        } else {
            Result.failure(VaultException("Failed to finish streaming import", StreamingConstants.ERR_IO))
        }
    }
    
    /**
     * Abort streaming import and cleanup
     */
    fun streamingAbort(importId: ByteArray): Result<Unit> {
        val result = nativeStreamingAbort(importId)
        return if (result == StreamingConstants.OK) {
            Result.success(Unit)
        } else {
            Result.failure(VaultException("Failed to abort streaming import", result))
        }
    }
    
    /**
     * Get state of a specific import
     */
    fun streamingGetState(importId: ByteArray): StreamingImportState? {
        return nativeStreamingGetState(importId)
    }
    
    /**
     * List all pending imports
     */
    fun streamingListPending(): List<StreamingImportState> {
        return nativeStreamingListPending()?.toList() ?: emptyList()
    }
    
    /**
     * Cleanup old/stale pending imports
     * SECURITY: Securely wipes chunk files before deletion
     * @param maxAgeMs Maximum age in milliseconds (0 = cleanup all)
     * @return Number of imports cleaned up
     */
    fun streamingCleanupOld(maxAgeMs: Long = 0): Int {
        return nativeStreamingCleanupOld(maxAgeMs)
    }
}

/**
 * Exception for vault operations
 */
class VaultException(message: String, val errorCode: Int) : Exception(message) {
    companion object {
        fun fromCode(code: Int): VaultException {
            val message = when (code) {
                VaultEngine.VAULT_ERR_INVALID_PARAM -> "Invalid parameter"
                VaultEngine.VAULT_ERR_MEMORY -> "Memory allocation failed"
                VaultEngine.VAULT_ERR_IO -> "I/O error"
                VaultEngine.VAULT_ERR_CRYPTO -> "Cryptographic error"
                VaultEngine.VAULT_ERR_AUTH_FAIL -> "Authentication failed"
                VaultEngine.VAULT_ERR_CORRUPTED -> "Vault corrupted"
                VaultEngine.VAULT_ERR_NOT_FOUND -> "Not found"
                VaultEngine.VAULT_ERR_ALREADY_EXISTS -> "Already exists"
                VaultEngine.VAULT_ERR_NOT_OPEN -> "Vault not open"
                VaultEngine.VAULT_ERR_PASSPHRASE_TOO_SHORT -> "Passphrase too short"
                else -> "Unknown error"
            }
            return VaultException(message, code)
        }
    }
    
    fun isAuthError(): Boolean = errorCode == VaultEngine.VAULT_ERR_AUTH_FAIL
    fun isCorrupted(): Boolean = errorCode == VaultEngine.VAULT_ERR_CORRUPTED
}

/**
 * Data class for vault file entry
 */
data class VaultFileEntry(
    val fileId: ByteArray,
    val name: String,
    val type: Int,
    val size: Long,
    val createdAt: Long,
    val mimeType: String?,
    val chunkCount: Int = 0
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as VaultFileEntry
        return fileId.contentEquals(other.fileId)
    }
    
    override fun hashCode(): Int = fileId.contentHashCode()
}
