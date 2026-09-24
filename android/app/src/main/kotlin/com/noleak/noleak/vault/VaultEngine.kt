package com.noleak.noleak.vault

import android.content.Context
import java.io.File
import java.util.concurrent.atomic.AtomicLong
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
        const val VAULT_ERR_RETIREMENT_PENDING = -11
        
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
    private external fun nativeSetKdfProfile(
        totalRamMb: Long,
        availableRamMb: Long,
        isLowRamDevice: Boolean,
        is64BitProcess: Boolean
    )
    private external fun nativeGetKdfInfo(): LongArray?
    private external fun nativeInspectKdfInfo(path: String): LongArray?
    private external fun nativeCreate(path: String, passphrase: ByteArray): Int
    private external fun nativeOpen(path: String, passphrase: ByteArray): Int
    private external fun nativeVerifyPassword(passphrase: ByteArray): Int
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
    private val sessionGeneration = AtomicLong()
    private var vaultMutationVersion = 0L
    
    // Track the currently open vault path for multi-vault support
    private var currentVaultPath: String? = null

    private fun markCommittedMutation(result: Int) {
        if (result == VAULT_OK || result == VAULT_ERR_RETIREMENT_PENDING) {
            vaultMutationVersion++
        }
    }

    private fun completeOpen(path: String, generation: Long): Result<Unit> {
        vaultMutationVersion++
        if (generation != sessionGeneration.get()) {
            nativeClose()
            currentVaultPath = null
            return Result.failure(VaultException("Vault session invalidated", VAULT_ERR_NOT_OPEN))
        }
        currentVaultPath = path
        cleanupStalePendingImportsAfterOpen()
        if (generation != sessionGeneration.get()) {
            nativeClose()
            currentVaultPath = null
            return Result.failure(VaultException("Vault session invalidated", VAULT_ERR_NOT_OPEN))
        }
        return Result.success(Unit)
    }
    
    /**
     * Initialize the vault engine
     * SECURITY: Sets adaptive KDF profile based on device RAM
     */
    @Synchronized
    fun initialize(): Result<Unit> {
        if (initialized) return Result.success(Unit)
        
        // SECURITY: Set adaptive KDF profile based on device RAM BEFORE init
        // This ensures proper memory settings even if init has issues
        configureKdfProfile()
        
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
    private data class MemoryProfileInput(
        val totalRamMb: Long,
        val availableRamMb: Long,
        val isLowRam: Boolean,
        val is64Bit: Boolean
    )

    private fun getMemoryProfileInput(): MemoryProfileInput {
        return try {
            val activityManager = context.getSystemService(android.content.Context.ACTIVITY_SERVICE) as android.app.ActivityManager
            val memInfo = android.app.ActivityManager.MemoryInfo()
            activityManager.getMemoryInfo(memInfo)
            MemoryProfileInput(
                totalRamMb = memInfo.totalMem / (1024 * 1024),
                availableRamMb = memInfo.availMem / (1024 * 1024),
                isLowRam = activityManager.isLowRamDevice || memInfo.lowMemory,
                is64Bit = android.os.Process.is64Bit()
            )
        } catch (e: Exception) {
            MemoryProfileInput(0, 0, true, false)
        }
    }

    private fun configureKdfProfile() {
        val memory = getMemoryProfileInput()
        nativeSetKdfProfile(
            memory.totalRamMb,
            memory.availableRamMb,
            memory.isLowRam,
            memory.is64Bit
        )
        SecureLog.i("VaultEngine", "Selected KDF profile for ${memory.totalRamMb}MB RAM device")
    }

    private fun cleanupStalePendingImportsAfterOpen() {
        val cleaned = nativeStreamingCleanupOld(24 * 60 * 60 * 1000L)
        if (cleaned > 0) {
            SecureLog.i("VaultEngine", "Cleaned up $cleaned stale pending imports")
        }
    }
    
    /**
     * Get the vault file path
     */
    @Synchronized
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
    @Synchronized
    fun vaultExists(): Boolean {
        return File(getVaultPath()).exists()
    }
    
    /**
     * Create a new vault
     * SECURITY: Passphrase bytes are zeroized after use
     */
    @Synchronized
    fun create(passphrase: ByteArray): Result<Unit> {
        configureKdfProfile()
        val passBytes = passphrase.copyOf()
        return try {
            val result = nativeCreate(getVaultPath(), passBytes)
            markCommittedMutation(result)
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
    fun open(passphrase: ByteArray): Result<Unit> {
        val generation = sessionGeneration.get()
        val path = getVaultPath()
        val passBytes = passphrase.copyOf()
        return synchronized(this) {
            try {
                if (generation != sessionGeneration.get()) {
                    return@synchronized Result.failure(
                        VaultException("Vault session invalidated", VAULT_ERR_NOT_OPEN)
                    )
                }
                val result = nativeOpen(path, passBytes)
                if (result == VAULT_OK) completeOpen(path, generation)
                else Result.failure(VaultException.fromCode(result))
            } finally {
                secureZeroize(passBytes)
            }
        }
    }

    /**
     * Create a vault at a specific path (for multi-vault support)
     * SECURITY: Passphrase bytes are zeroized after use
     */
    @Synchronized
    fun createAtPath(path: String, passphrase: ByteArray): Result<Unit> {
        configureKdfProfile()
        val passBytes = passphrase.copyOf()
        return try {
            val result = nativeCreate(path, passBytes)
            markCommittedMutation(result)
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
    fun openAtPath(path: String, passphrase: ByteArray): Result<Unit> {
        val generation = sessionGeneration.get()
        val passBytes = passphrase.copyOf()
        return synchronized(this) {
            try {
                if (generation != sessionGeneration.get()) {
                    return@synchronized Result.failure(
                        VaultException("Vault session invalidated", VAULT_ERR_NOT_OPEN)
                    )
                }
                val result = nativeOpen(path, passBytes)
                if (result == VAULT_OK) completeOpen(path, generation)
                else Result.failure(VaultException.fromCode(result))
            } finally {
                secureZeroize(passBytes)
            }
        }
    }
    
    /**
     * Close the vault
     */
    fun close() {
        sessionGeneration.incrementAndGet()
        synchronized(this) {
            nativeStreamingCleanupOld(0)
            nativeClose()
            currentVaultPath = null
        }
    }
    
    /**
     * Get the currently open vault path (null if no vault is open)
     */
    @Synchronized
    fun getCurrentVaultPath(): String? = currentVaultPath
    
    /**
     * Check if vault is open
     */
    @Synchronized
    fun isOpen(): Boolean {
        return nativeIsOpen()
    }

    @Synchronized
    fun getKdfInfo(): Map<String, Any> {
        val values = nativeGetKdfInfo() ?: longArrayOf(0, 0, 0, 0)
        return mapOf(
            "memoryMiB" to values[0] / (1024 * 1024),
            "opslimit" to values[1],
            "parallelism" to 1L,
            "storedParallelism" to values[2],
            "storedProfile" to (values[3] == 1L)
        )
    }

    @Synchronized
    fun inspectVaultKdfInfo(path: String): Result<Map<String, Any>> {
        configureKdfProfile()
        val values = nativeInspectKdfInfo(path)
            ?: return Result.failure(
                VaultException("Vault header is invalid or corrupted", VAULT_ERR_CORRUPTED)
            )
        if (values.size < 7) {
            return Result.failure(
                VaultException("Vault KDF metadata is incomplete", VAULT_ERR_CORRUPTED)
            )
        }

        val importedMemoryMiB = values[0] / (1024 * 1024)
        val deviceMemoryMiB = values[3] / (1024 * 1024)
        return Result.success(mapOf(
            "kdfMemoryMiB" to importedMemoryMiB,
            "kdfOpslimit" to values[1],
            "kdfParallelism" to values[2],
            "deviceKdfMemoryMiB" to deviceMemoryMiB,
            "deviceKdfOpslimit" to values[4],
            "deviceKdfParallelism" to values[5],
            "retirementPending" to (values[6] != 0L),
            "kdfExceedsDevice" to
                (importedMemoryMiB > deviceMemoryMiB || values[1] > values[4])
        ))
    }

    @Synchronized
    fun beginVaultExport(path: String): Result<LongArray> {
        val source = File(path)
        val info = nativeInspectKdfInfo(path)
        if (!source.isFile || info == null || info.size < 7 || info[6] != 0L) {
            return Result.failure(
                VaultException("Vault state is not safe to export", VAULT_ERR_CORRUPTED)
            )
        }
        return Result.success(
            longArrayOf(vaultMutationVersion, source.length(), source.lastModified())
        )
    }

    @Synchronized
    fun isVaultExportCurrent(path: String, token: LongArray): Boolean {
        if (token.size != 3) return false
        val source = File(path)
        val info = nativeInspectKdfInfo(path)
        return source.isFile && info != null && info.size >= 7 && info[6] == 0L &&
            token[0] == vaultMutationVersion && token[1] == source.length() &&
            token[2] == source.lastModified()
    }

    @Synchronized
    fun replaceVaultFile(source: File, destination: File): Boolean {
        val replaced = source.renameTo(destination)
        if (replaced) vaultMutationVersion++
        return replaced
    }
    
    /**
     * Import a file into the vault
     */
    @Synchronized
    fun importFile(data: ByteArray, type: Int, name: String, mime: String? = null): Result<ByteArray> {
        val fileId = nativeImportFile(data, type, name, mime)
        return if (fileId != null) {
            vaultMutationVersion++
            Result.success(fileId)
        } else {
            Result.failure(VaultException("Failed to import file", VAULT_ERR_IO))
        }
    }
    
    /**
     * Read a file from the vault
     */
    @Synchronized
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
    @Synchronized
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
    @Synchronized
    fun deleteFile(fileId: ByteArray): Result<Unit> {
        val result = nativeDeleteFile(fileId)
        markCommittedMutation(result)
        return if (result == VAULT_OK) {
            Result.success(Unit)
        } else {
            Result.failure(VaultException.fromCode(result))
        }
    }

    /**
     * Rename a file in the vault
     */
    @Synchronized
    fun renameFile(fileId: ByteArray, name: String): Result<Unit> {
        val result = nativeRenameFile(fileId, name)
        markCommittedMutation(result)
        return if (result == VAULT_OK) {
            Result.success(Unit)
        } else {
            Result.failure(VaultException.fromCode(result))
        }
    }
    
    /**
     * Compact the vault
     */
    @Synchronized
    fun compact(): Result<Unit> {
        val result = nativeCompact()
        markCommittedMutation(result)
        return if (result == VAULT_OK) {
            Result.success(Unit)
        } else {
            Result.failure(VaultException.fromCode(result))
        }
    }
    
    /**
     * Get number of entries in vault
     */
    @Synchronized
    fun getEntryCount(): Int {
        return nativeGetEntryCount()
    }
    
    /**
     * List all files in vault
     */
    @Synchronized
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
     * An open vault is verified in place; a closed vault is opened temporarily.
     * Uses the currently tracked vault path for multi-vault support
     * SECURITY: Password bytes are zeroized after use
     */
    @Synchronized
    fun verifyPassword(password: ByteArray): Result<Boolean> {

        val wasOpen = nativeIsOpen()
        val pathToVerify = currentVaultPath ?: getVaultPath()
        val passBytes = password.copyOf()
        
        SecureLog.d("VaultEngine", "verifyPassword: wasOpen=$wasOpen")
        
        return try {
            if (wasOpen) {
                val result = nativeVerifyPassword(passBytes)
                if (result == VAULT_OK) {
                    Result.success(true)
                } else {
                    if (result == VAULT_ERR_AUTH_FAIL) Result.success(false)
                    else Result.failure(VaultException.fromCode(result))
                }
            } else {
                val result = nativeOpen(pathToVerify, passBytes)
                if (result == VAULT_OK) {
                    nativeClose()
                    Result.success(true)
                } else {
                    if (result == VAULT_ERR_AUTH_FAIL) Result.success(false)
                    else Result.failure(VaultException.fromCode(result))
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
    @Synchronized
    fun changePassword(currentPassword: ByteArray, newPassword: ByteArray): Result<Unit> {
        if (!nativeIsOpen()) {
            SecureLog.e("VaultEngine", "changePassword: Vault not open")
            return Result.failure(VaultException.fromCode(VAULT_ERR_NOT_OPEN))
        }
        
        val currentBytes = currentPassword.copyOf()
        val newBytes = newPassword.copyOf()
        
        return try {
            SecureLog.i("VaultEngine", "changePassword: Processing...")
            val result = nativeChangePassword(currentBytes, newBytes)
            markCommittedMutation(result)
            SecureLog.i("VaultEngine", "changePassword: Complete")
            if (result == VAULT_OK) Result.success(Unit)
            else Result.failure(VaultException.fromCode(result))
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
    @Synchronized
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
    @Synchronized
    fun streamingComputeSourceHash(firstMb: ByteArray, lastMb: ByteArray?, fileSize: Long): ByteArray? {
        return nativeStreamingComputeSourceHash(firstMb, lastMb, fileSize)
    }
    
    /**
     * Start a new streaming import or resume an existing one
     * @return StreamingStartResult with importId and resumeFromChunk
     */
    @Synchronized
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
    @Synchronized
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
    @Synchronized
    fun streamingFinish(importId: ByteArray): Result<ByteArray> {
        val fileId = nativeStreamingFinish(importId)
        return if (fileId != null) {
            vaultMutationVersion++
            Result.success(fileId)
        } else {
            Result.failure(VaultException("Failed to finish streaming import", StreamingConstants.ERR_IO))
        }
    }
    
    /**
     * Abort streaming import and cleanup
     */
    @Synchronized
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
    @Synchronized
    fun streamingGetState(importId: ByteArray): StreamingImportState? {
        return nativeStreamingGetState(importId)
    }
    
    /**
     * List all pending imports
     */
    @Synchronized
    fun streamingListPending(): List<StreamingImportState> {
        return nativeStreamingListPending()?.toList() ?: emptyList()
    }
    
    /**
     * Cleanup old/stale pending imports
     * SECURITY: Securely wipes chunk files before deletion
     * @param maxAgeMs Maximum age in milliseconds (0 = cleanup all)
     * @return Number of imports cleaned up
     */
    @Synchronized
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
                VaultEngine.VAULT_ERR_RETIREMENT_PENDING -> "The previous vault root could not yet be retired"
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
