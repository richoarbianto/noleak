package com.noleak.noleak.vault

import android.content.Context
import org.json.JSONArray
import com.noleak.noleak.security.SecureLog
import com.noleak.noleak.security.RegistryCrypto
import org.json.JSONObject
import java.io.File
import java.util.UUID

/**
 * VaultRegistry - Manages multiple vaults on device
 * 
 * SECURITY:
 * - Registry is encrypted using Android Keystore
 * - Metadata (id, filename, timestamp) is protected at rest
 * - Falls back to plaintext if Keystore unavailable (legacy devices)
 */
class VaultRegistry private constructor(private val context: Context) {
    
    companion object {
        private const val TAG = "VaultRegistry"
        private const val REGISTRY_FILE = "vault_registry.enc"  // Encrypted registry
        private const val LEGACY_REGISTRY_FILE = "vault_registry.json"  // Old plaintext
        private const val MAX_VAULTS = 10
        
        @Volatile
        private var instance: VaultRegistry? = null
        
        fun getInstance(context: Context): VaultRegistry {
            return instance ?: synchronized(this) {
                instance ?: VaultRegistry(context.applicationContext).also {
                    instance = it
                }
            }
        }
    }
    
    private val registryFile: File
        get() = File(context.filesDir, REGISTRY_FILE)
    
    private val legacyRegistryFile: File
        get() = File(context.filesDir, LEGACY_REGISTRY_FILE)
    
    private val vaultDir: File
        get() {
            val dir = File(context.filesDir, "vault")
            if (!dir.exists()) dir.mkdirs()
            return dir
        }

    private fun listVaultsFromDisk(): List<VaultMetadata> {
        val files = vaultDir.listFiles { file ->
            file.isFile && file.name.endsWith(".dat", ignoreCase = true)
        } ?: return emptyList()

        return files.map { file ->
            VaultMetadata(
                id = file.name,
                filename = file.name,
                createdAt = file.lastModified(),
                sizeBytes = file.length()
            )
        }
    }
    
    /**
     * Data class for vault metadata in registry
     */
    data class VaultMetadata(
        val id: String,
        val filename: String,
        val createdAt: Long,
        val sizeBytes: Long = 0
    )
    
    /**
     * Load all vault metadata from registry
     * SECURITY: Reads encrypted registry, falls back to legacy plaintext if needed
     */
    fun listVaults(): List<VaultMetadata> {
        // Try encrypted registry first
        if (registryFile.exists()) {
            return try {
                val encrypted = registryFile.readText()
                val json = RegistryCrypto.decrypt(encrypted)
                if (json != null) {
                    parseRegistryJson(json)
                } else {
                    SecureLog.e(TAG, "Failed to decrypt registry")
                    listVaultsFromDisk()
                }
            } catch (e: Exception) {
                SecureLog.e(TAG, "Failed to load encrypted registry")
                listVaultsFromDisk()
            }
        }
        
        // Check for legacy plaintext registry and migrate
        if (legacyRegistryFile.exists()) {
            return try {
                val json = legacyRegistryFile.readText()
                val vaults = parseRegistryJson(json)
                // Migrate to encrypted
                saveRegistry(vaults)
                // Delete legacy plaintext file regardless of result
                legacyRegistryFile.delete()
                SecureLog.i(TAG, "Migrated plaintext registry to encrypted")
                vaults
            } catch (e: Exception) {
                SecureLog.e(TAG, "Failed to migrate legacy registry")
                listVaultsFromDisk()
            }
        }
        
        // Check for legacy single vault
        val legacyVault = File(vaultDir, "vault.dat")
        if (legacyVault.exists()) {
            val vaultId = UUID.randomUUID().toString()
            val metadata = VaultMetadata(
                id = vaultId,
                filename = "vault.dat",
                createdAt = legacyVault.lastModified(),
                sizeBytes = legacyVault.length()
            )
            saveRegistry(listOf(metadata))
            SecureLog.i(TAG, "Migrated legacy vault to registry")
            return listOf(metadata)
        }

        return listVaultsFromDisk()
    }
    
    /**
     * Parse JSON registry data
     */
    private fun parseRegistryJson(json: String): List<VaultMetadata> {
        val array = JSONArray(json)
        val vaults = mutableListOf<VaultMetadata>()
        
        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            val filename = obj.getString("filename")
            val vaultFile = File(vaultDir, filename)
            
            if (vaultFile.exists()) {
                vaults.add(VaultMetadata(
                    id = obj.getString("id"),
                    filename = filename,
                    createdAt = obj.getLong("createdAt"),
                    sizeBytes = vaultFile.length()
                ))
            }
        }
        return vaults
    }
    
    /**
     * Save registry to encrypted file
     * SECURITY: Uses Android Keystore for encryption
     */
    private fun saveRegistry(vaults: List<VaultMetadata>): Boolean {
        try {
            val array = JSONArray()
            vaults.forEach { vault ->
                val obj = JSONObject().apply {
                    put("id", vault.id)
                    put("filename", vault.filename)
                    put("createdAt", vault.createdAt)
                }
                array.put(obj)
            }
            
            val json = array.toString()
            val encrypted = RegistryCrypto.encrypt(json)
            
            if (encrypted != null) {
                registryFile.writeText(encrypted)
                if (legacyRegistryFile.exists()) {
                    legacyRegistryFile.delete()
                }
                return true
            } else {
                SecureLog.e(TAG, "Failed to encrypt registry, not saving plaintext")
                return false
            }
        } catch (e: Exception) {
            SecureLog.e(TAG, "Failed to save registry")
            return false
        }
    }
    
    /**
     * Check if can add more vaults
     */
    fun canAddVault(): Boolean {
        return listVaults().size < MAX_VAULTS
    }
    
    /**
     * Generate random vault filename using UUID
     * This prevents metadata leak through filename patterns
     */
    private fun nextVaultFilename(): String {
        // Generate cryptographically random filename (no patterns = no leak)
        val randomBytes = ByteArray(16)
        java.security.SecureRandom().nextBytes(randomBytes)
        val hexString = randomBytes.joinToString("") { "%02x".format(it) }
        return "$hexString.dat"
    }
    
    /**
     * Create a new vault entry in registry
     * Returns vault ID and path
     */
    fun createVaultEntry(): Pair<String, String>? {
        if (!canAddVault()) {
            SecureLog.e(TAG, "Maximum vaults reached")
            return null
        }

        val vaultId = UUID.randomUUID().toString()
        val filename = nextVaultFilename()
        val vaultPath = File(vaultDir, filename).absolutePath
        
        val metadata = VaultMetadata(
            id = vaultId,
            filename = filename,
            createdAt = System.currentTimeMillis()
        )
        
        val existing = listVaults().toMutableList()
        existing.add(metadata)
        val saved = saveRegistry(existing)

        val finalId = if (saved) vaultId else filename
        if (!saved) {
            SecureLog.e(TAG, "Registry unavailable, falling back to filename ID")
        }
        SecureLog.i(TAG, "Created vault entry: $finalId -> $filename")
        return Pair(finalId, vaultPath)
    }
    
    /**
     * Get vault path by ID
     */
    fun getVaultPath(vaultId: String): String? {
        val vault = listVaults().find { it.id == vaultId }
        if (vault != null) {
            return File(vaultDir, vault.filename).absolutePath
        }
        val byFilename = File(vaultDir, vaultId)
        return if (byFilename.exists()) byFilename.absolutePath else null
    }
    
    /**
     * Delete vault from registry and disk
     */
    fun deleteVault(vaultId: String): Boolean {
        val vaults = listVaults().toMutableList()
        val vault = vaults.find { it.id == vaultId }
            ?: run {
                val byFilename = File(vaultDir, vaultId)
                if (!byFilename.exists()) return false
                VaultMetadata(
                    id = vaultId,
                    filename = byFilename.name,
                    createdAt = byFilename.lastModified(),
                    sizeBytes = byFilename.length()
                )
            }

        // Delete vault file
        val vaultFile = File(vaultDir, vault.filename)
        if (vaultFile.exists()) {
            // Secure delete - overwrite with random data
            try {
                vaultFile.outputStream().use { out ->
                    val buffer = ByteArray(4096)
                    var remaining = vaultFile.length()
                    while (remaining > 0) {
                        val toWrite = minOf(remaining, buffer.size.toLong()).toInt()
                        java.security.SecureRandom().nextBytes(buffer)
                        out.write(buffer, 0, toWrite)
                        remaining -= toWrite
                    }
                }
            } catch (e: Exception) {
                SecureLog.e(TAG, "Secure overwrite failed: ${e.message}")
            }
            vaultFile.delete()
        }
        
        // Remove from registry
        vaults.removeIf { it.id == vaultId || it.filename == vault.filename }
        saveRegistry(vaults)
        
        SecureLog.i(TAG, "Deleted vault: $vaultId")
        return true
    }
    
    /**
     * Add imported vault to registry
     */
    fun addImportedVault(vaultPath: String): VaultMetadata? {
        if (!canAddVault()) return null
        
        val vaultFile = File(vaultPath)
        if (!vaultFile.exists()) return null
        
        // Move/copy to vault directory if not already there
        val targetFile = if (vaultFile.parent == vaultDir.absolutePath) {
            vaultFile
        } else {
            val filename = nextVaultFilename()
            val target = File(vaultDir, filename)
            vaultFile.copyTo(target, overwrite = true)
            target
        }
        
        val vaultId = UUID.randomUUID().toString()
        val metadata = VaultMetadata(
            id = vaultId,
            filename = targetFile.name,
            createdAt = System.currentTimeMillis(),
            sizeBytes = targetFile.length()
        )

        val existing = listVaults().toMutableList()
        existing.add(metadata)
        val saved = saveRegistry(existing)

        val finalMetadata = if (saved) {
            metadata
        } else {
            SecureLog.e(TAG, "Registry unavailable, falling back to filename ID")
            metadata.copy(id = targetFile.name)
        }
        SecureLog.i(TAG, "Added imported vault: ${finalMetadata.id}")
        return finalMetadata
    }
    
    /**
     * Get vault metadata by ID
     */
    fun getVault(vaultId: String): VaultMetadata? {
        return listVaults().find { it.id == vaultId }
    }
}
