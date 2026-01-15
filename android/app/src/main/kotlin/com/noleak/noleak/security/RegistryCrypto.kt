package com.noleak.noleak.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import android.util.Base64

/**
 * RegistryCrypto - Encrypts vault registry metadata using Android Keystore
 * 
 * SECURITY:
 * - Uses hardware-backed keystore when available
 * - AES-256-GCM for authenticated encryption
 * - Key is bound to device, cannot be exported
 */
object RegistryCrypto {
    private const val KEYSTORE_ALIAS = "noleak_registry_key"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH = 128
    private const val GCM_IV_LENGTH = 12
    
    /**
     * Get or create the registry encryption key from Android Keystore
     */
    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        
        // Check if key exists
        if (keyStore.containsAlias(KEYSTORE_ALIAS)) {
            return keyStore.getKey(KEYSTORE_ALIAS, null) as SecretKey
        }
        
        // Generate new key
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )
        
        val keySpec = KeyGenParameterSpec.Builder(
            KEYSTORE_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false) // Registry needs to be accessible at app start
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setUnlockedDeviceRequired(false) // Need to read registry on cold start
                    setIsStrongBoxBacked(false) // StrongBox not available on all devices
                }
            }
            .build()
        
        keyGenerator.init(keySpec)
        return keyGenerator.generateKey()
    }
    
    /**
     * Encrypt data using Android Keystore
     * @return Base64-encoded encrypted data (IV prepended)
     */
    fun encrypt(plaintext: String): String? {
        return try {
            val key = getOrCreateKey()
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            
            val iv = cipher.iv
            val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
            
            // Prepend IV to ciphertext
            val combined = ByteArray(iv.size + ciphertext.size)
            System.arraycopy(iv, 0, combined, 0, iv.size)
            System.arraycopy(ciphertext, 0, combined, iv.size, ciphertext.size)
            
            Base64.encodeToString(combined, Base64.NO_WRAP)
        } catch (e: Exception) {
            SecureLog.e("RegistryCrypto", "Encryption failed: ${e.message}")
            null
        }
    }
    
    /**
     * Decrypt data using Android Keystore
     * @param encrypted Base64-encoded encrypted data (IV prepended)
     * @return Decrypted plaintext
     */
    fun decrypt(encrypted: String): String? {
        return try {
            val key = getOrCreateKey()
            val combined = Base64.decode(encrypted, Base64.NO_WRAP)
            
            if (combined.size < GCM_IV_LENGTH) {
                SecureLog.e("RegistryCrypto", "Invalid encrypted data length")
                return null
            }
            
            // Extract IV and ciphertext
            val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
            val ciphertext = combined.copyOfRange(GCM_IV_LENGTH, combined.size)
            
            val cipher = Cipher.getInstance(TRANSFORMATION)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            
            val plaintext = cipher.doFinal(ciphertext)
            String(plaintext, Charsets.UTF_8)
        } catch (e: Exception) {
            SecureLog.e("RegistryCrypto", "Decryption failed")
            null
        }
    }
    
    /**
     * Check if keystore-based encryption is available
     */
    fun isAvailable(): Boolean {
        return try {
            getOrCreateKey()
            true
        } catch (e: Exception) {
            false
        }
    }
}
