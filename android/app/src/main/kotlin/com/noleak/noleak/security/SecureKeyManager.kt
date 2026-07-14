package com.noleak.noleak.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * SecureKeyManager - Android Keystore Integration with Biometric Protection
 * 
 * Manages cryptographic keys stored in the Android Keystore with hardware-backed
 * security and biometric authentication requirements.
 * 
 * KEY PROPERTIES:
 * - Algorithm: AES-256-GCM
 * - Storage: Android Keystore (hardware-backed when available)
 * - Authentication: Required for every use
 * - Invalidation: Key invalidated on biometric enrollment changes
 * 
 * BIOMETRIC AUTHENTICATION:
 * - Supports strong biometric authenticators
 * - Requires a Keystore CryptoObject so authentication unlocks actual key use
 * - Uses BiometricPrompt for consistent UI
 * 
 * Usage:
 * ```kotlin
 * secureKeyManager.authenticateWithBiometric(
 *     activity = this,
 *     onSuccess = { /* proceed */ },
 *     onError = { message -> /* handle error */ }
 * )
 * ```
 */
class SecureKeyManager(private val context: Context) {
    
    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEY_ALIAS = "noleak_vault_biometric_v2"
        private const val LEGACY_KEY_ALIAS = "noleak_vault_key"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val TAG = "SecureKeyManager"
    }
    
    private val keyStore: KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply {
        load(null)
    }
    
    /**
     * Check if biometric authentication is available on this device.
     * 
     * @return true if device supports strong biometric authentication
     */
    fun isBiometricAvailable(): Boolean {
        val biometricManager = BiometricManager.from(context)
        return when (biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        )) {
            BiometricManager.BIOMETRIC_SUCCESS -> true
            else -> false
        }
    }
    
    /**
     * Setup a biometric-protected key in Android Keystore.
     * 
     * Creates an AES-256-GCM key that requires user authentication for every use.
     * The key is invalidated if biometric enrollment changes (e.g., new fingerprint added).
     * 
     * This method is idempotent - if the key already exists, it does nothing.
     */
    fun setupBiometricKey() {
        if (keyStore.containsAlias(KEY_ALIAS)) {
            return // Key already exists
        }

        deleteAlias(LEGACY_KEY_ALIAS)
        
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEYSTORE_PROVIDER
        )
        
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                0, // Require authentication every time
                KeyProperties.AUTH_BIOMETRIC_STRONG
            )
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }

        val keyGenSpec = builder
            .setInvalidatedByBiometricEnrollment(true)
            .build()
        
        keyGenerator.init(keyGenSpec)
        keyGenerator.generateKey()
    }
    
    /**
     * Get a cipher initialized for encryption with the biometric-protected key.
     * 
     * This cipher can be used as a CryptoObject for BiometricPrompt to ensure
     * the key is only accessible after successful biometric authentication.
     * 
     * @return Cipher initialized in ENCRYPT_MODE with the keystore key
     * @throws Exception if key doesn't exist or cannot be accessed
     */
    fun getCipherForAuth(): Cipher {
        val key = keyStore.getKey(KEY_ALIAS, null) as SecretKey
        return Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, key)
        }
    }

    private fun getCipherForAuthWithRecovery(): Cipher {
        setupBiometricKey()

        return try {
            getCipherForAuth()
        } catch (e: Exception) {
            SecureLog.w(TAG, "Recreating biometric key after cipher init failed: ${e.javaClass.simpleName}")
            deleteKey()
            setupBiometricKey()
            getCipherForAuth()
        }
    }
    
    /**
     * Authenticate the user with a strong biometric-backed Keystore key.
     * 
     * Shows a BiometricPrompt dialog and calls the appropriate callback
     * based on the authentication result.
     * 
     * @param activity FragmentActivity required for BiometricPrompt
     * @param onSuccess Called when authentication succeeds
     * @param onError Called when authentication fails with error message
     */
    fun authenticateWithBiometric(
        activity: FragmentActivity,
        onSuccess: () -> Unit,
        onError: (String) -> Unit
    ) {
        val executor = ContextCompat.getMainExecutor(context)
        
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                if (result.cryptoObject?.cipher == null) {
                    onError("Biometric key authentication failed")
                    return
                }
                onSuccess()
            }
            
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                onError(errString.toString())
            }
            
            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                // Don't call onError here - user can retry
            }
        }
        
        val biometricPrompt = BiometricPrompt(activity, executor, callback)
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock Vault")
            .setSubtitle("Authenticate to access your vault")
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG
            )
            .setNegativeButtonText("Cancel")
            .build()
        
        try {
            val cipher = getCipherForAuthWithRecovery()
            biometricPrompt.authenticate(
                promptInfo,
                BiometricPrompt.CryptoObject(cipher)
            )
        } catch (e: Exception) {
            SecureLog.e(TAG, "Biometric key unavailable: ${e.javaClass.simpleName}", e)
            onError("Biometric key unavailable")
        }
    }

    private fun deleteAlias(alias: String) {
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }
    }
    
    /**
     * Delete the biometric-protected key from Android Keystore.
     * 
     * Call this when the user wants to reset biometric authentication
     * or when the key needs to be regenerated.
     */
    fun deleteKey() {
        deleteAlias(KEY_ALIAS)
        deleteAlias(LEGACY_KEY_ALIAS)
    }
}
