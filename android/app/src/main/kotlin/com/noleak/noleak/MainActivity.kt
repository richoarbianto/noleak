package com.noleak.noleak

import android.content.ComponentCallbacks2
import android.os.Bundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import com.noleak.noleak.audio.AudioPlayerManager
import com.noleak.noleak.vault.VaultBridge
import com.noleak.noleak.vault.VaultEngine
import com.noleak.noleak.video.VideoPlayerManager
import com.noleak.noleak.security.SecureLog

/**
 * MainActivity - Android Entry Point with Security Hardening
 * 
 * The main activity for the NoLeak application, implementing several
 * security measures to protect user data:
 * 
 * SECURITY FEATURES:
 * - Uses FlutterFragmentActivity for BiometricPrompt support
 * - Sets FLAG_SECURE to prevent screenshots and screen recording
 * - Auto-locks vault when app goes to background
 * - Handles memory pressure by wiping sensitive data
 * - Smart detection to avoid locking during file picker operations
 * 
 * LIFECYCLE HANDLING:
 * - onCreate: Initialize vault engine, set FLAG_SECURE
 * - onResume: Re-assert FLAG_SECURE
 * - onStop: Close vault (unless file picker is active)
 * - onTrimMemory: Close vault on memory pressure
 * - onDestroy: Final cleanup
 */
class MainActivity : FlutterFragmentActivity() {
    
    private var vaultEngine: VaultEngine? = null
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Get vault engine instance
        vaultEngine = VaultEngine.getInstance(applicationContext)
        
        // Set FLAG_SECURE to prevent screenshots and screen recording
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }
    
    override fun onResume() {
        super.onResume()
        // Re-assert FLAG_SECURE in case it was cleared
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }
    
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        
        // Register vault plugin
        flutterEngine.plugins.add(VaultPlugin())
    }
    
    /**
     * SECURITY: Close vault when app goes to background
     * BUT NOT if we're waiting for file picker result
     */
    override fun onStop() {
        super.onStop()
        
        // Check if file picker is active - don't close if so
        val isFilePicking = VaultPlugin.getInstance()?.isAwaitingActivityResult == true
        if (isFilePicking) {
            SecureLog.d("MainActivity", "onStop - skipping close (file picker active)")
            return
        }
        
        SecureLog.security("MainActivity", "onStop - closing vault for security")
        closeVaultSafely()
    }
    
    /**
     * SECURITY: Handle memory pressure - wipe sensitive data immediately
     * Called by system when memory is low
     */
    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        
        when (level) {
            // Only close on actual memory pressure, NOT on UI_HIDDEN
            // because file picker triggers UI_HIDDEN
            ComponentCallbacks2.TRIM_MEMORY_BACKGROUND,
            ComponentCallbacks2.TRIM_MEMORY_MODERATE,
            ComponentCallbacks2.TRIM_MEMORY_COMPLETE,
            ComponentCallbacks2.TRIM_MEMORY_RUNNING_CRITICAL -> {
                SecureLog.security("MainActivity", "onTrimMemory level=$level - closing vault")
                closeVaultSafely()
            }
        }
    }
    
    /**
     * SECURITY: Safely close vault and video players, catching any exceptions
     */
    private fun closeVaultSafely() {
        // SECURITY: Close all video players first to zeroize decrypted chunks
        try {
            VideoPlayerManager.getInstance(VaultBridge.getInstance(applicationContext)).closeAll()
            SecureLog.security("MainActivity", "Video players closed")
        } catch (e: Exception) {
            SecureLog.e("MainActivity", "Error closing video players: ${e.message}")
        }

        // SECURITY: Close any audio players holding decrypted data
        try {
            AudioPlayerManager.getInstance(VaultBridge.getInstance(applicationContext)).closeAll()
            SecureLog.security("MainActivity", "Audio players closed")
        } catch (e: Exception) {
            SecureLog.e("MainActivity", "Error closing audio players: ${e.message}")
        }
        
        // Close vault engine
        try {
            if (vaultEngine?.isOpen() == true) {
                vaultEngine?.close()
                SecureLog.security("MainActivity", "Vault closed successfully")
            }
        } catch (e: Exception) {
            SecureLog.e("MainActivity", "Error closing vault: ${e.message}")
        }
    }
    
    override fun onDestroy() {
        // Final cleanup - ensure vault is closed
        closeVaultSafely()
        super.onDestroy()
    }
}
