package com.noleak.noleak.security

import android.content.Context

/**
 * SecurityManager - Centralized Security Enforcement
 * 
 * Provides a single point of control for all security checks in the application.
 * Implements fail-closed behavior: if any security check fails, operations are
 * blocked rather than proceeding with potentially compromised security.
 * 
 * Security checks include:
 * - Root/jailbreak detection
 * - Emulator detection
 * - Debugger detection
 * - App tampering verification
 * 
 * Results are cached briefly (1 second) to avoid repeated expensive checks
 * while still detecting changes quickly.
 * 
 * Usage:
 * ```kotlin
 * // Check if environment is secure
 * if (securityManager.isEnvironmentSecure()) {
 *     // Proceed with operation
 * }
 * 
 * // Or throw exception if not secure
 * securityManager.enforceSecureEnvironment()
 * ```
 */
class SecurityManager(private val context: Context) {
    
    private var lastCheckResult: RootGate.SecurityResult? = null
    private var lastCheckTime: Long = 0
    private val checkCacheMs = 1000L // Cache result for 1 second
    
    /**
     * Check if environment is secure
     * Results are cached briefly to avoid repeated expensive checks
     */
    fun isEnvironmentSecure(): Boolean {
        val now = System.currentTimeMillis()
        
        // Use cached result if recent
        if (lastCheckResult != null && (now - lastCheckTime) < checkCacheMs) {
            return lastCheckResult == RootGate.SecurityResult.OK
        }
        
        // Perform fresh check
        lastCheckResult = RootGate.checkEnvironment(context)
        lastCheckTime = now
        
        SecureLog.d("SecurityManager", "Environment check: ${lastCheckResult?.name}")
        
        return lastCheckResult == RootGate.SecurityResult.OK
    }
    
    /**
     * Enforce security check before operation
     * @throws SecurityException if environment is not secure
     */
    fun enforceSecureEnvironment() {
        if (!isEnvironmentSecure()) {
            throw SecurityException("Environment not supported")
        }
    }
    
    /**
     * Execute operation only if environment is secure
     * @return Result of operation, or null if blocked
     */
    fun <T> executeIfSecure(operation: () -> T): T? {
        return if (isEnvironmentSecure()) {
            operation()
        } else {
            null
        }
    }
    
    /**
     * Execute operation with security check, throwing on failure
     */
    fun <T> executeSecure(operation: () -> T): T {
        enforceSecureEnvironment()
        return operation()
    }
    
    companion object {
        @Volatile
        private var instance: SecurityManager? = null
        
        fun getInstance(context: Context): SecurityManager {
            return instance ?: synchronized(this) {
                instance ?: SecurityManager(context.applicationContext).also {
                    instance = it
                }
            }
        }
    }
}
