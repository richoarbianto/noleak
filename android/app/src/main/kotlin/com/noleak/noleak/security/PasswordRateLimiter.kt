package com.noleak.noleak.security

import android.content.Context
import android.content.SharedPreferences

/**
 * PasswordRateLimiter - Prevents brute-force password attempts
 * 
 * SECURITY:
 * - Tracks failed attempts and applies exponential backoff
 * - Locks out after max attempts
 * - Persists state across app restarts to prevent reset-based attacks
 * - Uses System.currentTimeMillis() for cross-restart time tracking
 */
class PasswordRateLimiter private constructor(context: Context) {
    
    companion object {
        private const val MAX_ATTEMPTS = 5
        private const val BASE_BACKOFF_MS = 1000L  // 1 second
        private const val MAX_BACKOFF_MS = 60000L  // 1 minute max
        private const val LOCKOUT_DURATION_MS = 300000L  // 5 minute lockout after max attempts
        
        private const val PREFS_NAME = "noleak_rate_limiter"
        private const val KEY_FAILED_ATTEMPTS = "failed_attempts"
        private const val KEY_LAST_ATTEMPT_TIME = "last_attempt_time"
        private const val KEY_LOCKED_UNTIL = "locked_until"
        
        @Volatile
        private var instance: PasswordRateLimiter? = null
        
        fun getInstance(context: Context): PasswordRateLimiter {
            return instance ?: synchronized(this) {
                instance ?: PasswordRateLimiter(context.applicationContext).also {
                    instance = it
                }
            }
        }
    }
    
    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    
    /**
     * Check if we're currently locked out
     * @return true if locked, false if can proceed
     */
    @Synchronized
    fun isLockedOut(): Boolean {
        val lockedUntil = prefs.getLong(KEY_LOCKED_UNTIL, 0L)
        if (lockedUntil == 0L) return false
        
        val now = System.currentTimeMillis()
        if (now >= lockedUntil) {
            // Lockout expired, reset
            reset()
            return false
        }
        return true
    }
    
    /**
     * Get remaining lockout time in milliseconds
     */
    @Synchronized
    fun getRemainingLockoutMs(): Long {
        val lockedUntil = prefs.getLong(KEY_LOCKED_UNTIL, 0L)
        if (lockedUntil == 0L) return 0
        
        val now = System.currentTimeMillis()
        return maxOf(0, lockedUntil - now)
    }
    
    /**
     * Check if we need to wait before next attempt
     * @return wait time in milliseconds, 0 if can proceed immediately
     */
    @Synchronized
    fun getBackoffMs(): Long {
        val failedAttempts = prefs.getInt(KEY_FAILED_ATTEMPTS, 0)
        if (failedAttempts == 0) return 0
        
        val now = System.currentTimeMillis()
        val lastAttemptTime = prefs.getLong(KEY_LAST_ATTEMPT_TIME, 0L)
        
        // Calculate backoff: exponential with cap
        val backoffMs = minOf(
            BASE_BACKOFF_MS * (1L shl (failedAttempts - 1)),
            MAX_BACKOFF_MS
        )
        
        val canRetryAt = lastAttemptTime + backoffMs
        return maxOf(0, canRetryAt - now)
    }
    
    /**
     * Record a failed password attempt
     * @return remaining attempts before lockout, or -1 if now locked
     */
    @Synchronized
    fun recordFailure(): Int {
        val failedAttempts = prefs.getInt(KEY_FAILED_ATTEMPTS, 0) + 1
        val now = System.currentTimeMillis()
        
        prefs.edit().apply {
            putInt(KEY_FAILED_ATTEMPTS, failedAttempts)
            putLong(KEY_LAST_ATTEMPT_TIME, now)
            
            if (failedAttempts >= MAX_ATTEMPTS) {
                putLong(KEY_LOCKED_UNTIL, now + LOCKOUT_DURATION_MS)
                SecureLog.security("RateLimiter", "Lockout activated, $MAX_ATTEMPTS failures")
            } else {
                SecureLog.security("RateLimiter", "Failed attempt $failedAttempts/$MAX_ATTEMPTS")
            }
            
            apply()
        }
        
        return if (failedAttempts >= MAX_ATTEMPTS) -1 else MAX_ATTEMPTS - failedAttempts
    }
    
    /**
     * Record a successful password verification
     * Resets all counters
     */
    @Synchronized
    fun recordSuccess() {
        reset()
    }
    
    /**
     * Reset all rate limiting state
     */
    @Synchronized
    private fun reset() {
        prefs.edit().apply {
            putInt(KEY_FAILED_ATTEMPTS, 0)
            putLong(KEY_LAST_ATTEMPT_TIME, 0)
            putLong(KEY_LOCKED_UNTIL, 0)
            apply()
        }
    }
    
    /**
     * Get current failed attempt count
     */
    @Synchronized
    fun getFailedAttempts(): Int = prefs.getInt(KEY_FAILED_ATTEMPTS, 0)
}
