package com.noleak.noleak.security

import android.content.Context
import android.content.SharedPreferences
import android.os.SystemClock

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
        private const val BASE_BACKOFF_MS = 1000L
        private const val MAX_BACKOFF_MS = 60000L
        private const val BASE_LOCKOUT_MS = 60000L
        private const val MAX_LOCKOUT_MS = 30 * 60000L
        
        private const val PREFS_NAME = "noleak_rate_limiter"
        private const val KEY_FAILED_ATTEMPTS = "failed_attempts"
        private const val KEY_LAST_ATTEMPT_WALL = "last_attempt_wall"
        private const val KEY_LAST_ATTEMPT_ELAPSED = "last_attempt_elapsed"
        private const val KEY_LOCKED_UNTIL_WALL = "locked_until_wall"
        private const val KEY_LOCKED_UNTIL_ELAPSED = "locked_until_elapsed"
        
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

    private fun key(vaultId: String?, suffix: String): String {
        val id = vaultId?.takeIf { it.isNotBlank() } ?: "default"
        return "$id.$suffix"
    }
    
    /**
     * Check if we're currently locked out
     * @return true if locked, false if can proceed
     */
    @Synchronized
    fun isLockedOut(vaultId: String? = null): Boolean {
        if (getRemainingLockoutMs(vaultId) <= 0L) {
            clearLockout(vaultId)
            return false
        }
        return true
    }
    
    /**
     * Get remaining lockout time in milliseconds
     */
    @Synchronized
    fun getRemainingLockoutMs(vaultId: String? = null): Long {
        val lockedUntilWall = prefs.getLong(key(vaultId, KEY_LOCKED_UNTIL_WALL), 0L)
        val lockedUntilElapsed = prefs.getLong(key(vaultId, KEY_LOCKED_UNTIL_ELAPSED), 0L)
        if (lockedUntilWall == 0L && lockedUntilElapsed == 0L) return 0L

        val nowWall = System.currentTimeMillis()
        val nowElapsed = SystemClock.elapsedRealtime()
        val lastElapsed = prefs.getLong(key(vaultId, KEY_LAST_ATTEMPT_ELAPSED), 0L)
        val wallRemaining = maxOf(0, lockedUntilWall - nowWall)
        val elapsedRemaining = if (nowElapsed >= lastElapsed) {
            maxOf(0, lockedUntilElapsed - nowElapsed)
        } else {
            0
        }
        return maxOf(wallRemaining, elapsedRemaining)
    }
    
    /**
     * Check if we need to wait before next attempt
     * @return wait time in milliseconds, 0 if can proceed immediately
     */
    @Synchronized
    fun getBackoffMs(vaultId: String? = null): Long {
        val failedAttempts = prefs.getInt(key(vaultId, KEY_FAILED_ATTEMPTS), 0)
        if (failedAttempts == 0) return 0

        val nowElapsed = SystemClock.elapsedRealtime()
        val lastAttemptTime = prefs.getLong(key(vaultId, KEY_LAST_ATTEMPT_ELAPSED), 0L)
        if (nowElapsed < lastAttemptTime) return 0
        
        // Calculate backoff: exponential with cap
        val backoffMs = minOf(
            BASE_BACKOFF_MS * (1L shl (failedAttempts - 1).coerceAtMost(10)),
            MAX_BACKOFF_MS
        )
        
        val canRetryAt = lastAttemptTime + backoffMs
        return maxOf(0L, canRetryAt - nowElapsed)
    }
    
    /**
     * Record a failed password attempt
     * @return remaining attempts before lockout, or -1 if now locked
     */
    @Synchronized
    fun recordFailure(vaultId: String? = null): Int {
        val failedAttempts = prefs.getInt(key(vaultId, KEY_FAILED_ATTEMPTS), 0) + 1
        val nowWall = System.currentTimeMillis()
        val nowElapsed = SystemClock.elapsedRealtime()

        prefs.edit().apply {
            putInt(key(vaultId, KEY_FAILED_ATTEMPTS), failedAttempts)
            putLong(key(vaultId, KEY_LAST_ATTEMPT_WALL), nowWall)
            putLong(key(vaultId, KEY_LAST_ATTEMPT_ELAPSED), nowElapsed)
            
            if (failedAttempts >= MAX_ATTEMPTS) {
                val multiplier = failedAttempts - MAX_ATTEMPTS
                val lockout = minOf(BASE_LOCKOUT_MS * (1L shl multiplier.coerceAtMost(10)), MAX_LOCKOUT_MS)
                putLong(key(vaultId, KEY_LOCKED_UNTIL_WALL), nowWall + lockout)
                putLong(key(vaultId, KEY_LOCKED_UNTIL_ELAPSED), nowElapsed + lockout)
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
    fun recordSuccess(vaultId: String? = null) {
        reset(vaultId)
    }
    
    /**
     * Reset all rate limiting state
     */
    @Synchronized
    private fun reset(vaultId: String? = null) {
        prefs.edit().apply {
            putInt(key(vaultId, KEY_FAILED_ATTEMPTS), 0)
            putLong(key(vaultId, KEY_LAST_ATTEMPT_WALL), 0)
            putLong(key(vaultId, KEY_LAST_ATTEMPT_ELAPSED), 0)
            putLong(key(vaultId, KEY_LOCKED_UNTIL_WALL), 0)
            putLong(key(vaultId, KEY_LOCKED_UNTIL_ELAPSED), 0)
            apply()
        }
    }

    @Synchronized
    private fun clearLockout(vaultId: String? = null) {
        prefs.edit().apply {
            putLong(key(vaultId, KEY_LOCKED_UNTIL_WALL), 0)
            putLong(key(vaultId, KEY_LOCKED_UNTIL_ELAPSED), 0)
            apply()
        }
    }
    
    /**
     * Get current failed attempt count
     */
    @Synchronized
    fun getFailedAttempts(vaultId: String? = null): Int =
        prefs.getInt(key(vaultId, KEY_FAILED_ATTEMPTS), 0)
}
