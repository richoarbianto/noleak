package com.noleak.noleak.security

import android.util.Log
import com.noleak.noleak.BuildConfig

/**
 * SecureLog - Production-Safe Logging Utility
 * 
 * Provides logging functionality that is automatically disabled in release
 * builds to prevent information leakage. All log output is prefixed with
 * "NoLeak" for easy filtering in logcat.
 * 
 * SECURITY: Only logs when BuildConfig.DEBUG is true. In release builds,
 * all logging calls become no-ops, ensuring no sensitive information
 * can be leaked through logs.
 * 
 * Usage:
 * ```kotlin
 * SecureLog.d("MyClass", "Debug message")
 * SecureLog.e("MyClass", "Error occurred", exception)
 * SecureLog.security("MyClass", "Vault unlocked")
 * ```
 */
object SecureLog {
    private const val TAG_PREFIX = "NoLeak"
    private const val ENABLED = false
    
    /**
     * Log a debug message.
     * 
     * @param tag Component or class name for filtering
     * @param message Debug message to log
     */
    fun d(tag: String, message: String) {
        if (BuildConfig.DEBUG && ENABLED) {
            Log.d("$TAG_PREFIX-$tag", message)
        }
    }
    
    /**
     * Log an info message.
     * 
     * @param tag Component or class name for filtering
     * @param message Info message to log
     */
    fun i(tag: String, message: String) {
        if (BuildConfig.DEBUG && ENABLED) {
            Log.i("$TAG_PREFIX-$tag", message)
        }
    }
    
    /**
     * Log a warning message.
     * 
     * @param tag Component or class name for filtering
     * @param message Warning message to log
     */
    fun w(tag: String, message: String) {
        if (BuildConfig.DEBUG && ENABLED) {
            Log.w("$TAG_PREFIX-$tag", message)
        }
    }
    
    /**
     * Log an error message with optional exception.
     * 
     * @param tag Component or class name for filtering
     * @param message Error message to log
     * @param throwable Optional exception to include in log
     */
    fun e(tag: String, message: String, throwable: Throwable? = null) {
        if (BuildConfig.DEBUG && ENABLED) {
            if (throwable != null) {
                Log.e("$TAG_PREFIX-$tag", message, throwable)
            } else {
                Log.e("$TAG_PREFIX-$tag", message)
            }
        }
    }
    
    /**
     * Log a security-sensitive event.
     * 
     * Use this for audit trail events like vault unlock/lock, authentication
     * attempts, etc. Never logs actual sensitive data like passwords or keys.
     * 
     * @param tag Component or class name for filtering
     * @param event Security event description
     */
    fun security(tag: String, event: String) {
        if (BuildConfig.DEBUG && ENABLED) {
            Log.d("$TAG_PREFIX-SEC-$tag", event)
        }
    }
}
