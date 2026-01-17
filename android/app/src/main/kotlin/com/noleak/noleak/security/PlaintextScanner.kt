package com.noleak.noleak.security

import android.content.Context
import java.io.File

/**
 * PlaintextScanner - Scans app storage for plaintext content
 * 
 * Used for security verification to ensure no plaintext files are left on disk.
 */
object PlaintextScanner {
    
    /**
     * Scan app storage for any plaintext content
     * @param context Application context
     * @param knownPatterns List of byte patterns to search for (e.g., file headers)
     * @return List of files containing plaintext content
     */
    fun scanForPlaintext(
        context: Context,
        knownPatterns: List<ByteArray> = emptyList()
    ): List<PlaintextFinding> {
        val findings = mutableListOf<PlaintextFinding>()
        
        // Scan internal storage
        scanDirectory(context.filesDir, knownPatterns, findings)
        
        // Scan cache
        scanDirectory(context.cacheDir, knownPatterns, findings)
        
        // Scan external files (if any)
        context.getExternalFilesDir(null)?.let { dir ->
            scanDirectory(dir, knownPatterns, findings)
        }
        
        return findings
    }
    
    private fun scanDirectory(
        dir: File,
        patterns: List<ByteArray>,
        findings: MutableList<PlaintextFinding>
    ) {
        if (!dir.exists() || !dir.isDirectory) return
        
        dir.listFiles()?.forEach { file ->
            if (file.isDirectory) {
                // Skip vault directory (encrypted data is expected there)
                if (file.name != "vault") {
                    scanDirectory(file, patterns, findings)
                }
            } else {
                scanFile(file, patterns, findings)
            }
        }
    }
    
    private fun scanFile(
        file: File,
        patterns: List<ByteArray>,
        findings: MutableList<PlaintextFinding>
    ) {
        try {
            // Skip vault.dat (encrypted container)
            if (file.name == "vault.dat") return
            
            // Check file extension for suspicious types
            val suspiciousExtensions = listOf(
                ".txt", ".jpg", ".jpeg", ".png", ".webp", 
                ".mp4", ".mkv", ".tmp", ".bak"
            )
            
            if (suspiciousExtensions.any { file.name.endsWith(it, ignoreCase = true) }) {
                findings.add(PlaintextFinding(
                    path = file.absolutePath,
                    reason = "Suspicious file extension: ${file.extension}"
                ))
                return
            }
            
            // Check for known patterns in file content
            if (patterns.isNotEmpty() && file.length() < 10 * 1024 * 1024) { // Max 10MB
                val content = file.readBytes()
                for (pattern in patterns) {
                    if (containsPattern(content, pattern)) {
                        findings.add(PlaintextFinding(
                            path = file.absolutePath,
                            reason = "Contains known plaintext pattern"
                        ))
                        break
                    }
                }
            }
            
            // Check for common file signatures (magic bytes)
            if (file.length() >= 8) {
                val header = ByteArray(8)
                file.inputStream().use { it.read(header) }
                
                val signature = detectFileSignature(header)
                if (signature != null) {
                    findings.add(PlaintextFinding(
                        path = file.absolutePath,
                        reason = "Detected $signature file signature"
                    ))
                }
            }
        } catch (e: Exception) {
            // Ignore read errors
        }
    }
    
    private fun containsPattern(content: ByteArray, pattern: ByteArray): Boolean {
        if (pattern.isEmpty() || content.size < pattern.size) return false
        
        outer@ for (i in 0..(content.size - pattern.size)) {
            for (j in pattern.indices) {
                if (content[i + j] != pattern[j]) continue@outer
            }
            return true
        }
        return false
    }
    
    private fun detectFileSignature(header: ByteArray): String? {
        // JPEG
        if (header[0] == 0xFF.toByte() && header[1] == 0xD8.toByte() && header[2] == 0xFF.toByte()) {
            return "JPEG"
        }
        
        // PNG
        if (header[0] == 0x89.toByte() && header[1] == 0x50.toByte() && 
            header[2] == 0x4E.toByte() && header[3] == 0x47.toByte()) {
            return "PNG"
        }
        
        // MP4/MOV (ftyp)
        if (header[4] == 0x66.toByte() && header[5] == 0x74.toByte() && 
            header[6] == 0x79.toByte() && header[7] == 0x70.toByte()) {
            return "MP4"
        }
        
        // WebP (RIFF....WEBP)
        if (header[0] == 0x52.toByte() && header[1] == 0x49.toByte() && 
            header[2] == 0x46.toByte() && header[3] == 0x46.toByte()) {
            return "WebP/RIFF"
        }
        
        // MKV (EBML)
        if (header[0] == 0x1A.toByte() && header[1] == 0x45.toByte() && 
            header[2] == 0xDF.toByte() && header[3] == 0xA3.toByte()) {
            return "MKV"
        }
        
        return null
    }
}

/**
 * Represents a plaintext finding during security scan
 */
data class PlaintextFinding(
    val path: String,
    val reason: String
)
