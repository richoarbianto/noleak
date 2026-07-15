package com.noleak.noleak.vault

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import android.webkit.MimeTypeMap
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.SecureRandom

/**
 * SafFileHandler - Handles file operations via Storage Access Framework
 * 
 * SECURITY: 
 * - Uses streaming for large files (>10MB) to avoid OOM
 * - Zeroizes buffers after use to prevent memory forensics
 * - Limits file sizes to prevent DoS
 */
class SafFileHandler(private val context: Context) {
    
    companion object {
        private val DEDICATED_PREVIEW_MIME_TYPES = setOf(
            "application/pdf",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "application/x-pem-file",
            "application/pgp-keys",
            "application/x-ssh-key",
            "application/pkcs8"
        )

        private val SPECIAL_EXTENSION_MIME_TYPES = mapOf(
            "pem" to "application/x-pem-file",
            "key" to "application/x-pem-file",
            "pub" to "application/x-ssh-key",
            "asc" to "application/pgp-keys"
        )

        private val BOUNDED_TEXT_MIME_TYPES = setOf(
            "application/x-pem-file",
            "application/pgp-keys",
            "application/x-ssh-key",
            "application/pkcs8"
        )
        
        // Max file size (50GB for streaming import)
        const val MAX_FILE_SIZE = 50L * 1024 * 1024 * 1024
        
        // Threshold for streaming (10MB) - files larger use streaming
        const val STREAMING_THRESHOLD = 10L * 1024 * 1024
        private const val TEXT_PREVIEW_LIMIT = 1024L * 1024
        
        // SECURITY: Secure random for zeroizing
        private val secureRandom = SecureRandom()
        
        /**
         * SECURITY: Securely zeroize a byte array
         * Overwrites with random then zero to prevent recovery
         */
        fun secureZeroize(data: ByteArray?) {
            if (data == null || data.isEmpty()) return
            secureRandom.nextBytes(data)
            data.fill(0)
        }
    }
    
    private fun hasDedicatedPreview(mimeType: String): Boolean {
        return mimeType.startsWith("text/") ||
            mimeType.startsWith("image/") ||
            mimeType.startsWith("video/") ||
            mimeType.startsWith("audio/") ||
            DEDICATED_PREVIEW_MIME_TYPES.contains(mimeType)
    }

    private fun usesBoundedTextPreview(mimeType: String): Boolean {
        return mimeType.startsWith("text/") ||
            mimeType in BOUNDED_TEXT_MIME_TYPES
    }
    
    /**
     * Get file type from MIME type
     */
    fun getFileType(mimeType: String?): Int {
        return when {
            mimeType == null -> VaultEngine.FILE_TYPE_TXT
            mimeType.startsWith("text/") -> VaultEngine.FILE_TYPE_TXT
            mimeType.startsWith("image/") -> VaultEngine.FILE_TYPE_IMG
            mimeType.startsWith("video/") -> VaultEngine.FILE_TYPE_VIDEO
            mimeType.startsWith("audio/") -> VaultEngine.FILE_TYPE_TXT
            else -> VaultEngine.FILE_TYPE_TXT
        }
    }
    
    /**
     * Get MIME type from URI
     */
    fun getMimeType(uri: Uri): String? {
        return context.contentResolver.getType(uri)
    }
    
    /**
     * Get file name from URI
     */
    fun getFileName(uri: Uri): String {
        var name = "unknown"
        
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (nameIndex >= 0) {
                    name = cursor.getString(nameIndex) ?: "unknown"
                }
            }
        }
        
        return name
    }
    
    /**
     * Get file size from URI
     */
    fun getFileSize(uri: Uri): Long {
        var size = 0L
        
        // Try query first
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                if (sizeIndex >= 0) {
                    size = cursor.getLong(sizeIndex)
                }
            }
        }
        
        // Fallback: try to get size from file descriptor
        if (size <= 0) {
            try {
                context.contentResolver.openFileDescriptor(uri, "r")?.use { pfd ->
                    size = pfd.statSize
                }
            } catch (_: Exception) {
                // Ignore
            }
        }
        
        return size
    }
    
    /**
     * Open file for reading
     */
    fun openFileForRead(uri: Uri): InputStream? {
        return try {
            context.contentResolver.openInputStream(uri)
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Read entire file into byte array with secure buffer handling
     * SECURITY: Only for small files (<10MB). For large files use streaming.
     * Zeroizes read buffer after use.
     */
    fun readFileBytes(uri: Uri): ByteArray? {
        val readBuffer = ByteArray(16384)
        return try {
            context.contentResolver.openInputStream(uri)?.use { inputStream ->
                val buffer = ByteArrayOutputStream()
                var bytesRead: Int
                
                var total = 0
                while (inputStream.read(readBuffer, 0, readBuffer.size).also { bytesRead = it } != -1) {
                    total += bytesRead
                    if (total > STREAMING_THRESHOLD) return null
                    buffer.write(readBuffer, 0, bytesRead)
                }
                
                buffer.toByteArray()
            }
        } catch (e: Exception) {
            null
        } finally {
            // SECURITY: Zeroize read buffer
            secureZeroize(readBuffer)
        }
    }
    
    /**
     * Check if file should use streaming (large file)
     * SECURITY: Use streaming for any file > 10MB to prevent OOM
     */
    fun shouldUseStreaming(uri: Uri, mimeType: String): Boolean {
        val size = getFileSize(uri)
        return size > STREAMING_THRESHOLD ||
            !hasDedicatedPreview(mimeType) ||
            (usesBoundedTextPreview(mimeType) && size > TEXT_PREVIEW_LIMIT)
    }
    
    /**
     * Read file in chunks (for large files like videos)
     * SECURITY: Zeroizes buffer after each chunk is processed
     * @param onChunk Callback receives chunk data and index. Chunk is zeroized after callback returns.
     */
    fun readFileChunked(
        uri: Uri,
        chunkSize: Int = 1024 * 1024,
        onChunk: (ByteArray, Int) -> Boolean
    ): Boolean {
        val buffer = ByteArray(chunkSize)
        return try {
            context.contentResolver.openInputStream(uri)?.use { inputStream ->
                var chunkIndex = 0
                var bytesRead: Int
                
                while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                    val chunk = if (bytesRead == chunkSize) {
                        buffer.copyOf() // Create copy so we can zeroize original
                    } else {
                        buffer.copyOf(bytesRead)
                    }
                    
                    val continueReading = onChunk(chunk, chunkIndex)
                    
                    // SECURITY: Zeroize chunk after processing
                    secureZeroize(chunk)
                    
                    if (!continueReading) {
                        return@use false
                    }
                    
                    chunkIndex++
                }
                
                true
            } ?: false
        } catch (e: Exception) {
            false
        } finally {
            // SECURITY: Always zeroize buffer
            secureZeroize(buffer)
        }
    }
    
    /**
     * Validate file for import
     */
    fun validateFile(uri: Uri): FileValidationResult {
        val name = getFileName(uri)
        val reportedMime = getMimeType(uri)?.lowercase()
        val mimeType = if (reportedMime.isNullOrBlank() ||
            reportedMime == "application/octet-stream") {
            resolveMimeFromName(name) ?: "application/octet-stream"
        } else reportedMime

        val size = getFileSize(uri)
        if (size < 0L) {
            return FileValidationResult.UnknownSize
        }
        if (size > MAX_FILE_SIZE) {
            return FileValidationResult.TooLarge(size)
        }
        
        if (size == 0L) {
            return FileValidationResult.Empty
        }
        
        return FileValidationResult.Valid(
            name = name,
            mimeType = mimeType,
            size = size,
            fileType = getFileType(mimeType)
        )
    }

    private fun resolveMimeFromName(name: String): String? {
        val dot = name.lastIndexOf('.')
        if (dot <= 0 || dot == name.length - 1) return null
        val ext = name.substring(dot + 1).lowercase()
        return SPECIAL_EXTENSION_MIME_TYPES[ext]
            ?: MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext)
    }
    
    sealed class FileValidationResult {
        data class Valid(
            val name: String,
            val mimeType: String,
            val size: Long,
            val fileType: Int
        ) : FileValidationResult()
        
        data class TooLarge(val size: Long) : FileValidationResult()
        object UnknownSize : FileValidationResult()
        object Empty : FileValidationResult()
    }
}
