package com.noleak.noleak

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.view.Surface
import android.view.WindowManager
import androidx.fragment.app.FragmentActivity
import androidx.documentfile.provider.DocumentFile
import com.noleak.noleak.audio.AudioOpenResult
import com.noleak.noleak.audio.AudioPlayerManager
import com.noleak.noleak.security.SecureKeyManager
import com.noleak.noleak.security.SecurityManager
import com.noleak.noleak.security.PlaintextScanner
import com.noleak.noleak.vault.SafFileHandler
import com.noleak.noleak.vault.StreamingImportHandler
import com.noleak.noleak.vault.VaultBridge
import com.noleak.noleak.vault.VaultEngine
import com.noleak.noleak.vault.VaultException
import com.noleak.noleak.vault.VaultRegistry
import com.noleak.noleak.video.VideoOpenResult
import com.noleak.noleak.video.VideoPlayerManager
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.PluginRegistry
import io.flutter.view.TextureRegistry
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import com.noleak.noleak.security.SecureLog
import com.noleak.noleak.security.PasswordRateLimiter
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * VaultPlugin - Flutter MethodChannel handler for vault operations
 * 
 * This plugin bridges Flutter/Dart code with native Android vault operations.
 * It handles all communication between the Flutter UI and the native vault engine.
 * 
 * FEATURES:
 * - Vault creation, opening, and closing
 * - File import (small files and streaming for large files up to 50GB)
 * - File export with secure temp file handling
 * - Video and audio playback from encrypted vault
 * - Biometric authentication integration
 * - Multi-vault management
 * - Security window flags (FLAG_SECURE)
 * 
 * SECURITY:
 * - Tracks file picker state to prevent vault auto-lock during selection
 * - Uses streaming import for large files to prevent OOM
 * - Implements password rate limiting to prevent brute-force
 * - Securely wipes temp files after export
 * - All sensitive data is zeroized after use
 */
class VaultPlugin : FlutterPlugin, MethodChannel.MethodCallHandler, ActivityAware,
    PluginRegistry.ActivityResultListener {
    
    companion object {
        private const val CHANNEL_NAME = "com.noleak.vault"
        private const val PICK_FILE_REQUEST = 1001
        private const val EXPORT_VAULT_REQUEST = 1002
        private const val IMPORT_VAULT_REQUEST = 1003
        private const val PICK_FOLDER_REQUEST = 1004
        private const val EXPORT_FILE_REQUEST = 1005
        
        @Volatile
        private var instance: VaultPlugin? = null
        
        fun getInstance(): VaultPlugin? = instance
    }
    
    private lateinit var channel: MethodChannel
    private var activity: Activity? = null
    private var pendingResult: MethodChannel.Result? = null
    private var pendingFolderResult: MethodChannel.Result? = null
    private var pendingExportResult: MethodChannel.Result? = null
    private var pendingImportResult: MethodChannel.Result? = null
    private var pendingExportFileResult: MethodChannel.Result? = null
    private var pendingExportFilePath: String? = null  // Path to temp file with encrypted data
    
    private lateinit var vaultBridge: VaultBridge
    private lateinit var vaultRegistry: VaultRegistry
    private lateinit var securityManager: SecurityManager
    private lateinit var secureKeyManager: SecureKeyManager
    private lateinit var safFileHandler: SafFileHandler
    private lateinit var streamingImportHandler: StreamingImportHandler
    private lateinit var videoPlayerManager: VideoPlayerManager
    private lateinit var audioPlayerManager: AudioPlayerManager
    private lateinit var passwordRateLimiter: PasswordRateLimiter
    private var textureRegistry: TextureRegistry? = null
    private var importProgressChannel: EventChannel? = null
    private var importProgressSink: EventChannel.EventSink? = null
    private var transferProgressChannel: EventChannel? = null
    private var transferProgressSink: EventChannel.EventSink? = null
    private var currentVaultId: String? = null
    private val importIdRandom = SecureRandom()
    private val videoTextures = ConcurrentHashMap<Int, TextureRegistry.SurfaceTextureEntry>()
    private val videoSurfaces = ConcurrentHashMap<Int, Surface>()
    
    // SECURITY: Track if we're waiting for file picker result
    // Used by MainActivity to NOT close vault during file picker
    @Volatile
    var isAwaitingActivityResult: Boolean = false
        private set
    
    private val scope = CoroutineScope(Dispatchers.Main)

    private data class FolderImportTarget(
        val uri: Uri,
        val validation: SafFileHandler.FileValidationResult.Valid,
        val folder: String
    )
    
    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        instance = this
        channel = MethodChannel(binding.binaryMessenger, CHANNEL_NAME)
        channel.setMethodCallHandler(this)
        
        val context = binding.applicationContext
        vaultBridge = VaultBridge.getInstance(context)
        vaultRegistry = VaultRegistry.getInstance(context)
        securityManager = SecurityManager.getInstance(context)
        secureKeyManager = SecureKeyManager(context)
        safFileHandler = SafFileHandler(context)
        streamingImportHandler = StreamingImportHandler(context)
        videoPlayerManager = VideoPlayerManager.getInstance(vaultBridge)
        audioPlayerManager = AudioPlayerManager.getInstance(vaultBridge)
        passwordRateLimiter = PasswordRateLimiter.getInstance(context)
        textureRegistry = binding.textureRegistry
        
        // Set up EventChannel for import progress
        importProgressChannel = EventChannel(binding.binaryMessenger, "com.noleak.vault/import_progress")
        importProgressChannel?.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                importProgressSink = events
            }
            override fun onCancel(arguments: Any?) {
                importProgressSink = null
            }
        })

        transferProgressChannel = EventChannel(binding.binaryMessenger, "com.noleak.vault/transfer_progress")
        transferProgressChannel?.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                transferProgressSink = events
            }
            override fun onCancel(arguments: Any?) {
                transferProgressSink = null
            }
        })
        
        // Initialize vault engine
        scope.launch {
            vaultBridge.initialize()
        }
    }
    
    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }
    
    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
        binding.addActivityResultListener(this)
    }
    
    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
    }
    
    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity
        binding.addActivityResultListener(this)
    }
    
    override fun onDetachedFromActivity() {
        activity = null
    }
    
    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "checkEnvironment" -> handleCheckEnvironment(result)
            "vaultExists" -> handleVaultExists(result)
            "isVaultOpen" -> handleIsVaultOpen(result)
            "createVault" -> handleCreateVault(call, result)
            "openVault" -> handleOpenVault(call, result)
            "closeVault" -> handleCloseVault(result)
            "enableWakelock" -> handleEnableWakelock(result)
            "disableWakelock" -> handleDisableWakelock(result)
            "pickFile" -> handlePickFile(result)
            "pickFolder" -> handlePickFolder(result)
            "importFile" -> handleImportFile(call, result)
            "importFolder" -> handleImportFolder(call, result)
            "importBytes" -> handleImportBytes(call, result)
            "importFileStreaming" -> handleImportFileStreaming(call, result)
            "listPendingImports" -> handleListPendingImports(result)
            "abortImport" -> handleAbortImport(call, result)
            "readFile" -> handleReadFile(call, result)
            "readTextPreview" -> handleReadTextPreview(call, result)
            "deleteFile" -> handleDeleteFile(call, result)
            "renameFile" -> handleRenameFile(call, result)
            "copyFile" -> handleCopyFile(call, result)
            "exportFile" -> handleExportFile(call, result)
            "getEntryCount" -> handleGetEntryCount(result)
            "listFiles" -> handleListFiles(result)
            "authenticateBiometric" -> handleAuthenticateBiometric(result)
            // Video methods
            "openVideo" -> handleOpenVideo(call, result)
            "playVideo" -> handlePlayVideo(call, result)
            "pauseVideo" -> handlePauseVideo(call, result)
            "seekVideo" -> handleSeekVideo(call, result)
            "getVideoPosition" -> handleGetVideoPosition(call, result)
            "getVideoDuration" -> handleGetVideoDuration(call, result)
            "isVideoPlaying" -> handleIsVideoPlaying(call, result)
            "closeVideo" -> handleCloseVideo(call, result)
            // Audio methods
            "openAudio" -> handleOpenAudio(call, result)
            "playAudio" -> handlePlayAudio(call, result)
            "pauseAudio" -> handlePauseAudio(call, result)
            "seekAudio" -> handleSeekAudio(call, result)
            "getAudioPosition" -> handleGetAudioPosition(call, result)
            "getAudioDuration" -> handleGetAudioDuration(call, result)
            "isAudioPlaying" -> handleIsAudioPlaying(call, result)
            "closeAudio" -> handleCloseAudio(call, result)
            // Security methods
            "enableSecureWindow" -> handleEnableSecureWindow(result)
            "disableSecureWindow" -> handleDisableSecureWindow(result)
            "scanForPlaintext" -> handleScanForPlaintext(result)
            "exportVault" -> handleExportVault(result)
            "importVault" -> handleImportVault(result)
            "verifyPassword" -> handleVerifyPassword(call, result)
            "changePassword" -> handleChangePassword(call, result)
            // Multi-vault methods
            "listVaults" -> handleListVaults(result)
            "createVaultWithTitle" -> handleCreateVaultWithTitle(call, result)
            "importVaultWithTitle" -> handleImportVaultWithTitle(call, result)
            "importVaultFile" -> handleImportVaultFile(result)
            "pickVaultFile" -> handlePickVaultFile(result)
            "importVaultFromUri" -> handleImportVaultFromUri(call, result)
            "getVaultTitle" -> handleGetVaultTitle(call, result)
            "setVaultTitle" -> handleSetVaultTitle(call, result)
            "deleteVaultById" -> handleDeleteVaultById(call, result)
            "openVaultById" -> handleOpenVaultById(call, result)
            "exportVaultById" -> handleExportVaultById(call, result)
            else -> result.notImplemented()
        }
    }
    
    private fun handleCheckEnvironment(result: MethodChannel.Result) {
        val isSecure = securityManager.isEnvironmentSecure()
        result.success(mapOf("ok" to isSecure))
    }
    
    private fun handleVaultExists(result: MethodChannel.Result) {
        result.success(vaultBridge.vaultExists())
    }
    
    private fun handleIsVaultOpen(result: MethodChannel.Result) {
        result.success(vaultBridge.isVaultOpen())
    }
    
    private fun handleCreateVault(call: MethodCall, result: MethodChannel.Result) {
        val passphrase = call.argument<String>("passphrase")
        if (passphrase == null) {
            result.error("INVALID_ARGUMENT", "Passphrase required", null)
            return
        }
        
        scope.launch {
            vaultBridge.createVault(passphrase).fold(
                onSuccess = { result.success(true) },
                onFailure = { e -> result.error("CREATE_FAILED", e.message, null) }
            )
        }
    }
    
    private fun handleOpenVault(call: MethodCall, result: MethodChannel.Result) {
        val passphrase = call.argument<String>("passphrase")
        if (passphrase == null) {
            result.error("INVALID_ARGUMENT", "Passphrase required", null)
            return
        }

        // SECURITY: Rate limiting to prevent brute-force
        if (passwordRateLimiter.isLockedOut()) {
            val remainingSecs = passwordRateLimiter.getRemainingLockoutMs() / 1000
            result.error(
                "RATE_LIMITED",
                "Too many attempts. Try again in ${remainingSecs}s",
                mapOf("remainingSeconds" to remainingSecs)
            )
            return
        }

        val backoffMs = passwordRateLimiter.getBackoffMs()
        if (backoffMs > 0) {
            val remainingSecs = backoffMs / 1000
            result.error(
                "RATE_LIMITED",
                "Wait ${remainingSecs}s before next attempt",
                mapOf("remainingSeconds" to remainingSecs)
            )
            return
        }
        
        scope.launch {
            vaultBridge.openVault(passphrase).fold(
                onSuccess = {
                    passwordRateLimiter.recordSuccess()
                    result.success(true)
                },
                onFailure = { e -> 
                    if (e is VaultException && e.isAuthError()) {
                        val remaining = passwordRateLimiter.recordFailure()
                        if (remaining == -1) {
                            val remainingSecs = passwordRateLimiter.getRemainingLockoutMs() / 1000
                            result.error(
                                "RATE_LIMITED",
                                "Too many attempts. Try again in ${remainingSecs}s",
                                mapOf("remainingSeconds" to remainingSecs)
                            )
                        } else {
                            result.error(
                                "AUTH_FAILED",
                                "Incorrect password",
                                mapOf("remainingAttempts" to remaining)
                            )
                        }
                        return@fold
                    }
                    val code = when {
                        e.message?.contains("Authentication") == true -> "AUTH_FAILED"
                        e.message?.contains("corrupted") == true -> "CORRUPTED"
                        else -> "OPEN_FAILED"
                    }
                    val message = when (code) {
                        "AUTH_FAILED" -> "Incorrect password"
                        "CORRUPTED" -> "Vault file is corrupted"
                        else -> e.message ?: "Failed to open vault"
                    }
                    result.error(code, message, null)
                }
            )
        }
    }
    
    private fun handleCloseVault(result: MethodChannel.Result) {
        scope.launch {
            vaultBridge.closeVault()
            result.success(true)
        }
    }
    
    private fun handleEnableWakelock(result: MethodChannel.Result) {
        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }
        try {
            currentActivity.window.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            SecureLog.d("VaultPlugin", "handleEnableWakelock: wakelock enabled")
            result.success(true)
        } catch (e: Exception) {
            SecureLog.e("VaultPlugin", "handleEnableWakelock: failed: ${e.message}")
            result.error("WAKELOCK_FAILED", e.message, null)
        }
    }
    
    private fun handleDisableWakelock(result: MethodChannel.Result) {
        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }
        try {
            currentActivity.window.clearFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            SecureLog.d("VaultPlugin", "handleDisableWakelock: wakelock disabled")
            result.success(true)
        } catch (e: Exception) {
            SecureLog.e("VaultPlugin", "handleDisableWakelock: failed: ${e.message}")
            result.error("WAKELOCK_FAILED", e.message, null)
        }
    }
    
    private fun handlePickFile(result: MethodChannel.Result) {
        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }
        
        pendingResult = result
        
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        
        // SECURITY: Mark that we're waiting for file picker
        isAwaitingActivityResult = true
        currentActivity.startActivityForResult(intent, PICK_FILE_REQUEST)
    }

    private fun handlePickFolder(result: MethodChannel.Result) {
        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }

        pendingFolderResult = result

        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
            addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION or
                    Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or
                    Intent.FLAG_GRANT_PREFIX_URI_PERMISSION
            )
        }

        isAwaitingActivityResult = true
        currentActivity.startActivityForResult(intent, PICK_FOLDER_REQUEST)
    }
    
    private fun handleImportFile(call: MethodCall, result: MethodChannel.Result) {
        val uriString = call.argument<String>("uri")
        if (uriString == null) {
            result.error("INVALID_ARGUMENT", "URI required", null)
            return
        }
        val sessionId = call.argument<Number>("sessionId")?.toLong()
        
        // Check if vault is open before attempting import
        if (!vaultBridge.isVaultOpen()) {
            result.error("VAULT_NOT_OPEN", "Vault must be unlocked to import files", null)
            return
        }
        
        // SECURITY: Cleanup any stale pending imports before starting new import
        try {
            val cleaned = vaultBridge.cleanupStalePendingImports()
            if (cleaned > 0) {
                SecureLog.d("VaultPlugin", "Cleaned up $cleaned stale pending imports before file import")
            }
        } catch (e: Exception) {
            SecureLog.w("VaultPlugin", "Failed to cleanup stale imports: ${e.message}")
        }
        
        SecureLog.d("VaultPlugin", "handleImportFile: uri=$uriString")
        val uri = Uri.parse(uriString)
        
        // Validate file
        SecureLog.d("VaultPlugin", "handleImportFile: validating file")
        when (val validation = safFileHandler.validateFile(uri)) {
            is SafFileHandler.FileValidationResult.Valid -> {
                SecureLog.d("VaultPlugin", "handleImportFile: file valid, type=${validation.fileType}, name=${validation.name}, size=${validation.size}")
                scope.launch {
                    // SECURITY: Use streaming for large files to avoid OOM
                    val useStreaming = safFileHandler.shouldUseStreaming(uri, validation.fileType)
                    SecureLog.d("VaultPlugin", "handleImportFile: useStreaming=$useStreaming (size=${validation.size})")
                    
                    if (useStreaming) {
                        // Stream large files chunk by chunk
                        handleImportFileStreaming(uri, validation, sessionId, result)
                    } else {
                        // Small files: read into memory (existing path)
                        handleImportFileSmall(uri, validation, sessionId, result)
                    }
                }
            }
            is SafFileHandler.FileValidationResult.UnsupportedType -> {
                SecureLog.e("VaultPlugin", "handleImportFile: unsupported type ${validation.mimeType}")
                result.error("UNSUPPORTED_TYPE", "File type not supported: ${validation.mimeType}", null)
            }
            is SafFileHandler.FileValidationResult.TooLarge -> {
                SecureLog.e("VaultPlugin", "handleImportFile: file too large ${validation.size}")
                result.error("FILE_TOO_LARGE", "File too large: ${validation.size} bytes", null)
            }
            SafFileHandler.FileValidationResult.Empty -> {
                SecureLog.e("VaultPlugin", "handleImportFile: file is empty")
                result.error("EMPTY_FILE", "File is empty", null)
            }
        }
    }

    private fun handleImportFolder(call: MethodCall, result: MethodChannel.Result) {
        val uriString = call.argument<String>("uri")
        if (uriString == null) {
            result.error("INVALID_ARGUMENT", "URI required", null)
            return
        }
        val sessionId = call.argument<Number>("sessionId")?.toLong()
        SecureLog.d("VaultPlugin", "handleImportFolder: uri=$uriString, sessionId=$sessionId")

        if (!vaultBridge.isVaultOpen()) {
            SecureLog.e("VaultPlugin", "handleImportFolder: vault not open")
            result.error("VAULT_NOT_OPEN", "Vault must be unlocked to import folders", null)
            return
        }

        val ctx = activity
        if (ctx == null) {
            SecureLog.e("VaultPlugin", "handleImportFolder: no activity")
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }
        
        // SECURITY: Cleanup any stale pending imports before starting new folder import
        // This prevents issues where previous failed imports leave orphaned state
        try {
            val cleaned = vaultBridge.cleanupStalePendingImports()
            if (cleaned > 0) {
                SecureLog.d("VaultPlugin", "Cleaned up $cleaned stale pending imports before folder import")
            }
        } catch (e: Exception) {
            SecureLog.w("VaultPlugin", "Failed to cleanup stale imports: ${e.message}")
        }
        
        val root = DocumentFile.fromTreeUri(ctx, Uri.parse(uriString))
        if (root == null) {
            SecureLog.e("VaultPlugin", "handleImportFolder: could not access folder")
            result.error("INVALID_FOLDER", "Could not access folder", null)
            return
        }

        val rootName = root.name ?: "folder"
        SecureLog.d("VaultPlugin", "handleImportFolder: rootName=$rootName")
        val targets = mutableListOf<FolderImportTarget>()
        var skipped = 0
        collectFolderTargets(root, rootName, targets) { skipped++ }
        SecureLog.d("VaultPlugin", "handleImportFolder: collected ${targets.size} targets, skipped=$skipped")

        if (targets.isEmpty()) {
            SecureLog.e("VaultPlugin", "handleImportFolder: folder is empty")
            result.error("EMPTY_FOLDER", "Folder is empty or contains no supported files", null)
            return
        }

        val totalBytes = targets.sumOf { it.validation.size }
        val importId = ByteArray(16).also { importIdRandom.nextBytes(it) }
        emitImportProgress(
            importId = importId,
            bytesWritten = 0,
            totalBytes = totalBytes,
            chunksCompleted = 0,
            totalChunks = targets.size,
            sessionId = sessionId
        )

        scope.launch {
            val imported = mutableListOf<Map<String, Any>>()
            var bytesWritten = 0L
            var completedFiles = 0

            for (target in targets) {
                val validation = target.validation
                val useStreaming = safFileHandler.shouldUseStreaming(target.uri, validation.fileType)
                // FIXED: Use only the file name, folder mapping is handled separately by Dart
                // Previously used fullName with folder path which caused file names like "Folder/file.txt"
                val fileName = validation.name

                if (useStreaming) {
                    var fileId: ByteArray? = null
                    var hadError = false
                    var streamingImportId: ByteArray? = null
                    streamingImportHandler.importFileStreaming(target.uri, fileName)
                        .catch { e ->
                            hadError = true
                            // Cleanup pending import on error
                            streamingImportId?.let { id ->
                                try {
                                    streamingImportHandler.abortImport(id)
                                } catch (_: Exception) {}
                            }
                            emitImportProgress(
                                importId = importId,
                                bytesWritten = bytesWritten,
                                totalBytes = totalBytes,
                                chunksCompleted = completedFiles,
                                totalChunks = targets.size,
                                sessionId = sessionId,
                                error = e.message ?: "Streaming import failed"
                            )
                            result.error("IMPORT_FAILED", e.message, null)
                        }
                        .collect { progress ->
                            // Track the streaming import ID for cleanup on error
                            if (streamingImportId == null && progress.importId.any { it != 0.toByte() }) {
                                streamingImportId = progress.importId
                            }
                            if (hadError) return@collect
                            if (progress.error != null) {
                                // Cleanup pending import on error
                                streamingImportId?.let { id ->
                                    try {
                                        streamingImportHandler.abortImport(id)
                                    } catch (_: Exception) {}
                                }
                                emitImportProgress(
                                    importId = importId,
                                    bytesWritten = bytesWritten,
                                    totalBytes = totalBytes,
                                    chunksCompleted = completedFiles,
                                    totalChunks = targets.size,
                                    sessionId = sessionId,
                                    error = progress.error
                                )
                                result.error("IMPORT_FAILED", progress.error, null)
                                hadError = true
                                return@collect
                            }
                            val aggregate = bytesWritten + progress.bytesWritten
                            emitImportProgress(
                                importId = importId,
                                bytesWritten = aggregate,
                                totalBytes = totalBytes,
                                chunksCompleted = completedFiles,
                                totalChunks = targets.size,
                                sessionId = sessionId
                            )
                            if (progress.isComplete && progress.fileId != null) {
                                fileId = progress.fileId
                            }
                        }
                    if (hadError) return@launch
                    if (fileId == null) {
                        result.error("IMPORT_FAILED", "Streaming import failed", null)
                        return@launch
                    }
                    bytesWritten += validation.size
                    completedFiles++
                    emitImportProgress(
                        importId = importId,
                        bytesWritten = bytesWritten,
                        totalBytes = totalBytes,
                        chunksCompleted = completedFiles,
                        totalChunks = targets.size,
                        isComplete = completedFiles == targets.size,
                        sessionId = sessionId
                    )
                    imported.add(
                        mapOf(
                            "fileId" to fileId!!.toList(),
                            "folder" to target.folder,
                            "name" to validation.name,
                            "size" to validation.size
                        )
                    )
                } else {
                    var data: ByteArray? = null
                    try {
                        data = withContext(Dispatchers.IO) { safFileHandler.readFileBytes(target.uri) }
                        if (data == null) {
                            result.error("READ_FAILED", "Could not read file", null)
                            return@launch
                        }
                        val importResult = vaultBridge.importFile(
                            data = data,
                            type = validation.fileType,
                            name = fileName,
                            mime = validation.mimeType
                        )
                        if (importResult.isFailure) {
                            result.error("IMPORT_FAILED", importResult.exceptionOrNull()?.message, null)
                            return@launch
                        }
                        val fileId = importResult.getOrThrow()
                        bytesWritten += validation.size
                        completedFiles++
                        emitImportProgress(
                            importId = importId,
                            bytesWritten = bytesWritten,
                            totalBytes = totalBytes,
                            chunksCompleted = completedFiles,
                            totalChunks = targets.size,
                            isComplete = completedFiles == targets.size,
                            sessionId = sessionId
                        )
                        imported.add(
                            mapOf(
                                "fileId" to fileId.toList(),
                                "folder" to target.folder,
                                "name" to validation.name,
                                "size" to validation.size
                            )
                        )
                    } finally {
                        SafFileHandler.secureZeroize(data)
                        // Hint GC to reclaim memory after each file
                        if (completedFiles % 10 == 0) {
                            System.gc()
                        }
                    }
                }
            }

            SecureLog.d("VaultPlugin", "handleImportFolder: completed, imported ${imported.size} files, skipped=$skipped")
            for (item in imported) {
                SecureLog.d("VaultPlugin", "handleImportFolder: file=${item["name"]}, folder=${item["folder"]}")
            }
            result.success(
                mapOf(
                    "files" to imported,
                    "skipped" to skipped
                )
            )
        }
    }

    private fun collectFolderTargets(
        root: DocumentFile,
        basePath: String,
        targets: MutableList<FolderImportTarget>,
        onSkip: () -> Unit
    ) {
        // Limit to prevent OOM from too many file metadata
        val maxFiles = 5000
        SecureLog.d("VaultPlugin", "collectFolderTargets: basePath=$basePath, root=${root.name}")
        
        for (child in root.listFiles()) {
            if (targets.size >= maxFiles) {
                SecureLog.w("VaultPlugin", "Folder import limited to $maxFiles files")
                return
            }
            
            val name = child.name ?: continue
            if (child.isDirectory) {
                val nextPath = if (basePath.isEmpty()) name else "$basePath/$name"
                SecureLog.d("VaultPlugin", "collectFolderTargets: entering directory $name, nextPath=$nextPath")
                collectFolderTargets(child, nextPath, targets, onSkip)
            } else if (child.isFile) {
                when (val validation = safFileHandler.validateFile(child.uri)) {
                    is SafFileHandler.FileValidationResult.Valid -> {
                        SecureLog.d("VaultPlugin", "collectFolderTargets: adding file ${validation.name}, folder=$basePath")
                        targets.add(
                            FolderImportTarget(
                                uri = child.uri,
                                validation = validation,
                                folder = basePath
                            )
                        )
                    }
                    else -> {
                        SecureLog.d("VaultPlugin", "collectFolderTargets: skipping file $name (validation failed)")
                        onSkip()
                    }
                }
            }
        }
    }
    
    /**
     * Import small files (<10MB) by reading entirely into memory
     * SECURITY: Zeroizes plaintext after import
     */
    private suspend fun handleImportFileSmall(
        uri: Uri,
        validation: SafFileHandler.FileValidationResult.Valid,
        sessionId: Long?,
        result: MethodChannel.Result
    ) {
        var data: ByteArray? = null
        val importId = ByteArray(16).also { importIdRandom.nextBytes(it) }
        emitImportProgress(
            importId = importId,
            bytesWritten = 0,
            totalBytes = validation.size,
            chunksCompleted = 0,
            totalChunks = 1,
            sessionId = sessionId
        )
        try {
            SecureLog.d("VaultPlugin", "handleImportFileSmall: reading file bytes")
            data = withContext(Dispatchers.IO) { safFileHandler.readFileBytes(uri) }
            if (data == null) {
                SecureLog.e("VaultPlugin", "handleImportFileSmall: readFileBytes returned null")
                emitImportProgress(
                    importId = importId,
                    bytesWritten = 0,
                    totalBytes = validation.size,
                    chunksCompleted = 0,
                    totalChunks = 1,
                    sessionId = sessionId,
                    error = "Read failed"
                )
                result.error("READ_FAILED", "Could not read file", null)
                return
            }
            SecureLog.d("VaultPlugin", "handleImportFileSmall: read ${data.size} bytes, calling vaultBridge.importFile")
            
            vaultBridge.importFile(
                data = data,
                type = validation.fileType,
                name = validation.name,
                mime = validation.mimeType
            ).fold(
                onSuccess = { fileId ->
                    SecureLog.d("VaultPlugin", "handleImportFileSmall: success, fileId=${fileId.toList()}")
                    emitImportProgress(
                        importId = importId,
                        bytesWritten = validation.size,
                        totalBytes = validation.size,
                        chunksCompleted = 1,
                        totalChunks = 1,
                        isComplete = true,
                        sessionId = sessionId
                    )
                    result.success(mapOf(
                        "fileId" to fileId.toList(),
                        "name" to validation.name,
                        "size" to validation.size
                    ))
                },
                onFailure = { e ->
                    SecureLog.e("VaultPlugin", "handleImportFileSmall: vaultBridge.importFile failed: ${e.message}")
                    emitImportProgress(
                        importId = importId,
                        bytesWritten = 0,
                        totalBytes = validation.size,
                        chunksCompleted = 0,
                        totalChunks = 1,
                        sessionId = sessionId,
                        error = e.message ?: "Import failed"
                    )
                    result.error("IMPORT_FAILED", e.message, null)
                }
            )
        } catch (e: Exception) {
            SecureLog.e("VaultPlugin", "handleImportFileSmall: exception: ${e.message}", e)
            emitImportProgress(
                importId = importId,
                bytesWritten = 0,
                totalBytes = validation.size,
                chunksCompleted = 0,
                totalChunks = 1,
                sessionId = sessionId,
                error = e.message ?: "Import failed"
            )
            result.error("IMPORT_FAILED", "Exception: ${e.message}", null)
        } finally {
            // SECURITY: Zeroize plaintext data after import
            SafFileHandler.secureZeroize(data)
        }
    }
    
    /**
     * Import large files (>10MB) using TRUE streaming to avoid OOM
     * SECURITY: Never holds more than 2 chunks in memory, zeroizes each chunk after encryption
     * Supports files up to 50GB with resume capability
     */
    private suspend fun handleImportFileStreaming(
        uri: Uri,
        validation: SafFileHandler.FileValidationResult.Valid,
        sessionId: Long?,
        result: MethodChannel.Result
    ) {
        SecureLog.d("VaultPlugin", "handleImportFileStreaming: starting TRUE streaming import for ${validation.name}")
        
        scope.launch {
            streamingImportHandler.importFileStreaming(uri)
                .catch { e ->
                    SecureLog.e("VaultPlugin", "Streaming import error: ${e.message}", e)
                    result.error("IMPORT_FAILED", e.message, null)
                }
                .collect { progress ->
                    // Send progress to Flutter via EventChannel
                    importProgressSink?.success(mapOf(
                        "importId" to progress.importId.toList(),
                        "bytesWritten" to progress.bytesWritten,
                        "totalBytes" to progress.totalBytes,
                        "chunksCompleted" to progress.chunksCompleted,
                        "totalChunks" to progress.totalChunks,
                        "percentage" to progress.percentage,
                        "isComplete" to progress.isComplete,
                        "error" to progress.error,
                        "sessionId" to sessionId
                    ))
                    
                    // Handle completion or error
                    if (progress.isComplete && progress.fileId != null) {
                        result.success(mapOf(
                            "fileId" to progress.fileId.toList(),
                            "name" to validation.name,
                            "size" to validation.size
                        ))
                    } else if (progress.error != null) {
                        result.error("IMPORT_FAILED", progress.error, null)
                    }
                }
        }
    }
    
    /**
     * Handle streaming import from Flutter method call
     */
    private fun handleImportFileStreaming(call: MethodCall, result: MethodChannel.Result) {
        val uriString = call.argument<String>("uri")
        if (uriString == null) {
            result.error("INVALID_ARGUMENT", "URI required", null)
            return
        }
        val sessionId = call.argument<Number>("sessionId")?.toLong()
        
        if (!vaultBridge.isVaultOpen()) {
            result.error("VAULT_NOT_OPEN", "Vault must be unlocked to import files", null)
            return
        }
        
        val uri = Uri.parse(uriString)
        when (val validation = safFileHandler.validateFile(uri)) {
            is SafFileHandler.FileValidationResult.Valid -> {
                if (validation.fileType != VaultEngine.FILE_TYPE_VIDEO) {
                    result.error("UNSUPPORTED_TYPE", "Streaming import only supports video files", null)
                    return
                }
                scope.launch {
                    handleImportFileStreaming(uri, validation, sessionId, result)
                }
            }
            is SafFileHandler.FileValidationResult.UnsupportedType -> {
                result.error("UNSUPPORTED_TYPE", "File type not supported: ${validation.mimeType}", null)
            }
            is SafFileHandler.FileValidationResult.TooLarge -> {
                result.error("FILE_TOO_LARGE", "File too large: ${validation.size} bytes (max 50GB)", null)
            }
            SafFileHandler.FileValidationResult.Empty -> {
                result.error("EMPTY_FILE", "File is empty", null)
            }
        }
    }

    private fun handleImportBytes(call: MethodCall, result: MethodChannel.Result) {
        val data = call.argument<ByteArray>("data")
        val name = call.argument<String>("name")
        val mime = call.argument<String>("mime")
        val type = call.argument<Number>("type")?.toInt() ?: VaultEngine.FILE_TYPE_TXT
        SecureLog.d("VaultPlugin", "handleImportBytes: name=$name, size=${data?.size}, type=$type")

        if (data == null || name == null || name.isBlank()) {
            SecureLog.e("VaultPlugin", "handleImportBytes: invalid argument")
            result.error("INVALID_ARGUMENT", "Data and name required", null)
            return
        }
        if (!vaultBridge.isVaultOpen()) {
            SecureLog.e("VaultPlugin", "handleImportBytes: vault not open")
            result.error("VAULT_NOT_OPEN", "Vault must be unlocked to import data", null)
            return
        }

        scope.launch {
            try {
                vaultBridge.importFile(
                    data = data,
                    type = type,
                    name = name,
                    mime = mime
                ).fold(
                    onSuccess = { fileId -> 
                        SecureLog.d("VaultPlugin", "handleImportBytes: success, fileId=${fileId.take(4)}")
                        result.success(fileId.toList()) 
                    },
                    onFailure = { e -> 
                        SecureLog.e("VaultPlugin", "handleImportBytes: failed: ${e.message}")
                        result.error("IMPORT_FAILED", e.message, null) 
                    }
                )
            } finally {
                SafFileHandler.secureZeroize(data)
            }
        }
    }
    
    /**
     * List pending imports that can be resumed
     */
    private fun handleListPendingImports(result: MethodChannel.Result) {
        val pending = streamingImportHandler.getPendingImports()
        result.success(pending.map { state ->
            mapOf(
                "importId" to state.importId.toList(),
                "fileId" to state.fileId.toList(),
                "fileName" to state.fileName,
                "mimeType" to state.mimeType,
                "fileType" to state.fileType,
                "fileSize" to state.fileSize,
                "totalChunks" to state.totalChunks,
                "completedChunks" to state.completedChunks,
                "progress" to state.progress,
                "createdAt" to state.createdAt,
                "updatedAt" to state.updatedAt
            )
        })
    }
    
    /**
     * Abort a pending import
     */
    private fun handleAbortImport(call: MethodCall, result: MethodChannel.Result) {
        val importIdList = call.argument<List<Int>>("importId")
        if (importIdList == null) {
            result.error("INVALID_ARGUMENT", "Import ID required", null)
            return
        }
        
        val importId = importIdList.map { it.toByte() }.toByteArray()
        streamingImportHandler.abortImport(importId).fold(
            onSuccess = { result.success(true) },
            onFailure = { e -> result.error("ABORT_FAILED", e.message, null) }
        )
    }
    
    private fun handleReadFile(call: MethodCall, result: MethodChannel.Result) {
        val fileIdList = call.argument<List<Int>>("fileId")
        if (fileIdList == null) {
            result.error("INVALID_ARGUMENT", "File ID required", null)
            return
        }
        
        val fileId = fileIdList.map { it.toByte() }.toByteArray()
        
        scope.launch {
            vaultBridge.readFile(fileId).fold(
                onSuccess = { data -> result.success(data) },
                onFailure = { e -> result.error("READ_FAILED", e.message, null) }
            )
        }
    }

    private fun handleReadTextPreview(call: MethodCall, result: MethodChannel.Result) {
        val fileIdList = call.argument<List<Int>>("fileId")
        val maxBytes = call.argument<Int>("maxBytes") ?: (1024 * 1024) // Default 1MB
        if (fileIdList == null) {
            result.error("INVALID_ARGUMENT", "File ID required", null)
            return
        }
        
        val fileId = fileIdList.map { it.toByte() }.toByteArray()
        
        scope.launch {
            vaultBridge.readTextPreview(fileId, maxBytes).fold(
                onSuccess = { preview ->
                    result.success(mapOf(
                        "data" to preview.data,
                        "truncated" to preview.truncated,
                        "totalSize" to preview.totalSize
                    ))
                },
                onFailure = { e -> result.error("READ_FAILED", e.message, null) }
            )
        }
    }
    
    private fun handleDeleteFile(call: MethodCall, result: MethodChannel.Result) {
        val fileIdList = call.argument<List<Int>>("fileId")
        if (fileIdList == null) {
            result.error("INVALID_ARGUMENT", "File ID required", null)
            return
        }
        
        val fileId = fileIdList.map { it.toByte() }.toByteArray()
        SecureLog.d("VaultPlugin", "handleDeleteFile: deleting file ${fileIdList.take(4)}...")
        
        scope.launch {
            vaultBridge.deleteFile(fileId).fold(
                onSuccess = { 
                    SecureLog.d("VaultPlugin", "handleDeleteFile: file deleted successfully")
                    result.success(true) 
                },
                onFailure = { e -> 
                    SecureLog.e("VaultPlugin", "handleDeleteFile: delete failed: ${e.message}")
                    result.error("DELETE_FAILED", e.message, null) 
                }
            )
        }
    }

    private fun handleCopyFile(call: MethodCall, result: MethodChannel.Result) {
        val fileIdList = call.argument<List<Int>>("fileId")
        if (fileIdList == null) {
            result.error("INVALID_ARGUMENT", "File ID required", null)
            return
        }
        val fileId = fileIdList.map { it.toByte() }.toByteArray()
        SecureLog.d("VaultPlugin", "handleCopyFile: copying file ${fileIdList.take(4)}...")
        
        scope.launch {
            vaultBridge.copyFile(fileId).fold(
                onSuccess = { newId -> 
                    SecureLog.d("VaultPlugin", "handleCopyFile: file copied successfully, newId=${newId.take(4)}...")
                    result.success(newId.toList()) 
                },
                onFailure = { e -> 
                    SecureLog.e("VaultPlugin", "handleCopyFile: copy failed: ${e.message}")
                    result.error("COPY_FAILED", e.message, null) 
                }
            )
        }
    }

    private fun handleExportFile(call: MethodCall, result: MethodChannel.Result) {
        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }
        if (!securityManager.isEnvironmentSecure()) {
            result.error("ENV_BLOCKED", "Environment not supported", null)
            return
        }
        
        val fileIdList = call.argument<List<Int>>("fileId")
        val suggestedName = call.argument<String>("suggestedName")
        
        if (fileIdList == null || suggestedName.isNullOrEmpty()) {
            result.error("INVALID_ARGUMENT", "File ID and suggested name required", null)
            return
        }
        
        val fileId = fileIdList.map { it.toByte() }.toByteArray()
        SecureLog.d("VaultPlugin", "handleExportFile: exporting file ${fileIdList.take(4)}..., name=$suggestedName")
        
        // Set flag BEFORE reading file to prevent vault close during read
        isAwaitingActivityResult = true
        
        // Read file data and save to temp file BEFORE opening file picker
        scope.launch {
            vaultBridge.readFile(fileId).fold(
                onSuccess = { fileData ->
                    SecureLog.d("VaultPlugin", "handleExportFile: read ${fileData.size} bytes from vault")
                    
                    // Save to temp file (will be deleted after export)
                    val tempFile = File(currentActivity.cacheDir, "export_temp_${System.currentTimeMillis()}.tmp")
                    try {
                        tempFile.outputStream().use { it.write(fileData) }
                        SecureLog.d("VaultPlugin", "handleExportFile: saved to temp file ${tempFile.absolutePath}")
                        
                        // Wipe memory immediately after writing to temp
                        java.util.Arrays.fill(fileData, 0.toByte())
                        
                        // Store temp path for use in activity result
                        pendingExportFileResult = result
                        pendingExportFilePath = tempFile.absolutePath
                        
                        // Determine MIME type from file extension
                        val mimeType = getMimeTypeFromName(suggestedName)
                        
                        // Must launch file picker on main thread
                        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                            val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                                addCategory(Intent.CATEGORY_OPENABLE)
                                type = mimeType
                                putExtra(Intent.EXTRA_TITLE, suggestedName)
                            }
                            SecureLog.d("VaultPlugin", "handleExportFile: launching file picker")
                            currentActivity.startActivityForResult(intent, EXPORT_FILE_REQUEST)
                        }
                    } catch (e: Exception) {
                        SecureLog.e("VaultPlugin", "handleExportFile: failed to save temp file: ${e.message}")
                        java.util.Arrays.fill(fileData, 0.toByte())
                        tempFile.delete()
                        isAwaitingActivityResult = false
                        result.error("TEMP_FILE_FAILED", e.message, null)
                    }
                },
                onFailure = { e ->
                    SecureLog.e("VaultPlugin", "handleExportFile: read failed: ${e.message}")
                    isAwaitingActivityResult = false
                    result.error("READ_FAILED", e.message, null)
                }
            )
        }
    }
    
    private fun getMimeTypeFromName(name: String): String {
        val extension = name.substringAfterLast('.', "").lowercase()
        return when (extension) {
            "jpg", "jpeg" -> "image/jpeg"
            "png" -> "image/png"
            "gif" -> "image/gif"
            "webp" -> "image/webp"
            "bmp" -> "image/bmp"
            "mp4" -> "video/mp4"
            "mkv" -> "video/x-matroska"
            "avi" -> "video/x-msvideo"
            "mov" -> "video/quicktime"
            "webm" -> "video/webm"
            "mp3" -> "audio/mpeg"
            "wav" -> "audio/wav"
            "ogg" -> "audio/ogg"
            "flac" -> "audio/flac"
            "m4a" -> "audio/mp4"
            "pdf" -> "application/pdf"
            "doc" -> "application/msword"
            "docx" -> "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            "xls" -> "application/vnd.ms-excel"
            "xlsx" -> "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            "ppt" -> "application/vnd.ms-powerpoint"
            "pptx" -> "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            "txt" -> "text/plain"
            "csv" -> "text/csv"
            "json" -> "application/json"
            "xml" -> "application/xml"
            "zip" -> "application/zip"
            "rar" -> "application/x-rar-compressed"
            "7z" -> "application/x-7z-compressed"
            else -> "application/octet-stream"
        }
    }

    private fun handleRenameFile(call: MethodCall, result: MethodChannel.Result) {
        val fileIdList = call.argument<List<Int>>("fileId")
        val name = call.argument<String>("name")?.trim()
        val allowSystem = call.argument<Boolean>("allowSystem") ?: false
        SecureLog.d("VaultPlugin", "handleRenameFile: name=$name, allowSystem=$allowSystem, fileId=${fileIdList?.take(4)}")
        
        if (fileIdList == null || name.isNullOrEmpty()) {
            SecureLog.e("VaultPlugin", "handleRenameFile: invalid argument")
            result.error("INVALID_ARGUMENT", "File ID and name required", null)
            return
        }
        if (name.length > 4096 || (!allowSystem && name.startsWith("__"))) {
            SecureLog.e("VaultPlugin", "handleRenameFile: invalid file name")
            result.error("INVALID_ARGUMENT", "Invalid file name", null)
            return
        }
        if (allowSystem && name.startsWith("__") && !isAllowedSystemFileName(name)) {
            SecureLog.e("VaultPlugin", "handleRenameFile: invalid system file name")
            result.error("INVALID_ARGUMENT", "Invalid system file name", null)
            return
        }

        val fileId = fileIdList.map { it.toByte() }.toByteArray()

        scope.launch {
            vaultBridge.renameFile(fileId, name).fold(
                onSuccess = { 
                    SecureLog.d("VaultPlugin", "handleRenameFile: success")
                    result.success(true) 
                },
                onFailure = { e -> 
                    SecureLog.e("VaultPlugin", "handleRenameFile: failed: ${e.message}")
                    result.error("RENAME_FAILED", e.message, null) 
                }
            )
        }
    }

    private fun isAllowedSystemFileName(name: String): Boolean {
        return when (name) {
            "__folder_map__",
            "__folder_map__.tmp",
            "__vault_title__",
            "__vault_title__.tmp" -> true
            else -> false
        }
    }
    
    private fun handleGetEntryCount(result: MethodChannel.Result) {
        result.success(vaultBridge.getEntryCount())
    }
    
    private fun handleListFiles(result: MethodChannel.Result) {
        scope.launch {
            vaultBridge.listFiles().fold(
                onSuccess = { entries ->
                    result.success(entries.map { entry ->
                        mapOf(
                            "fileId" to entry.fileId.toList(),
                            "name" to entry.name,
                            "type" to entry.type,
                            "size" to entry.size,
                            "createdAt" to entry.createdAt,
                            "mimeType" to entry.mimeType,
                            "chunkCount" to entry.chunkCount
                        )
                    })
                },
                onFailure = { e ->
                    result.error("LIST_FAILED", e.message, null)
                }
            )
        }
    }
    
    private fun handleAuthenticateBiometric(result: MethodChannel.Result) {
        val currentActivity = activity
        if (currentActivity == null || currentActivity !is FragmentActivity) {
            result.error("NO_ACTIVITY", "FragmentActivity required", null)
            return
        }
        
        secureKeyManager.authenticateWithBiometric(
            activity = currentActivity,
            onSuccess = { result.success(true) },
            onError = { error -> result.error("AUTH_FAILED", error, null) }
        )
    }
    
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        // SECURITY: Clear flag since activity result received
        isAwaitingActivityResult = false
        
        if (requestCode == PICK_FILE_REQUEST) {
            val result = pendingResult
            pendingResult = null
            
            if (resultCode == Activity.RESULT_OK && data?.data != null) {
                val uri = data.data!!
                result?.success(mapOf(
                    "uri" to uri.toString(),
                    "name" to safFileHandler.getFileName(uri),
                    "mimeType" to safFileHandler.getMimeType(uri),
                    "size" to safFileHandler.getFileSize(uri)
                ))
            } else {
                result?.success(null)
            }
            return true
        }
        if (requestCode == PICK_FOLDER_REQUEST) {
            val result = pendingFolderResult
            pendingFolderResult = null

            if (resultCode == Activity.RESULT_OK && data?.data != null) {
                val uri = data.data!!
                val ctx = activity
                if (ctx == null) {
                    result?.success(null)
                    return true
                }
                try {
                    ctx.contentResolver.takePersistableUriPermission(
                        uri,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION
                    )
                } catch (_: Exception) {
                }
                val name = DocumentFile.fromTreeUri(ctx, uri)?.name ?: "folder"
                result?.success(
                    mapOf(
                        "uri" to uri.toString(),
                        "name" to name
                    )
                )
            } else {
                result?.success(null)
            }
            return true
        }
        if (requestCode == EXPORT_VAULT_REQUEST) {
            val result = pendingExportResult
            pendingExportResult = null
            
            if (resultCode == Activity.RESULT_OK && data?.data != null) {
                val uri = data.data!!
                scope.launch {
                    val success = copyVaultToUri(uri)
                    result?.success(success)
                }
            } else {
                result?.success(false)
            }
            return true
        }
        
        if (requestCode == IMPORT_VAULT_REQUEST) {
            val result = pendingImportResult
            pendingImportResult = null
            
            if (resultCode == Activity.RESULT_OK && data?.data != null) {
                val uri = data.data!!
                scope.launch {
                    val success = copyUriToVault(uri)
                    result?.success(success)
                }
            } else {
                result?.success(false)
            }
            return true
        }
        
        if (requestCode == IMPORT_VAULT_WITH_TITLE_REQUEST) {
            val result = pendingImportVaultResult
            val title = pendingImportTitle
            pendingImportVaultResult = null
            pendingImportTitle = null
            
            if (resultCode == Activity.RESULT_OK && data?.data != null && title != null) {
                val uri = data.data!!
                scope.launch {
                    // Run I/O operations on IO dispatcher to avoid ANR
                    val importResult = withContext(Dispatchers.IO) {
                        importVaultWithTitleFromUri(uri, title)
                    }
                    if (importResult != null) {
                        result?.success(importResult)
                    } else {
                        result?.success(null)
                    }
                }
            } else {
                result?.success(null)
            }
            return true
        }
        
        if (requestCode == IMPORT_VAULT_FILE_REQUEST) {
            val result = pendingImportVaultFileResult
            pendingImportVaultFileResult = null
            
            if (resultCode == Activity.RESULT_OK && data?.data != null) {
                val uri = data.data!!
                scope.launch {
                    // Run I/O operations on IO dispatcher to avoid ANR
                    val importResult = withContext(Dispatchers.IO) {
                        importVaultFileFromUri(uri)
                    }
                    if (importResult != null) {
                        result?.success(importResult)
                    } else {
                        result?.success(null)
                    }
                }
            } else {
                result?.success(null)
            }
            return true
        }

        // 2-step import: Pick vault file only (returns URI string)
        if (requestCode == PICK_VAULT_FILE_REQUEST) {
            val result = pendingPickVaultFileResult
            pendingPickVaultFileResult = null
            
            if (resultCode == Activity.RESULT_OK && data?.data != null) {
                val uri = data.data!!
                result?.success(uri.toString())
            } else {
                result?.success(null)
            }
            return true
        }
        
        if (requestCode == EXPORT_FILE_REQUEST) {
            SecureLog.d("VaultPlugin", "onActivityResult: EXPORT_FILE_REQUEST received, resultCode=$resultCode")
            isAwaitingActivityResult = false
            val result = pendingExportFileResult
            val tempFilePath = pendingExportFilePath
            pendingExportFileResult = null
            pendingExportFilePath = null
            
            SecureLog.d("VaultPlugin", "onActivityResult: tempFilePath=$tempFilePath, uri=${data?.data}")
            
            if (resultCode == Activity.RESULT_OK && data?.data != null && tempFilePath != null) {
                val uri = data.data!!
                SecureLog.d("VaultPlugin", "onActivityResult: starting export from temp file to $uri")
                scope.launch {
                    val success = exportTempFileToUri(tempFilePath, uri)
                    SecureLog.d("VaultPlugin", "onActivityResult: export result=$success")
                    result?.success(success)
                }
            } else {
                SecureLog.d("VaultPlugin", "onActivityResult: export cancelled or no temp file")
                // Securely delete temp file if cancelled
                tempFilePath?.let { path ->
                    try {
                        val tempFile = File(path)
                        if (tempFile.exists()) {
                            // Overwrite with zeros before delete
                            tempFile.outputStream().use { out ->
                                val zeros = ByteArray(minOf(tempFile.length().toInt(), 64 * 1024))
                                var remaining = tempFile.length()
                                while (remaining > 0) {
                                    val toWrite = minOf(remaining, zeros.size.toLong()).toInt()
                                    out.write(zeros, 0, toWrite)
                                    remaining -= toWrite
                                }
                            }
                            tempFile.delete()
                            SecureLog.d("VaultPlugin", "onActivityResult: temp file securely deleted")
                        }
                    } catch (e: Exception) {
                        SecureLog.e("VaultPlugin", "onActivityResult: failed to delete temp file: ${e.message}")
                    }
                }
                result?.success(false)
            }
            return true
        }
        return false
    }
    
    private suspend fun exportTempFileToUri(tempFilePath: String, uri: Uri): Boolean {
        val ctx = activity ?: return false
        val tempFile = File(tempFilePath)
        
        if (!tempFile.exists()) {
            SecureLog.e("VaultPlugin", "exportTempFileToUri: temp file not found")
            return false
        }
        
        SecureLog.d("VaultPlugin", "exportTempFileToUri: copying ${tempFile.length()} bytes from temp file")
        
        return try {
            withContext(Dispatchers.IO) {
                // Copy from temp file to destination URI
                ctx.contentResolver.openOutputStream(uri)?.use { output ->
                    tempFile.inputStream().use { input ->
                        val buffer = ByteArray(64 * 1024)
                        var bytesRead: Int
                        while (input.read(buffer).also { bytesRead = it } != -1) {
                            output.write(buffer, 0, bytesRead)
                        }
                        output.flush()
                    }
                }
                
                // Securely delete temp file: overwrite with zeros then delete
                val fileSize = tempFile.length()
                tempFile.outputStream().use { out ->
                    val zeros = ByteArray(minOf(fileSize.toInt(), 64 * 1024))
                    var remaining = fileSize
                    while (remaining > 0) {
                        val toWrite = minOf(remaining, zeros.size.toLong()).toInt()
                        out.write(zeros, 0, toWrite)
                        remaining -= toWrite
                    }
                }
                tempFile.delete()
                
                SecureLog.d("VaultPlugin", "exportTempFileToUri: export completed, temp file securely deleted")
            }
            true
        } catch (e: Exception) {
            SecureLog.e("VaultPlugin", "exportTempFileToUri: export failed: ${e.message}")
            // Try to delete temp file on error
            try {
                tempFile.delete()
            } catch (_: Exception) {}
            false
        }
    }
    
    private suspend fun importVaultFileFromUri(uri: Uri): Map<String, Any>? {
        val ctx = activity ?: return null
        val vaultEngine = VaultEngine.getInstance(ctx)
        val totalBytes = safFileHandler.getFileSize(uri)
        var bytesCopied = 0L
        var lastPercent = -1
        
        SecureLog.d("VaultPlugin", "importVaultFileFromUri: starting, totalBytes=$totalBytes")
        
        if (!securityManager.isEnvironmentSecure()) {
            SecureLog.e("VaultPlugin", "importVaultFileFromUri: environment not secure")
            return null
        }
        
        // SECURITY: Declare tempFile outside try for cleanup in catch
        val tempFile = File(ctx.cacheDir, "vault_import_${System.currentTimeMillis()}.tmp")
        
        // Helper to emit progress on main thread
        suspend fun emitProgress(bytes: Long, total: Long, complete: Boolean = false, err: String? = null) {
            withContext(Dispatchers.Main) {
                emitTransferProgress("import_vault", bytes, total, complete, err)
            }
        }
        
        return try {
            emitProgress(bytesCopied, totalBytes)
            // Copy to temp file first
            ctx.contentResolver.openInputStream(uri)?.use { input ->
                tempFile.outputStream().use { output ->
                    val buffer = ByteArray(64 * 1024)
                    var read = input.read(buffer)
                    var lastEmitTime = System.currentTimeMillis()
                    while (read > 0) {
                        output.write(buffer, 0, read)
                        bytesCopied += read.toLong()
                        if (totalBytes > 0) {
                            val percent = ((bytesCopied * 100) / totalBytes).toInt()
                            if (percent != lastPercent) {
                                lastPercent = percent
                                emitProgress(bytesCopied, totalBytes)
                            }
                        } else {
                            // Unknown total size - emit progress every 500ms
                            val now = System.currentTimeMillis()
                            if (now - lastEmitTime > 500) {
                                lastEmitTime = now
                                // Use bytesCopied as both values to show indeterminate progress
                                emitProgress(bytesCopied, bytesCopied)
                            }
                        }
                        read = input.read(buffer)
                    }
                    output.flush()
                }
            } ?: return null
            
            // After copy, we know the actual size
            val actualSize = tempFile.length()
            SecureLog.d("VaultPlugin", "importVaultFileFromUri: copy complete, actualSize=$actualSize")
            
            // Validate vault magic
            val ok = FileInputStream(tempFile).use { fis ->
                val magic = ByteArray(7)
                val read = fis.read(magic)
                read == 7 && String(magic) == "VAULTv1"
            }
            if (!ok) {
                SecureLog.e("VaultPlugin", "importVaultFileFromUri: invalid vault magic")
                // SECURITY: Secure wipe temp file before deletion
                vaultEngine.secureWipeFile(tempFile.absolutePath)
                return null
            }
            
            // Create registry entry and copy file
            val entry = vaultRegistry.createVaultEntry()
            if (entry == null) {
                SecureLog.e("VaultPlugin", "importVaultFileFromUri: failed to create registry entry")
                // SECURITY: Secure wipe temp file before deletion
                vaultEngine.secureWipeFile(tempFile.absolutePath)
                return null
            }
            
            val (vaultId, vaultPath) = entry
            val vaultFile = File(vaultPath)
            
            SecureLog.d("VaultPlugin", "importVaultFileFromUri: moving temp file to vault location...")
            
            // Try to rename first (instant if same filesystem)
            val renamed = tempFile.renameTo(vaultFile)
            if (!renamed) {
                // Fallback to copy if rename fails (different filesystem)
                SecureLog.d("VaultPlugin", "importVaultFileFromUri: rename failed, falling back to copy...")
                val tempSize = tempFile.length()
                var copiedBytes = 0L
                var lastCopyPercent = -1
                
                tempFile.inputStream().use { input ->
                    vaultFile.outputStream().use { output ->
                        val buffer = ByteArray(64 * 1024)
                        var read = input.read(buffer)
                        while (read > 0) {
                            output.write(buffer, 0, read)
                            copiedBytes += read
                            val percent = ((copiedBytes * 100) / tempSize).toInt()
                            if (percent != lastCopyPercent && percent % 5 == 0) {
                                lastCopyPercent = percent
                                // Emit as "finalizing" phase (100% + copy progress indicator)
                                emitProgress(copiedBytes, tempSize)
                            }
                            read = input.read(buffer)
                        }
                        output.flush()
                    }
                }
                // SECURITY: Secure wipe temp file after copy
                vaultEngine.secureWipeFile(tempFile.absolutePath)
            }
            // If renamed, temp file no longer exists, no need to wipe
            
            // Emit final progress with actual size
            val finalSize = vaultFile.length()
            emitProgress(finalSize, finalSize, complete = true)
            
            SecureLog.d("VaultPlugin", "importVaultFileFromUri: success, vaultId=$vaultId, size=$finalSize, renamed=$renamed")
            
            val metadata = vaultRegistry.getVault(vaultId)
            mapOf(
                "id" to vaultId,
                "filename" to (metadata?.filename ?: ""),
                "createdAt" to (metadata?.createdAt ?: System.currentTimeMillis()),
                "sizeBytes" to finalSize
            )
        } catch (e: Exception) {
            SecureLog.e("VaultPlugin", "Import vault file failed")
            // SECURITY: Clean up temp file on exception
            try {
                vaultEngine.secureWipeFile(tempFile.absolutePath)
            } catch (_: Exception) {}
            emitProgress(bytesCopied, totalBytes, err = "Import failed")
            null
        }
    }
    
    private suspend fun importVaultWithTitleFromUri(uri: Uri, title: String): Map<String, Any>? {
        val ctx = activity ?: return null
        val vaultEngine = VaultEngine.getInstance(ctx)
        val totalBytes = safFileHandler.getFileSize(uri)
        var bytesCopied = 0L
        var lastPercent = -1
        
        if (!securityManager.isEnvironmentSecure()) return null
        
        // SECURITY: Declare tempFile outside try for cleanup in catch
        val tempFile = File(ctx.cacheDir, "vault_import_${System.currentTimeMillis()}.tmp")
        
        // Helper to emit progress on main thread
        suspend fun emitProgress(bytes: Long, total: Long, complete: Boolean = false, err: String? = null) {
            withContext(Dispatchers.Main) {
                emitTransferProgress("import_vault", bytes, total, complete, err)
            }
        }
        
        return try {
            emitProgress(bytesCopied, totalBytes)
            // Copy to temp file first
            ctx.contentResolver.openInputStream(uri)?.use { input ->
                tempFile.outputStream().use { output ->
                    val buffer = ByteArray(64 * 1024)
                    var read = input.read(buffer)
                    var lastEmitTime = System.currentTimeMillis()
                    while (read > 0) {
                        output.write(buffer, 0, read)
                        bytesCopied += read.toLong()
                        if (totalBytes > 0) {
                            val percent = ((bytesCopied * 100) / totalBytes).toInt()
                            if (percent != lastPercent) {
                                lastPercent = percent
                                emitProgress(bytesCopied, totalBytes)
                            }
                        } else {
                            // Unknown total size - emit progress every 500ms
                            val now = System.currentTimeMillis()
                            if (now - lastEmitTime > 500) {
                                lastEmitTime = now
                                emitProgress(bytesCopied, bytesCopied)
                            }
                        }
                        read = input.read(buffer)
                    }
                    output.flush()
                }
            } ?: return null
            
            // Validate vault magic
            val ok = FileInputStream(tempFile).use { fis ->
                val magic = ByteArray(7)
                val read = fis.read(magic)
                read == 7 && String(magic) == "VAULTv1"
            }
            if (!ok) {
                // SECURITY: Secure wipe temp file before deletion
                vaultEngine.secureWipeFile(tempFile.absolutePath)
                return null
            }
            
            // Add to registry
            val metadata = vaultRegistry.addImportedVault(tempFile.absolutePath)
            // SECURITY: Secure wipe temp file after import
            vaultEngine.secureWipeFile(tempFile.absolutePath)
            
            // Emit final progress with actual size
            val finalSize = metadata?.sizeBytes ?: tempFile.length()
            emitProgress(finalSize, finalSize, complete = true)
            
            if (metadata != null) {
                mapOf(
                    "id" to metadata.id,
                    "filename" to metadata.filename,
                    "createdAt" to metadata.createdAt,
                    "sizeBytes" to metadata.sizeBytes
                )
            } else {
                null
            }
        } catch (e: Exception) {
            // SECURITY: Clean up temp file on exception
            try {
                vaultEngine.secureWipeFile(tempFile.absolutePath)
            } catch (_: Exception) {}
            emitProgress(bytesCopied, totalBytes, err = "Import failed")
            null
        }
    }
    
    // Video handling methods
    
    private fun handleOpenVideo(call: MethodCall, result: MethodChannel.Result) {
        val fileIdList = call.argument<List<Int>>("fileId")
        val chunkCount = call.argument<Int>("chunkCount")
        val durationMs = call.argument<Number>("durationMs")?.toLong() ?: 0L
        val width = call.argument<Number>("width")?.toInt() ?: 0
        val height = call.argument<Number>("height")?.toInt() ?: 0
        val size = call.argument<Number>("size")?.toLong() ?: 0L
        
        if (fileIdList == null || chunkCount == null) {
            result.error("INVALID_ARGUMENT", "fileId and chunkCount required", null)
            return
        }
        
        val fileId = fileIdList.map { it.toByte() }.toByteArray()
        
        // Create texture entry for video rendering
        val textureEntry = textureRegistry?.createSurfaceTexture()
        if (textureEntry == null) {
            result.error("TEXTURE_ERROR", "Failed to create texture", null)
            return
        }
        
        val surfaceTexture = textureEntry.surfaceTexture()
        val initialWidth = if (width > 0) width else 1920
        val initialHeight = if (height > 0) height else 1080
        surfaceTexture.setDefaultBufferSize(initialWidth, initialHeight)
        val surface = Surface(surfaceTexture)
        
        scope.launch {
            when (val openResult = videoPlayerManager.openVideo(
                fileId, surface, chunkCount, durationMs, width, height, size
            )) {
                is VideoOpenResult.Success -> {
                    val actualWidth = openResult.width
                    val actualHeight = openResult.height
                    
                    // Set SurfaceTexture buffer size to match actual video dimensions
                    // This must be done to ensure correct aspect ratio rendering
                    val bufferWidth = if (actualWidth > 0) actualWidth else 1920
                    val bufferHeight = if (actualHeight > 0) actualHeight else 1080
                    surfaceTexture.setDefaultBufferSize(bufferWidth, bufferHeight)

                    videoTextures[openResult.handle] = textureEntry
                    videoSurfaces[openResult.handle] = surface
                    videoPlayerManager.setOnPrepared(openResult.handle) { preparedWidth, preparedHeight, _ ->
                        val finalWidth = if (preparedWidth > 0) preparedWidth else bufferWidth
                        val finalHeight = if (preparedHeight > 0) preparedHeight else bufferHeight
                        surfaceTexture.setDefaultBufferSize(finalWidth, finalHeight)
                    }
                    
                    result.success(mapOf(
                        "handle" to openResult.handle,
                        "textureId" to textureEntry.id(),
                        "width" to actualWidth,
                        "height" to actualHeight,
                        "durationMs" to openResult.durationMs
                    ))
                }
                is VideoOpenResult.Error -> {
                    textureEntry.release()
                    surface.release()
                    result.error("OPEN_FAILED", openResult.message, null)
                }
            }
        }
    }
    
    private fun handlePlayVideo(call: MethodCall, result: MethodChannel.Result) {
        val handle = call.argument<Int>("handle")
        if (handle == null) {
            result.error("INVALID_ARGUMENT", "handle required", null)
            return
        }
        
        val success = videoPlayerManager.play(handle)
        result.success(success)
    }
    
    private fun handlePauseVideo(call: MethodCall, result: MethodChannel.Result) {
        val handle = call.argument<Int>("handle")
        if (handle == null) {
            result.error("INVALID_ARGUMENT", "handle required", null)
            return
        }
        
        val success = videoPlayerManager.pause(handle)
        result.success(success)
    }
    
    private fun handleSeekVideo(call: MethodCall, result: MethodChannel.Result) {
        val handle = call.argument<Int>("handle")
        // Handle both Int and Long from Flutter (Dart int can be either)
        val positionMs: Long? = when (val pos = call.argument<Any>("positionMs")) {
            is Long -> pos
            is Int -> pos.toLong()
            is Number -> pos.toLong()
            else -> null
        }
        
        if (handle == null || positionMs == null) {
            result.error("INVALID_ARGUMENT", "handle and positionMs required", null)
            return
        }
        
        val success = videoPlayerManager.seek(handle, positionMs)
        result.success(success)
    }
    
    private fun handleGetVideoPosition(call: MethodCall, result: MethodChannel.Result) {
        val handle = call.argument<Int>("handle")
        if (handle == null) {
            result.error("INVALID_ARGUMENT", "handle required", null)
            return
        }
        
        result.success(videoPlayerManager.getPosition(handle))
    }
    
    private fun handleGetVideoDuration(call: MethodCall, result: MethodChannel.Result) {
        val handle = call.argument<Int>("handle")
        if (handle == null) {
            result.error("INVALID_ARGUMENT", "handle required", null)
            return
        }
        
        result.success(videoPlayerManager.getDuration(handle))
    }
    
    private fun handleIsVideoPlaying(call: MethodCall, result: MethodChannel.Result) {
        val handle = call.argument<Int>("handle")
        if (handle == null) {
            result.error("INVALID_ARGUMENT", "handle required", null)
            return
        }
        
        result.success(videoPlayerManager.isPlaying(handle))
    }
    
    private fun handleCloseVideo(call: MethodCall, result: MethodChannel.Result) {
        val handle = call.argument<Int>("handle")
        if (handle == null) {
            result.error("INVALID_ARGUMENT", "handle required", null)
            return
        }
        
        videoPlayerManager.setOnPrepared(handle, null)
        val success = videoPlayerManager.close(handle)
        videoSurfaces.remove(handle)?.release()
        videoTextures.remove(handle)?.release()
        result.success(success)
    }

    // Audio handling methods

    private fun handleOpenAudio(call: MethodCall, result: MethodChannel.Result) {
        val fileIdList = call.argument<List<Int>>("fileId")
        if (fileIdList == null) {
            result.error("INVALID_ARGUMENT", "fileId required", null)
            return
        }
        val fileId = fileIdList.map { it.toByte() }.toByteArray()

        scope.launch {
            when (val openResult = audioPlayerManager.openAudio(fileId)) {
                is AudioOpenResult.Success -> {
                    result.success(
                        mapOf(
                            "handle" to openResult.handle,
                            "durationMs" to openResult.durationMs
                        )
                    )
                }
                is AudioOpenResult.Error -> {
                    result.error("OPEN_FAILED", openResult.message, null)
                }
            }
        }
    }

    private fun handlePlayAudio(call: MethodCall, result: MethodChannel.Result) {
        val handle = call.argument<Int>("handle")
        if (handle == null) {
            result.error("INVALID_ARGUMENT", "handle required", null)
            return
        }
        result.success(audioPlayerManager.play(handle))
    }

    private fun handlePauseAudio(call: MethodCall, result: MethodChannel.Result) {
        val handle = call.argument<Int>("handle")
        if (handle == null) {
            result.error("INVALID_ARGUMENT", "handle required", null)
            return
        }
        result.success(audioPlayerManager.pause(handle))
    }

    private fun handleSeekAudio(call: MethodCall, result: MethodChannel.Result) {
        val handle = call.argument<Int>("handle")
        val positionMs = call.argument<Number>("positionMs")?.toLong()
        if (handle == null || positionMs == null) {
            result.error("INVALID_ARGUMENT", "handle and positionMs required", null)
            return
        }
        result.success(audioPlayerManager.seek(handle, positionMs))
    }

    private fun handleGetAudioPosition(call: MethodCall, result: MethodChannel.Result) {
        val handle = call.argument<Int>("handle")
        if (handle == null) {
            result.error("INVALID_ARGUMENT", "handle required", null)
            return
        }
        result.success(audioPlayerManager.getPosition(handle))
    }

    private fun handleGetAudioDuration(call: MethodCall, result: MethodChannel.Result) {
        val handle = call.argument<Int>("handle")
        if (handle == null) {
            result.error("INVALID_ARGUMENT", "handle required", null)
            return
        }
        result.success(audioPlayerManager.getDuration(handle))
    }

    private fun handleIsAudioPlaying(call: MethodCall, result: MethodChannel.Result) {
        val handle = call.argument<Int>("handle")
        if (handle == null) {
            result.error("INVALID_ARGUMENT", "handle required", null)
            return
        }
        result.success(audioPlayerManager.isPlaying(handle))
    }

    private fun handleCloseAudio(call: MethodCall, result: MethodChannel.Result) {
        val handle = call.argument<Int>("handle")
        if (handle == null) {
            result.error("INVALID_ARGUMENT", "handle required", null)
            return
        }
        result.success(audioPlayerManager.close(handle))
    }

    // Security methods
    
    private fun handleEnableSecureWindow(result: MethodChannel.Result) {
        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }
        
        currentActivity.runOnUiThread {
            currentActivity.window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )
        }
        result.success(true)
    }
    
    private fun handleDisableSecureWindow(result: MethodChannel.Result) {
        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }
        
        currentActivity.runOnUiThread {
            currentActivity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        result.success(true)
    }
    
    private fun handleScanForPlaintext(result: MethodChannel.Result) {
        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }
        
        scope.launch {
            val findings = PlaintextScanner.scanForPlaintext(currentActivity.applicationContext)
            result.success(findings.map { mapOf("path" to it.path, "reason" to it.reason) })
        }
    }

    private fun handleExportVault(result: MethodChannel.Result) {
        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }
        if (!securityManager.isEnvironmentSecure()) {
            result.error("ENV_BLOCKED", "Environment not supported", null)
            return
        }
        
        // For multi-vault: check if vault is currently open and use that path
        // Otherwise fall back to legacy single-vault path
        val vaultEngine = VaultEngine.getInstance(currentActivity)
        val vaultPath = if (vaultEngine.isOpen()) {
            // Use the currently open vault path
            vaultEngine.getCurrentVaultPath() ?: vaultEngine.getVaultPath()
        } else {
            vaultEngine.getVaultPath()
        }
        
        if (!java.io.File(vaultPath).exists()) {
            result.error("NO_VAULT", "No vault to export (path: $vaultPath)", null)
            return
        }
        
        // Store path for use in copyVaultToUri
        pendingExportVaultPath = vaultPath
        pendingExportResult = result

        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/octet-stream"
            putExtra(Intent.EXTRA_TITLE, "vault_export.dat")
        }
        isAwaitingActivityResult = true
        currentActivity.startActivityForResult(intent, EXPORT_VAULT_REQUEST)
    }

    private fun handleImportVault(result: MethodChannel.Result) {
        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }
        if (!securityManager.isEnvironmentSecure()) {
            result.error("ENV_BLOCKED", "Environment not supported", null)
            return
        }
        pendingImportResult = result

        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        isAwaitingActivityResult = true
        currentActivity.startActivityForResult(intent, IMPORT_VAULT_REQUEST)
    }

    private suspend fun copyVaultToUri(uri: Uri): Boolean {
        val ctx = activity ?: return false
        // Use pendingExportVaultPath if set (multi-vault), otherwise default vault
        val vaultPath = pendingExportVaultPath ?: VaultEngine.getInstance(ctx).getVaultPath()
        pendingExportVaultPath = null
        val totalBytes = File(vaultPath).length()
        var bytesCopied = 0L
        var lastPercent = -1

        return try {
            emitTransferProgress("export_vault", bytesCopied, totalBytes)
            FileInputStream(File(vaultPath)).use { input ->
                ctx.contentResolver.openOutputStream(uri)?.use { output ->
                    val buffer = ByteArray(64 * 1024)
                    var read = input.read(buffer)
                    while (read > 0) {
                        output.write(buffer, 0, read)
                        bytesCopied += read.toLong()
                        if (totalBytes > 0) {
                            val percent = ((bytesCopied * 100) / totalBytes).toInt()
                            if (percent != lastPercent) {
                                lastPercent = percent
                                emitTransferProgress("export_vault", bytesCopied, totalBytes)
                            }
                        }
                        read = input.read(buffer)
                    }
                    output.flush()
                    emitTransferProgress("export_vault", totalBytes, totalBytes, isComplete = true)
                    true
                } ?: false
            }
        } catch (e: Exception) {
            emitTransferProgress("export_vault", bytesCopied, totalBytes, error = "Export failed")
            false
        }
    }

    private suspend fun copyUriToVault(uri: Uri): Boolean {
        val ctx = activity ?: return false
        val vaultEngine = VaultEngine.getInstance(ctx)
        val vaultPath = vaultEngine.getVaultPath()
        val totalBytes = safFileHandler.getFileSize(uri)
        var bytesCopied = 0L
        var lastPercent = -1

        if (!securityManager.isEnvironmentSecure()) return false

        // SECURITY: Declare tempFile outside try for cleanup in catch
        val tempFile = File(ctx.cacheDir, "vault_import.tmp")
        
        return try {
            // Close current vault before replacing
            vaultBridge.closeVault()
            emitTransferProgress("import_vault", bytesCopied, totalBytes)
            ctx.contentResolver.openInputStream(uri)?.use { input ->
                tempFile.outputStream().use { output ->
                    val buffer = ByteArray(64 * 1024)
                    var read = input.read(buffer)
                    while (read > 0) {
                        output.write(buffer, 0, read)
                        bytesCopied += read.toLong()
                        if (totalBytes > 0) {
                            val percent = ((bytesCopied * 100) / totalBytes).toInt()
                            if (percent != lastPercent) {
                                lastPercent = percent
                                emitTransferProgress("import_vault", bytesCopied, totalBytes)
                            }
                        }
                        read = input.read(buffer)
                    }
                    output.flush()
                }
            } ?: return false

            // Minimal magic check
            val ok = FileInputStream(tempFile).use { fis ->
                val magic = ByteArray(7)
                val read = fis.read(magic)
                read == 7 && String(magic) == "VAULTv1"
            }
            if (!ok) {
                // SECURITY: Secure wipe temp file before deletion
                vaultEngine.secureWipeFile(tempFile.absolutePath)
                return false
            }

            val destFile = File(vaultPath)
            tempFile.copyTo(destFile, overwrite = true)
            // SECURITY: Secure wipe temp file after copy
            vaultEngine.secureWipeFile(tempFile.absolutePath)
            emitTransferProgress("import_vault", totalBytes, totalBytes, isComplete = true)
            true
        } catch (e: Exception) {
            // SECURITY: Clean up temp file on exception
            try {
                vaultEngine.secureWipeFile(tempFile.absolutePath)
            } catch (_: Exception) {}
            emitTransferProgress("import_vault", bytesCopied, totalBytes, error = "Import failed")
            false
        }
    }

    private fun emitTransferProgress(
        operation: String,
        bytesProcessed: Long,
        totalBytes: Long,
        isComplete: Boolean = false,
        error: String? = null
    ) {
        val percent = if (totalBytes > 0) {
            (bytesProcessed.toDouble() / totalBytes.toDouble()) * 100.0
        } else {
            0.0
        }
        transferProgressSink?.success(
            mapOf(
                "operation" to operation,
                "bytesProcessed" to bytesProcessed,
                "totalBytes" to totalBytes,
                "percent" to percent,
                "isComplete" to isComplete,
                "error" to error
            )
        )
    }

    private fun emitImportProgress(
        importId: ByteArray,
        bytesWritten: Long,
        totalBytes: Long,
        chunksCompleted: Int,
        totalChunks: Int,
        isComplete: Boolean = false,
        sessionId: Long? = null,
        error: String? = null
    ) {
        val percentage = if (totalBytes > 0) {
            (bytesWritten.toDouble() / totalBytes.toDouble()) * 100.0
        } else {
            0.0
        }
        importProgressSink?.success(
            mapOf(
                "importId" to importId.toList(),
                "bytesWritten" to bytesWritten,
                "totalBytes" to totalBytes,
                "chunksCompleted" to chunksCompleted,
                "totalChunks" to totalChunks,
                "percentage" to percentage,
                "isComplete" to isComplete,
                "sessionId" to sessionId,
                "error" to error
            )
        )
    }

    private fun handleVerifyPassword(call: MethodCall, result: MethodChannel.Result) {
        val password = call.argument<String>("password")
        if (password == null) {
            result.error("INVALID_ARGUMENT", "password required", null)
            return
        }
        if (!securityManager.isEnvironmentSecure()) {
            result.error("ENV_BLOCKED", "Environment not supported", null)
            return
        }
        
        // SECURITY: Rate limiting to prevent brute-force
        if (passwordRateLimiter.isLockedOut()) {
            val remainingSecs = passwordRateLimiter.getRemainingLockoutMs() / 1000
            result.error("RATE_LIMITED", "Too many attempts. Try again in ${remainingSecs}s", null)
            return
        }
        
        val backoffMs = passwordRateLimiter.getBackoffMs()
        if (backoffMs > 0) {
            result.error("RATE_LIMITED", "Wait ${backoffMs / 1000}s before next attempt", null)
            return
        }

        scope.launch {
            try {
                val verified = vaultBridge.verifyPassword(password)
                if (verified) {
                    passwordRateLimiter.recordSuccess()
                } else {
                    val remaining = passwordRateLimiter.recordFailure()
                    if (remaining == -1) {
                        SecureLog.security("VaultPlugin", "Password lockout activated")
                    }
                }
                result.success(verified)
            } catch (e: Exception) {
                passwordRateLimiter.recordFailure()
                result.success(false)
            }
        }
    }

    private fun handleChangePassword(call: MethodCall, result: MethodChannel.Result) {
        val currentPassword = call.argument<String>("currentPassword")
        val newPassword = call.argument<String>("newPassword")
        
        if (currentPassword == null || newPassword == null) {
            result.error("INVALID_ARGUMENT", "currentPassword and newPassword required", null)
            return
        }
        if (newPassword.length < 12) {
            result.error("WEAK_PASSWORD", "New password must be at least 12 characters", null)
            return
        }
        if (!securityManager.isEnvironmentSecure()) {
            result.error("ENV_BLOCKED", "Environment not supported", null)
            return
        }
        if (!vaultBridge.isVaultOpen()) {
            result.error("VAULT_LOCKED", "Vault must be unlocked to change password", null)
            return
        }

        scope.launch {
            try {
                val success = vaultBridge.changePassword(currentPassword, newPassword)
                result.success(success)
            } catch (e: Exception) {
                result.error("CHANGE_FAILED", e.message, null)
            }
        }
    }

    // ========== Multi-Vault Methods ==========

    private fun handleListVaults(result: MethodChannel.Result) {
        val vaults = vaultRegistry.listVaults()
        result.success(vaults.map { vault ->
            mapOf(
                "id" to vault.id,
                "filename" to vault.filename,
                "createdAt" to vault.createdAt,
                "sizeBytes" to vault.sizeBytes
            )
        })
    }

    private fun handleCreateVaultWithTitle(call: MethodCall, result: MethodChannel.Result) {
        val title = call.argument<String>("title")
        val password = call.argument<String>("password")
        
        if (title == null || password == null) {
            result.error("INVALID_ARGUMENT", "title and password required", null)
            return
        }
        if (password.length < 12) {
            result.error("WEAK_PASSWORD", "Password must be at least 12 characters", null)
            return
        }
        if (!vaultRegistry.canAddVault()) {
            result.error("MAX_VAULTS", "Maximum 10 vaults allowed", null)
            return
        }
        
        // Security check
        if (!securityManager.isEnvironmentSecure()) {
            result.error("ENV_BLOCKED", "Environment not supported", null)
            return
        }
        
        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }

        scope.launch {
            try {
                // Create vault entry in registry
                val entry = vaultRegistry.createVaultEntry()
                if (entry == null) {
                    result.error("REGISTRY_FAILED", "Failed to create vault entry in registry", null)
                    return@launch
                }
                
                val (vaultId, vaultPath) = entry
                
                // Create the actual vault file with the VaultEngine
                val vaultEngine = VaultEngine.getInstance(currentActivity)
                
                // Initialize vault engine if not already
                val initResult = vaultBridge.initialize()
                if (initResult.isFailure) {
                    vaultRegistry.deleteVault(vaultId)
                    result.error("INIT_FAILED", "Failed to initialize vault engine: ${initResult.exceptionOrNull()?.message}", null)
                    return@launch
                }
                
                // Create vault at path
                val createResult = vaultBridge.createVaultAtPath(vaultPath, password)
                
                if (createResult.isSuccess) {
                    // Store encrypted title in vault
                    // Use type 1 (TEXT) for title metadata
                    val titleData = title.toByteArray(Charsets.UTF_8)
                    val openResult = vaultBridge.openVaultAtPath(vaultPath, password)
                    
                    if (openResult.isSuccess) {
                        val importResult = vaultBridge.importFile(titleData, 1, "__vault_title__", "text/plain")
                        if (importResult.isFailure) {
                            SecureLog.e("VaultPlugin", "Failed to save title")
                        } else {
                            SecureLog.i("VaultPlugin", "Title saved")
                        }
                        vaultBridge.closeVault()
                    } else {
                        SecureLog.e("VaultPlugin", "Failed to open vault for title: ${openResult.exceptionOrNull()?.message}")
                        // Vault was created but we couldn't save title - still return success
                        // Title will just be empty
                    }
                    
                    val metadata = vaultRegistry.getVault(vaultId)
                    val vaultFile = java.io.File(vaultPath)
                    result.success(mapOf(
                        "id" to vaultId,
                        "filename" to (metadata?.filename ?: ""),
                        "createdAt" to (metadata?.createdAt ?: System.currentTimeMillis()),
                        "sizeBytes" to vaultFile.length()
                    ))
                } else {
                    vaultRegistry.deleteVault(vaultId)
                    val errorMsg = createResult.exceptionOrNull()?.message ?: "Unknown error during vault creation"
                    result.error("CREATE_FAILED", errorMsg, null)
                }
            } catch (e: Exception) {
                result.error("CREATE_FAILED", "Exception: ${e.message ?: e.javaClass.simpleName}", null)
            }
        }
    }

    private fun handleImportVaultWithTitle(call: MethodCall, result: MethodChannel.Result) {
        val title = call.argument<String>("title")
        
        if (title == null) {
            result.error("INVALID_ARGUMENT", "title required", null)
            return
        }
        if (!vaultRegistry.canAddVault()) {
            result.error("MAX_VAULTS", "Maximum 10 vaults allowed", null)
            return
        }

        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }

        // Store title for later use after file is selected
        pendingImportTitle = title
        pendingImportVaultResult = result

        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        currentActivity.startActivityForResult(intent, IMPORT_VAULT_WITH_TITLE_REQUEST)
    }

    private var pendingImportTitle: String? = null
    private var pendingImportVaultResult: MethodChannel.Result? = null
    private val IMPORT_VAULT_WITH_TITLE_REQUEST = 1006
    private val IMPORT_VAULT_FILE_REQUEST = 1007
    private var pendingImportVaultFileResult: MethodChannel.Result? = null
    private val PICK_VAULT_FILE_REQUEST = 1008
    private var pendingPickVaultFileResult: MethodChannel.Result? = null

    private fun handleImportVaultFile(result: MethodChannel.Result) {
        if (!vaultRegistry.canAddVault()) {
            result.error("MAX_VAULTS", "Maximum 10 vaults allowed", null)
            return
        }

        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }

        pendingImportVaultFileResult = result

        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        currentActivity.startActivityForResult(intent, IMPORT_VAULT_FILE_REQUEST)
    }

    // 2-step import: Step 1 - Pick file only (returns URI string)
    private fun handlePickVaultFile(result: MethodChannel.Result) {
        if (!vaultRegistry.canAddVault()) {
            result.error("MAX_VAULTS", "Maximum 10 vaults allowed", null)
            return
        }

        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }

        pendingPickVaultFileResult = result
        
        // SECURITY: Mark that we're waiting for file picker
        isAwaitingActivityResult = true

        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        currentActivity.startActivityForResult(intent, PICK_VAULT_FILE_REQUEST)
    }

    // 2-step import: Step 2 - Import from URI (with progress)
    private fun handleImportVaultFromUri(call: MethodCall, result: MethodChannel.Result) {
        val uriString = call.argument<String>("uri")
        if (uriString == null) {
            result.error("INVALID_ARGUMENT", "uri required", null)
            return
        }

        if (!vaultRegistry.canAddVault()) {
            result.error("MAX_VAULTS", "Maximum 10 vaults allowed", null)
            return
        }

        val uri = Uri.parse(uriString)
        scope.launch {
            // Run I/O operations on IO dispatcher to avoid ANR
            val importResult = withContext(Dispatchers.IO) {
                importVaultFileFromUri(uri)
            }
            if (importResult != null) {
                result.success(importResult)
            } else {
                result.success(null)
            }
        }
    }

    private fun handleGetVaultTitle(call: MethodCall, result: MethodChannel.Result) {
        val vaultId = call.argument<String>("vaultId")
        val password = call.argument<String>("password")
        
        if (vaultId == null || password == null) {
            result.error("INVALID_ARGUMENT", "vaultId and password required", null)
            return
        }

        val vaultPath = vaultRegistry.getVaultPath(vaultId)
        if (vaultPath == null) {
            result.error("NOT_FOUND", "Vault not found", null)
            return
        }

        scope.launch {
            try {
                // Check if the requested vault is already open
                val vaultEngine = VaultEngine.getInstance(activity!!)
                val isAlreadyOpen = vaultBridge.isVaultOpen() && vaultEngine.getCurrentVaultPath() == vaultPath
                
                if (!isAlreadyOpen) {
                    // Close any currently open vault first
                    if (vaultBridge.isVaultOpen()) {
                        vaultBridge.closeVault()
                    }
                    
                    val openResult = vaultBridge.openVaultAtPath(vaultPath, password)
                    if (openResult.isFailure) {
                        result.error("AUTH_FAILED", "Incorrect password", null)
                        return@launch
                    }
                }
                
                // Find the title file
                val files = vaultBridge.listFiles().getOrNull()
                val titleEntry = files?.find { it.name == "__vault_title__" }
                
                val title = if (titleEntry != null) {
                    val titleData = vaultBridge.readFile(titleEntry.fileId).getOrNull()
                    titleData?.toString(Charsets.UTF_8) ?: ""
                } else {
                    // No title entry = legacy vault, return empty string (not error)
                    ""
                }
                
                // Only close if we opened it ourselves
                if (!isAlreadyOpen) {
                    vaultBridge.closeVault()
                }
                
                result.success(title)
            } catch (e: Exception) {
                result.error("READ_FAILED", e.message, null)
            }
        }
    }

    private fun handleSetVaultTitle(call: MethodCall, result: MethodChannel.Result) {
        val vaultId = call.argument<String>("vaultId")
        val password = call.argument<String>("password")
        val newTitle = call.argument<String>("newTitle")
        
        if (vaultId == null || password == null || newTitle == null) {
            result.error("INVALID_ARGUMENT", "vaultId, password, and newTitle required", null)
            return
        }

        val vaultPath = vaultRegistry.getVaultPath(vaultId)
        if (vaultPath == null) {
            result.error("NOT_FOUND", "Vault not found", null)
            return
        }

        scope.launch {
            try {
                // Check if the requested vault is already open
                val vaultEngine = VaultEngine.getInstance(activity!!)
                val isAlreadyOpen = vaultBridge.isVaultOpen() && vaultEngine.getCurrentVaultPath() == vaultPath
                
                if (!isAlreadyOpen) {
                    // Close any currently open vault first
                    if (vaultBridge.isVaultOpen()) {
                        vaultBridge.closeVault()
                    }
                    
                    val openResult = vaultBridge.openVaultAtPath(vaultPath, password)
                    if (openResult.isFailure) {
                        SecureLog.e("VaultPlugin", "Failed to open vault for title update")
                        result.error("AUTH_FAILED", "Incorrect password", null)
                        return@launch
                    }
                }
                
                // Find and delete existing title
                val files = vaultBridge.listFiles().getOrNull()
                val titleEntry = files?.find { it.name == "__vault_title__" }
                if (titleEntry != null) {
                    vaultBridge.deleteFile(titleEntry.fileId)
                }
                
                // Store new title - use type 1 (TEXT)
                val titleData = newTitle.toByteArray(Charsets.UTF_8)
                val importResult = vaultBridge.importFile(titleData, 1, "__vault_title__", "text/plain")
                if (importResult.isFailure) {
                    SecureLog.e("VaultPlugin", "Failed to save new title")
                }
                
                // Only close if we opened it ourselves
                if (!isAlreadyOpen) {
                    vaultBridge.closeVault()
                }
                
                result.success(true)
            } catch (e: Exception) {
                result.error("UPDATE_FAILED", e.message, null)
            }
        }
    }

    private fun handleDeleteVaultById(call: MethodCall, result: MethodChannel.Result) {
        val vaultId = call.argument<String>("vaultId")
        
        if (vaultId == null) {
            result.error("INVALID_ARGUMENT", "vaultId required", null)
            return
        }

        // Close current vault if it's the one being deleted
        if (currentVaultId == vaultId && vaultBridge.isVaultOpen()) {
            scope.launch { vaultBridge.closeVault() }
        }

        val success = vaultRegistry.deleteVault(vaultId)
        result.success(success)
    }

    private fun handleOpenVaultById(call: MethodCall, result: MethodChannel.Result) {
        val vaultId = call.argument<String>("vaultId")
        val password = call.argument<String>("password")
        
        if (vaultId == null || password == null) {
            result.error("INVALID_ARGUMENT", "vaultId and password required", null)
            return
        }

        val vaultPath = vaultRegistry.getVaultPath(vaultId)
        if (vaultPath == null) {
            result.error("NOT_FOUND", "Vault not found", null)
            return
        }

        // SECURITY: Rate limiting to prevent brute-force
        if (passwordRateLimiter.isLockedOut()) {
            val remainingSecs = passwordRateLimiter.getRemainingLockoutMs() / 1000
            result.error(
                "RATE_LIMITED",
                "Too many attempts. Try again in ${remainingSecs}s",
                mapOf("remainingSeconds" to remainingSecs)
            )
            return
        }

        val backoffMs = passwordRateLimiter.getBackoffMs()
        if (backoffMs > 0) {
            val remainingSecs = backoffMs / 1000
            result.error(
                "RATE_LIMITED",
                "Wait ${remainingSecs}s before next attempt",
                mapOf("remainingSeconds" to remainingSecs)
            )
            return
        }

        scope.launch {
            // Close any currently open vault
            if (vaultBridge.isVaultOpen()) {
                vaultBridge.closeVault()
            }

            vaultBridge.openVaultAtPath(vaultPath, password).fold(
                onSuccess = {
                    currentVaultId = vaultId
                    passwordRateLimiter.recordSuccess()
                    result.success(true)
                },
                onFailure = { e ->
                    if (e is VaultException && e.isAuthError()) {
                        val remaining = passwordRateLimiter.recordFailure()
                        if (remaining == -1) {
                            val remainingSecs = passwordRateLimiter.getRemainingLockoutMs() / 1000
                            result.error(
                                "RATE_LIMITED",
                                "Too many attempts. Try again in ${remainingSecs}s",
                                mapOf("remainingSeconds" to remainingSecs)
                            )
                        } else {
                            result.error(
                                "AUTH_FAILED",
                                "Incorrect password",
                                mapOf("remainingAttempts" to remaining)
                            )
                        }
                        return@fold
                    }
                    val code = when {
                        e.message?.contains("Authentication") == true -> "AUTH_FAILED"
                        e.message?.contains("corrupted") == true -> "CORRUPTED"
                        else -> "OPEN_FAILED"
                    }
                    val message = when (code) {
                        "AUTH_FAILED" -> "Incorrect password"
                        "CORRUPTED" -> "Vault file is corrupted"
                        else -> e.message ?: "Failed to open vault"
                    }
                    result.error(code, message, null)
                }
            )
        }
    }

    private fun handleExportVaultById(call: MethodCall, result: MethodChannel.Result) {
        val vaultId = call.argument<String>("vaultId")
        
        if (vaultId == null) {
            result.error("INVALID_ARGUMENT", "vaultId required", null)
            return
        }

        val vaultPath = vaultRegistry.getVaultPath(vaultId)
        if (vaultPath == null) {
            result.error("NOT_FOUND", "Vault not found", null)
            return
        }

        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }

        pendingExportVaultPath = vaultPath
        pendingExportResult = result

        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/octet-stream"
            putExtra(Intent.EXTRA_TITLE, "vault_export.dat")
        }
        currentActivity.startActivityForResult(intent, EXPORT_VAULT_REQUEST)
    }

    private var pendingExportVaultPath: String? = null
}
