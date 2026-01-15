package com.noleak.noleak.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.provider.Settings
import com.noleak.noleak.BuildConfig
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.security.MessageDigest

/**
 * RootGate - Security checks for root/tamper/debug detection
 * 
 * Implements fail-closed behavior: if ANY check fails, all vault operations are blocked.
 */
object RootGate {
    
    enum class SecurityResult {
        OK,
        BLOCKED
    }
    
    private val SU_PATHS = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/su",
        "/system/bin/.ext/.su",
        "/system/usr/we-need-root/su-backup",
        "/system/xbin/mu",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/local/su",
        "/su/bin/su",
        "/su/bin",
        "/magisk/.core/bin/su"
    )
    
    private val MAGISK_PATHS = listOf(
        "/sbin/.magisk",
        "/sbin/.core",
        "/data/adb/magisk",
        "/data/adb/modules",
        "/data/adb/zygisk",
        "/data/adb/modules/zygisk",
        "/system/xbin/magisk",
        "/cache/.disable_magisk",
        "/dev/.magisk.unblock"
    )

    private val FRIDA_PATHS = listOf(
        "/data/local/tmp/frida-server",
        "/data/local/tmp/re.frida.server",
        "/system/bin/frida-server",
        "/system/xbin/frida-server"
    )
    
    private val DANGEROUS_PACKAGES = listOf(
        "com.topjohnwu.magisk",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "eu.chainfire.supersu",
        "com.yellowes.su",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclickroot",
        "com.zhiqupk.root.global",
        "com.alephzain.framaroot"
    )
    
    private val HOOKING_LIBRARIES = listOf(
        "frida",
        "xposed",
        "substrate",
        "cydia",
        "libhook",
        "libxposed"
    )

    private val BLOCKED_INSTALLERS = listOf(
        "com.android.shell"
    )
    
    /**
     * Perform all security checks
     * @return SecurityResult.OK if all checks pass, SecurityResult.BLOCKED otherwise
     */
    fun checkEnvironment(context: Context): SecurityResult {
        val checks = listOf(
            { checkSuBinary() },
            { checkMagiskArtifacts() },
            { checkRootPackages(context) },
            { checkDebuggable(context) },
            { checkDebuggerAttached() },
            { checkTracerPid() },
            { checkHookingLibraries() },
            { checkFridaArtifacts() },
            { checkAdbDisabled(context) },
            { checkNotEmulator() },
            { checkBootloaderLocked() },
            { checkInstallSource(context) },
            { checkSignatureValid(context) },
            { checkTestKeys() },
            { checkBuildTags() }
        )
        
        for (check in checks) {
            if (!check()) {
                return SecurityResult.BLOCKED
            }
        }
        
        return SecurityResult.OK
    }
    
    /**
     * Check for su binary in common paths
     * @return true if safe (no su found), false if compromised
     */
    private fun checkSuBinary(): Boolean {
        for (path in SU_PATHS) {
            if (File(path).exists()) {
                return false
            }
        }
        
        // Also check PATH
        val pathEnv = System.getenv("PATH") ?: return true
        for (pathDir in pathEnv.split(":")) {
            val suFile = File(pathDir, "su")
            if (suFile.exists()) {
                return false
            }
        }
        
        return true
    }
    
    /**
     * Check for Magisk artifacts
     * @return true if safe, false if Magisk detected
     */
    private fun checkMagiskArtifacts(): Boolean {
        for (path in MAGISK_PATHS) {
            if (File(path).exists()) {
                return false
            }
        }
        return true
    }
    
    /**
     * Check for root-related packages
     * @return true if safe, false if root packages found
     */
    private fun checkRootPackages(context: Context): Boolean {
        val pm = context.packageManager
        for (pkg in DANGEROUS_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0)
                return false // Package found
            } catch (e: Exception) {
                // Package not found, continue
            }
        }
        return true
    }
    
    /**
     * Check if app is debuggable
     * @return true if safe (not debuggable), false if debuggable
     */
    private fun checkDebuggable(context: Context): Boolean {
        return (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) == 0
    }
    
    /**
     * Check if debugger is attached
     * @return true if safe (no debugger), false if debugger attached
     */
    private fun checkDebuggerAttached(): Boolean {
        return !Debug.isDebuggerConnected() && !Debug.waitingForDebugger()
    }

    /**
     * Check if the process is being traced (syscall anti-debug)
     */
    private fun checkTracerPid(): Boolean {
        try {
            BufferedReader(FileReader("/proc/self/status")).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    if (line!!.startsWith("TracerPid:")) {
                        val parts = line!!.split("\t")
                        if (parts.size >= 2) {
                            val tracerPid = parts[1].trim().toIntOrNull() ?: 0
                            return tracerPid == 0
                        }
                    }
                }
            }
        } catch (e: Exception) {
            // If we can't read status, assume safe
        }
        return true
    }
    
    /**
     * Check for hooking libraries in /proc/self/maps
     * @return true if safe, false if hooking libraries found
     */
    private fun checkHookingLibraries(): Boolean {
        try {
            val mapsFile = File("/proc/self/maps")
            if (!mapsFile.exists()) {
                return true
            }
            
            BufferedReader(FileReader(mapsFile)).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val lowerLine = line!!.lowercase()
                    for (lib in HOOKING_LIBRARIES) {
                        if (lowerLine.contains(lib)) {
                            return false
                        }
                    }
                }
            }
        } catch (e: Exception) {
            // If we can't read maps, assume safe
        }
        return true
    }

    /**
     * Check for Frida server artifacts
     */
    private fun checkFridaArtifacts(): Boolean {
        for (path in FRIDA_PATHS) {
            if (File(path).exists()) {
                return false
            }
        }
        return true
    }

    /**
     * Check if ADB/USB debugging is disabled
     */
    private fun checkAdbDisabled(context: Context): Boolean {
        return try {
            val resolver = context.contentResolver
            val adb = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                Settings.Global.getInt(resolver, Settings.Global.ADB_ENABLED, 0)
            } else {
                Settings.Secure.getInt(resolver, Settings.Secure.ADB_ENABLED, 0)
            }
            adb == 0
        } catch (e: Exception) {
            true
        }
    }

    /**
     * Detect emulator via build fingerprints and hardware identifiers
     */
    private fun checkNotEmulator(): Boolean {
        val fingerprint = Build.FINGERPRINT.lowercase()
        val model = Build.MODEL.lowercase()
        val brand = Build.BRAND.lowercase()
        val device = Build.DEVICE.lowercase()
        val product = Build.PRODUCT.lowercase()
        val manufacturer = Build.MANUFACTURER.lowercase()
        val hardware = Build.HARDWARE.lowercase()

        if (fingerprint.startsWith("generic") || fingerprint.contains("vbox") || fingerprint.contains("test-keys")) {
            return false
        }
        if (model.contains("google_sdk") || model.contains("emulator") || model.contains("android sdk")) {
            return false
        }
        if (manufacturer.contains("genymotion") || hardware.contains("goldfish") || hardware.contains("ranchu")) {
            return false
        }
        if (brand.startsWith("generic") && device.startsWith("generic")) {
            return false
        }
        if (product.contains("sdk") || product.contains("emulator") || product.contains("simulator")) {
            return false
        }
        return true
    }

    /**
     * Check bootloader lock state (best effort)
     */
    private fun checkBootloaderLocked(): Boolean {
        val vbmeta = getSystemProperty("ro.boot.vbmeta.device_state")
        val verified = getSystemProperty("ro.boot.verifiedbootstate")
        val flashLocked = getSystemProperty("ro.boot.flash.locked")

        if (vbmeta == "unlocked" || verified == "orange" || verified == "yellow" || flashLocked == "0") {
            return false
        }
        return true
    }

    /**
     * Detect install source (block adb shell installs)
     */
    private fun checkInstallSource(context: Context): Boolean {
        return try {
            val pm = context.packageManager
            val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(context.packageName).installingPackageName
            } else {
                pm.getInstallerPackageName(context.packageName)
            }
            if (installer == null) {
                true
            } else {
                !BLOCKED_INSTALLERS.contains(installer)
            }
        } catch (e: Exception) {
            true
        }
    }

    /**
     * Verify app signing certificate (optional allowlist)
     */
    private fun checkSignatureValid(context: Context): Boolean {
        val expected = BuildConfig.EXPECTED_SIGNATURES
            .split(",")
            .map { it.trim().uppercase() }
            .filter { it.isNotEmpty() }
        if (expected.isEmpty()) return true

        return try {
            val pm = context.packageManager
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                val signingInfo = info.signingInfo ?: return false
                signingInfo.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                info.signatures ?: emptyArray()
            }

            if (signatures.isEmpty()) return false

            signatures.any { sig ->
                val digest = MessageDigest.getInstance("SHA-256").digest(sig.toByteArray())
                val hex = digest.joinToString("") { "%02X".format(it) }
                expected.contains(hex)
            }
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Check for test-keys in build
     * @return true if safe, false if test-keys found
     */
    private fun checkTestKeys(): Boolean {
        val buildTags = Build.TAGS ?: return true
        return !buildTags.contains("test-keys")
    }
    
    /**
     * Check build tags for development indicators
     * @return true if safe, false if dev build detected
     */
    private fun checkBuildTags(): Boolean {
        val buildTags = Build.TAGS ?: return true
        return !buildTags.contains("dev-keys")
    }

    private fun getSystemProperty(key: String): String? {
        return try {
            val clazz = Class.forName("android.os.SystemProperties")
            val get = clazz.getMethod("get", String::class.java)
            get.invoke(null, key) as? String
        } catch (e: Exception) {
            null
        }
    }
}
