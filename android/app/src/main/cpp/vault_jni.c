/**
 * NoLeak Vault Engine - JNI Bridge
 * 
 * Exposes vault functions to Kotlin/Java
 */

#include "vault_engine.h"
#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>

#define LOG_TAG "VaultJNI"

// SECURITY: Disable logging unless explicitly enabled
#if defined(NDEBUG) || !VAULT_DEBUG_LOGS
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif
#define UNUSED(x) (void)(x)

// JNI package name
#define JNI_PACKAGE "com/noleak/noleak/vault"

// Helper: Convert Java byte array to C array
static uint8_t* jbytearray_to_uint8(JNIEnv* env, jbyteArray array, size_t* len_out) {
    if (!array) {
        *len_out = 0;
        return NULL;
    }
    
    jsize len = (*env)->GetArrayLength(env, array);
    uint8_t* buf = malloc(len);
    if (!buf) {
        *len_out = 0;
        return NULL;
    }
    
    (*env)->GetByteArrayRegion(env, array, 0, len, (jbyte*)buf);
    *len_out = len;
    return buf;
}

// Helper: Convert C array to Java byte array
static jbyteArray uint8_to_jbytearray(JNIEnv* env, const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return NULL;
    }
    
    jbyteArray array = (*env)->NewByteArray(env, len);
    if (!array) {
        return NULL;
    }
    
    (*env)->SetByteArrayRegion(env, array, 0, len, (const jbyte*)data);
    return array;
}

// Helper: Convert Java string to C string
static char* jstring_to_cstring(JNIEnv* env, jstring str) {
    if (!str) {
        return NULL;
    }
    
    const char* utf = (*env)->GetStringUTFChars(env, str, NULL);
    if (!utf) {
        return NULL;
    }
    
    char* result = strdup(utf);
    (*env)->ReleaseStringUTFChars(env, str, utf);
    return result;
}

// ============================================================================
// JNI Functions
// ============================================================================

JNIEXPORT jint JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeInit(JNIEnv* env, jclass clazz) {
    UNUSED(env);
    UNUSED(clazz);
    return vault_init();
}

JNIEXPORT void JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeSetKdfProfile(
    JNIEnv* env, jclass clazz, jlong totalRamMb
) {
    UNUSED(env);
    UNUSED(clazz);
    vault_set_kdf_profile_by_ram((size_t)totalRamMb);
}

JNIEXPORT jint JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeCreate(
    JNIEnv* env, jclass clazz,
    jstring path,
    jbyteArray passphrase
) {
    UNUSED(clazz);
    char* c_path = jstring_to_cstring(env, path);
    if (!c_path) {
        return VAULT_ERR_INVALID_PARAM;
    }
    
    size_t pass_len;
    uint8_t* pass = jbytearray_to_uint8(env, passphrase, &pass_len);
    if (!pass) {
        free(c_path);
        return VAULT_ERR_INVALID_PARAM;
    }
    
    int result = vault_create(c_path, pass, pass_len);
    
    vault_zeroize(pass, pass_len);
    free(pass);
    free(c_path);
    
    return result;
}

JNIEXPORT jint JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeOpen(
    JNIEnv* env, jclass clazz,
    jstring path,
    jbyteArray passphrase
) {
    UNUSED(clazz);
    char* c_path = jstring_to_cstring(env, path);
    if (!c_path) {
        return VAULT_ERR_INVALID_PARAM;
    }
    
    size_t pass_len;
    uint8_t* pass = jbytearray_to_uint8(env, passphrase, &pass_len);
    if (!pass) {
        free(c_path);
        return VAULT_ERR_INVALID_PARAM;
    }
    
    int result = vault_open(c_path, pass, pass_len);
    
    vault_zeroize(pass, pass_len);
    free(pass);
    free(c_path);
    
    return result;
}

JNIEXPORT void JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeClose(JNIEnv* env, jclass clazz) {
    UNUSED(env);
    UNUSED(clazz);
    vault_close();
}

JNIEXPORT jboolean JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeIsOpen(JNIEnv* env, jclass clazz) {
    UNUSED(env);
    UNUSED(clazz);
    return vault_is_open() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeImportFile(
    JNIEnv* env, jclass clazz,
    jbyteArray data,
    jint type,
    jstring name,
    jstring mime
) {
    UNUSED(clazz);
    LOGI("nativeImportFile: starting, type=%d", type);
    
    size_t data_len;
    uint8_t* c_data = jbytearray_to_uint8(env, data, &data_len);
    if (!c_data) {
        LOGE("nativeImportFile: failed to convert data array");
        return NULL;
    }
    LOGI("nativeImportFile: data_len=%zu", data_len);
    
    char* c_name = jstring_to_cstring(env, name);
    char* c_mime = jstring_to_cstring(env, mime);
    LOGI("nativeImportFile: name=%s, mime=%s", c_name ? c_name : "null", c_mime ? c_mime : "null");
    
    uint8_t file_id[VAULT_ID_LEN];
    int result = vault_import_file(c_data, data_len, type, c_name, c_mime, file_id);
    LOGI("nativeImportFile: vault_import_file returned %d", result);
    
    // SECURITY: Zeroize plaintext data before freeing to prevent memory forensics
    vault_zeroize(c_data, data_len);
    free(c_data);
    free(c_name);
    if (c_mime) free(c_mime);
    
    if (result != VAULT_OK) {
        LOGE("nativeImportFile: import failed with error %d", result);
        return NULL;
    }
    
    LOGI("nativeImportFile: success");
    return uint8_to_jbytearray(env, file_id, VAULT_ID_LEN);
}

JNIEXPORT jbyteArray JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeReadFile(
    JNIEnv* env, jclass clazz,
    jbyteArray fileId
) {
    UNUSED(clazz);
    size_t id_len;
    uint8_t* c_id = jbytearray_to_uint8(env, fileId, &id_len);
    if (!c_id || id_len != VAULT_ID_LEN) {
        if (c_id) free(c_id);
        return NULL;
    }
    
    uint8_t* data = NULL;
    size_t data_len = 0;
    int result = vault_read_file(c_id, &data, &data_len);
    
    free(c_id);
    
    if (result != VAULT_OK || !data) {
        return NULL;
    }
    
    jbyteArray array = uint8_to_jbytearray(env, data, data_len);
    
    vault_zeroize(data, data_len);
    vault_free(data);
    
    return array;
}

JNIEXPORT jbyteArray JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeReadChunk(
    JNIEnv* env, jclass clazz,
    jbyteArray fileId,
    jint chunkIndex
) {
    UNUSED(clazz);
    size_t id_len;
    uint8_t* c_id = jbytearray_to_uint8(env, fileId, &id_len);
    if (!c_id || id_len != VAULT_ID_LEN) {
        if (c_id) free(c_id);
        return NULL;
    }
    
    uint8_t* data = NULL;
    size_t data_len = 0;
    int result = vault_read_chunk(c_id, chunkIndex, &data, &data_len);
    
    free(c_id);
    
    if (result != VAULT_OK || !data) {
        return NULL;
    }
    
    jbyteArray array = uint8_to_jbytearray(env, data, data_len);
    
    vault_zeroize(data, data_len);
    vault_free(data);
    
    return array;
}

JNIEXPORT jint JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeDeleteFile(
    JNIEnv* env, jclass clazz,
    jbyteArray fileId
) {
    UNUSED(clazz);
    size_t id_len;
    uint8_t* c_id = jbytearray_to_uint8(env, fileId, &id_len);
    if (!c_id || id_len != VAULT_ID_LEN) {
        if (c_id) free(c_id);
        return VAULT_ERR_INVALID_PARAM;
    }
    
    int result = vault_delete_file(c_id);
    free(c_id);
    
    return result;
}

JNIEXPORT jint JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeRenameFile(
    JNIEnv* env, jclass clazz,
    jbyteArray fileId,
    jstring newName
) {
    UNUSED(clazz);
    size_t id_len;
    uint8_t* c_id = jbytearray_to_uint8(env, fileId, &id_len);
    if (!c_id || id_len != VAULT_ID_LEN) {
        if (c_id) free(c_id);
        return VAULT_ERR_INVALID_PARAM;
    }

    char* c_name = jstring_to_cstring(env, newName);
    if (!c_name) {
        free(c_id);
        return VAULT_ERR_INVALID_PARAM;
    }

    int result = vault_rename_file(c_id, c_name);
    vault_zeroize(c_name, strlen(c_name));
    free(c_name);
    free(c_id);

    return result;
}

JNIEXPORT jint JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeCompact(JNIEnv* env, jclass clazz) {
    UNUSED(env);
    UNUSED(clazz);
    return vault_compact();
}

JNIEXPORT jint JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeGetEntryCount(JNIEnv* env, jclass clazz) {
    UNUSED(env);
    UNUSED(clazz);
    vault_entry_t* entries;
    uint32_t count;
    
    if (vault_list_files(&entries, &count) != VAULT_OK) {
        return 0;
    }
    
    return count;
}

JNIEXPORT jobjectArray JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeListFiles(JNIEnv* env, jclass clazz) {
    UNUSED(clazz);
    vault_entry_t* entries;
    uint32_t count;
    
    if (vault_list_files(&entries, &count) != VAULT_OK) {
        return NULL;
    }
    
    // Find VaultFileEntry class
    jclass entryClass = (*env)->FindClass(env, "com/noleak/noleak/vault/VaultFileEntry");
    if (!entryClass) {
        LOGE("Failed to find VaultFileEntry class");
        return NULL;
    }
    
    // Get constructor
    jmethodID constructor = (*env)->GetMethodID(env, entryClass, "<init>", 
        "([BLjava/lang/String;IJJLjava/lang/String;I)V");
    if (!constructor) {
        LOGE("Failed to find VaultFileEntry constructor");
        return NULL;
    }
    
    // Create array
    jobjectArray result = (*env)->NewObjectArray(env, count, entryClass, NULL);
    if (!result) {
        return NULL;
    }
    
    // Populate array
    for (uint32_t i = 0; i < count; i++) {
        vault_entry_t* entry = &entries[i];
        
        jbyteArray fileId = uint8_to_jbytearray(env, entry->file_id, VAULT_ID_LEN);
        jstring name = (*env)->NewStringUTF(env, entry->name ? entry->name : "");
        jstring mime = entry->mime ? (*env)->NewStringUTF(env, entry->mime) : NULL;
        
        jobject entryObj = (*env)->NewObject(env, entryClass, constructor,
            fileId,
            name,
            (jint)entry->type,
            (jlong)entry->size,
            (jlong)entry->created_at,
            mime,
            (jint)entry->chunk_count
        );
        
        (*env)->SetObjectArrayElement(env, result, i, entryObj);
        
        // Clean up local refs
        (*env)->DeleteLocalRef(env, fileId);
        (*env)->DeleteLocalRef(env, name);
        if (mime) (*env)->DeleteLocalRef(env, mime);
        (*env)->DeleteLocalRef(env, entryObj);
    }
    
    return result;
}

JNIEXPORT jint JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeChangePassword(
    JNIEnv* env, jclass clazz,
    jbyteArray oldPassphrase,
    jbyteArray newPassphrase
) {
    UNUSED(clazz);
    
    size_t old_pass_len, new_pass_len;
    uint8_t* old_pass = jbytearray_to_uint8(env, oldPassphrase, &old_pass_len);
    uint8_t* new_pass = jbytearray_to_uint8(env, newPassphrase, &new_pass_len);
    
    if (!old_pass || !new_pass) {
        if (old_pass) {
            vault_zeroize(old_pass, old_pass_len);
            free(old_pass);
        }
        if (new_pass) {
            vault_zeroize(new_pass, new_pass_len);
            free(new_pass);
        }
        return VAULT_ERR_INVALID_PARAM;
    }
    
    int result = vault_change_password(old_pass, old_pass_len, new_pass, new_pass_len);
    
    vault_zeroize(old_pass, old_pass_len);
    vault_zeroize(new_pass, new_pass_len);
    free(old_pass);
    free(new_pass);
    
    return result;
}

// Secure wipe file before deletion
JNIEXPORT jboolean JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeSecureWipeFile(
    JNIEnv* env, jclass clazz, jstring path
) {
    UNUSED(clazz);
    
    if (!path) {
        return JNI_FALSE;
    }
    
    const char* c_path = (*env)->GetStringUTFChars(env, path, NULL);
    if (!c_path) {
        return JNI_FALSE;
    }
    
    int result = vault_secure_wipe_file(c_path);
    
    (*env)->ReleaseStringUTFChars(env, path, c_path);
    
    return result == VAULT_OK ? JNI_TRUE : JNI_FALSE;
}

// Get device KDF parameters (based on device RAM)
JNIEXPORT jintArray JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeGetKdfInfo(JNIEnv* env, jclass clazz) {
    UNUSED(clazz);
    
    size_t mem;
    uint32_t iter, parallel;
    vault_get_kdf_params(&mem, &iter, &parallel);
    
    jintArray result = (*env)->NewIntArray(env, 3);
    if (!result) return NULL;
    
    jint values[3];
    values[0] = (jint)(mem / (1024 * 1024)); // Convert to MB
    values[1] = (jint)iter;
    values[2] = (jint)parallel;
    
    (*env)->SetIntArrayRegion(env, result, 0, 3, values);
    return result;
}

// Get vault KDF parameters (from currently open vault header)
JNIEXPORT jintArray JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeGetVaultKdfParams(JNIEnv* env, jclass clazz) {
    UNUSED(clazz);
    
    if (!vault_is_open()) {
        return NULL;
    }
    
    jintArray result = (*env)->NewIntArray(env, 3);
    if (!result) return NULL;
    
    jint values[3];
    values[0] = (jint)(g_vault.kdf_mem / (1024 * 1024)); // Convert to MB
    values[1] = (jint)g_vault.kdf_iter;
    values[2] = (jint)g_vault.kdf_parallel;
    
    (*env)->SetIntArrayRegion(env, result, 0, 3, values);
    return result;
}

// Register native methods
static JNINativeMethod gMethods[] = {
    {"nativeInit", "()I", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeInit},
    {"nativeSetKdfProfile", "(J)V", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeSetKdfProfile},
    {"nativeCreate", "(Ljava/lang/String;[B)I", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeCreate},
    {"nativeOpen", "(Ljava/lang/String;[B)I", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeOpen},
    {"nativeClose", "()V", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeClose},
    {"nativeIsOpen", "()Z", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeIsOpen},
    {"nativeImportFile", "([BILjava/lang/String;Ljava/lang/String;)[B", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeImportFile},
    {"nativeReadFile", "([B)[B", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeReadFile},
    {"nativeReadChunk", "([BI)[B", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeReadChunk},
    {"nativeDeleteFile", "([B)I", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeDeleteFile},
    {"nativeRenameFile", "([BLjava/lang/String;)I", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeRenameFile},
    {"nativeCompact", "()I", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeCompact},
    {"nativeGetEntryCount", "()I", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeGetEntryCount},
    {"nativeListFiles", "()[Lcom/noleak/noleak/vault/VaultFileEntry;", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeListFiles},
    {"nativeChangePassword", "([B[B)I", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeChangePassword},
    {"nativeSecureWipeFile", "(Ljava/lang/String;)Z", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeSecureWipeFile},
    {"nativeGetKdfInfo", "()[I", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeGetKdfInfo},
    {"nativeGetVaultKdfParams", "()[I", (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeGetVaultKdfParams},
};

// Register streaming natives (defined in vault_streaming_jni.c)
extern int register_streaming_natives(JNIEnv* env);

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    UNUSED(reserved);
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    
    jclass clazz = (*env)->FindClass(env, "com/noleak/noleak/vault/VaultEngine");
    if (!clazz) {
        LOGE("Failed to find VaultEngine class");
        return JNI_ERR;
    }
    
    if ((*env)->RegisterNatives(env, clazz, gMethods, sizeof(gMethods) / sizeof(gMethods[0])) < 0) {
        LOGE("Failed to register native methods");
        return JNI_ERR;
    }
    
    // Register streaming methods
    if (register_streaming_natives(env) < 0) {
        LOGE("Failed to register streaming native methods");
        return JNI_ERR;
    }
    
    LOGI("JNI loaded successfully");
    return JNI_VERSION_1_6;
}
