/**
 * NoLeak Vault Engine - Streaming Import JNI Bridge
 * 
 * Exposes streaming import functions to Kotlin/Java
 */

#include "vault_streaming.h"
#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>

#define LOG_TAG "VaultStreamingJNI"

#if defined(NDEBUG) || !VAULT_DEBUG_LOGS
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif
#define UNUSED(x) (void)(x)

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
    if (!data || len == 0) return NULL;
    jbyteArray array = (*env)->NewByteArray(env, len);
    if (!array) return NULL;
    (*env)->SetByteArrayRegion(env, array, 0, len, (const jbyte*)data);
    return array;
}

// Helper: Convert Java string to C string
static char* jstring_to_cstring(JNIEnv* env, jstring str) {
    if (!str) return NULL;
    const char* utf = (*env)->GetStringUTFChars(env, str, NULL);
    if (!utf) return NULL;
    char* result = strdup(utf);
    (*env)->ReleaseStringUTFChars(env, str, utf);
    return result;
}


// ============================================================================
// Streaming JNI Functions
// ============================================================================

JNIEXPORT jint JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingInit(JNIEnv* env, jclass clazz) {
    UNUSED(env);
    UNUSED(clazz);
    return streaming_init();
}

JNIEXPORT jbyteArray JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingComputeSourceHash(
    JNIEnv* env, jclass clazz,
    jbyteArray firstMb,
    jbyteArray lastMb,
    jlong fileSize
) {
    UNUSED(clazz);
    
    size_t first_len, last_len;
    uint8_t* first = jbytearray_to_uint8(env, firstMb, &first_len);
    uint8_t* last = jbytearray_to_uint8(env, lastMb, &last_len);
    
    if (!first) {
        if (last) free(last);
        return NULL;
    }
    
    uint8_t hash[VAULT_HASH_LEN];
    int result = streaming_compute_source_hash(first, first_len, last, last_len, 
                                                (uint64_t)fileSize, hash);
    
    free(first);
    if (last) free(last);
    
    if (result != STREAMING_OK) return NULL;
    return uint8_to_jbytearray(env, hash, VAULT_HASH_LEN);
}

JNIEXPORT jobject JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingStart(
    JNIEnv* env, jclass clazz,
    jstring sourceUri,
    jbyteArray sourceHash,
    jstring name,
    jstring mime,
    jint type,
    jlong fileSize
) {
    UNUSED(clazz);
    
    char* c_uri = jstring_to_cstring(env, sourceUri);
    char* c_name = jstring_to_cstring(env, name);
    char* c_mime = jstring_to_cstring(env, mime);
    
    size_t hash_len;
    uint8_t* c_hash = jbytearray_to_uint8(env, sourceHash, &hash_len);
    
    if (!c_uri || !c_name || !c_hash || hash_len != VAULT_HASH_LEN) {
        if (c_uri) free(c_uri);
        if (c_name) free(c_name);
        if (c_mime) free(c_mime);
        if (c_hash) free(c_hash);
        return NULL;
    }
    
    uint8_t import_id[VAULT_ID_LEN];
    uint32_t resume_from = 0;
    
    int result = streaming_start(c_uri, c_hash, c_name, c_mime, (uint8_t)type,
                                  (uint64_t)fileSize, import_id, &resume_from);
    
    free(c_uri);
    free(c_name);
    if (c_mime) free(c_mime);
    free(c_hash);
    
    if (result != STREAMING_OK) {
        LOGE("streaming_start failed: %d", result);
        return NULL;
    }
    
    // Create result object with importId and resumeFromChunk
    jclass resultClass = (*env)->FindClass(env, "com/noleak/noleak/vault/StreamingStartResult");
    if (!resultClass) return NULL;
    
    jmethodID constructor = (*env)->GetMethodID(env, resultClass, "<init>", "([BI)V");
    if (!constructor) return NULL;
    
    jbyteArray importIdArray = uint8_to_jbytearray(env, import_id, VAULT_ID_LEN);
    return (*env)->NewObject(env, resultClass, constructor, importIdArray, (jint)resume_from);
}


JNIEXPORT jint JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingWriteChunk(
    JNIEnv* env, jclass clazz,
    jbyteArray importId,
    jbyteArray plaintext,
    jint chunkIndex
) {
    UNUSED(clazz);
    
    size_t id_len, pt_len;
    uint8_t* c_id = jbytearray_to_uint8(env, importId, &id_len);
    uint8_t* c_pt = jbytearray_to_uint8(env, plaintext, &pt_len);
    
    if (!c_id || id_len != VAULT_ID_LEN || !c_pt) {
        if (c_id) free(c_id);
        if (c_pt) {
            vault_zeroize(c_pt, pt_len);
            free(c_pt);
        }
        return STREAMING_ERR_INVALID_PARAM;
    }
    
    // Note: streaming_write_chunk will zeroize c_pt
    int result = streaming_write_chunk(c_id, c_pt, pt_len, (uint32_t)chunkIndex);
    
    free(c_id);
    // c_pt already freed/zeroized by streaming_write_chunk
    
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingFinish(
    JNIEnv* env, jclass clazz,
    jbyteArray importId
) {
    UNUSED(clazz);
    
    size_t id_len;
    uint8_t* c_id = jbytearray_to_uint8(env, importId, &id_len);
    
    if (!c_id || id_len != VAULT_ID_LEN) {
        if (c_id) free(c_id);
        return NULL;
    }
    
    uint8_t file_id[VAULT_ID_LEN];
    int result = streaming_finish(c_id, file_id);
    
    free(c_id);
    
    if (result != STREAMING_OK) {
        LOGE("streaming_finish failed: %d", result);
        return NULL;
    }
    
    return uint8_to_jbytearray(env, file_id, VAULT_ID_LEN);
}

JNIEXPORT jint JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingAbort(
    JNIEnv* env, jclass clazz,
    jbyteArray importId
) {
    UNUSED(clazz);
    
    size_t id_len;
    uint8_t* c_id = jbytearray_to_uint8(env, importId, &id_len);
    
    if (!c_id || id_len != VAULT_ID_LEN) {
        if (c_id) free(c_id);
        return STREAMING_ERR_INVALID_PARAM;
    }
    
    int result = streaming_abort(c_id);
    free(c_id);
    return result;
}

JNIEXPORT jobject JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingGetState(
    JNIEnv* env, jclass clazz,
    jbyteArray importId
) {
    UNUSED(clazz);
    
    size_t id_len;
    uint8_t* c_id = jbytearray_to_uint8(env, importId, &id_len);
    
    if (!c_id || id_len != VAULT_ID_LEN) {
        if (c_id) free(c_id);
        return NULL;
    }
    
    streaming_import_state_t state;
    int result = streaming_get_state(c_id, &state);
    free(c_id);
    
    if (result != STREAMING_OK) return NULL;
    
    // Create StreamingImportState object
    jclass stateClass = (*env)->FindClass(env, "com/noleak/noleak/vault/StreamingImportState");
    if (!stateClass) {
        streaming_free_state(&state);
        return NULL;
    }
    
    jmethodID constructor = (*env)->GetMethodID(env, stateClass, "<init>", 
        "([B[BLjava/lang/String;Ljava/lang/String;Ljava/lang/String;IJIIIJJ)V");
    if (!constructor) {
        streaming_free_state(&state);
        return NULL;
    }
    
    jbyteArray jImportId = uint8_to_jbytearray(env, state.import_id, VAULT_ID_LEN);
    jbyteArray jFileId = uint8_to_jbytearray(env, state.file_id, VAULT_ID_LEN);
    jstring jFileName = state.file_name ? (*env)->NewStringUTF(env, state.file_name) : NULL;
    jstring jMimeType = state.mime_type ? (*env)->NewStringUTF(env, state.mime_type) : NULL;
    jstring jSourceUri = state.source_uri ? (*env)->NewStringUTF(env, state.source_uri) : NULL;
    
    jobject jState = (*env)->NewObject(env, stateClass, constructor,
        jImportId, jFileId, jFileName, jMimeType, jSourceUri,
        (jint)state.file_type, (jlong)state.file_size,
        (jint)state.total_chunks, (jint)state.completed_chunks,
        (jint)state.chunk_size, (jlong)state.created_at, (jlong)state.updated_at);
    
    streaming_free_state(&state);
    return jState;
}


JNIEXPORT jobjectArray JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingListPending(
    JNIEnv* env, jclass clazz
) {
    UNUSED(clazz);
    
    streaming_import_state_t* states = NULL;
    uint32_t count = 0;
    
    int result = streaming_list_pending(&states, &count);
    if (result != STREAMING_OK || count == 0) {
        if (states) free(states);
        return NULL;
    }
    
    jclass stateClass = (*env)->FindClass(env, "com/noleak/noleak/vault/StreamingImportState");
    if (!stateClass) {
        for (uint32_t i = 0; i < count; i++) streaming_free_state(&states[i]);
        free(states);
        return NULL;
    }
    
    jobjectArray array = (*env)->NewObjectArray(env, count, stateClass, NULL);
    if (!array) {
        for (uint32_t i = 0; i < count; i++) streaming_free_state(&states[i]);
        free(states);
        return NULL;
    }
    
    jmethodID constructor = (*env)->GetMethodID(env, stateClass, "<init>", 
        "([B[BLjava/lang/String;Ljava/lang/String;Ljava/lang/String;IJIIIJJ)V");
    
    for (uint32_t i = 0; i < count; i++) {
        streaming_import_state_t* s = &states[i];
        
        jbyteArray jImportId = uint8_to_jbytearray(env, s->import_id, VAULT_ID_LEN);
        jbyteArray jFileId = uint8_to_jbytearray(env, s->file_id, VAULT_ID_LEN);
        jstring jFileName = s->file_name ? (*env)->NewStringUTF(env, s->file_name) : NULL;
        jstring jMimeType = s->mime_type ? (*env)->NewStringUTF(env, s->mime_type) : NULL;
        jstring jSourceUri = s->source_uri ? (*env)->NewStringUTF(env, s->source_uri) : NULL;
        
        jobject jState = (*env)->NewObject(env, stateClass, constructor,
            jImportId, jFileId, jFileName, jMimeType, jSourceUri,
            (jint)s->file_type, (jlong)s->file_size,
            (jint)s->total_chunks, (jint)s->completed_chunks,
            (jint)s->chunk_size, (jlong)s->created_at, (jlong)s->updated_at);
        
        (*env)->SetObjectArrayElement(env, array, i, jState);
        streaming_free_state(s);
    }
    
    free(states);
    return array;
}

JNIEXPORT jint JNICALL
Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingCleanupOld(
    JNIEnv* env, jclass clazz,
    jlong maxAgeMs
) {
    UNUSED(env);
    UNUSED(clazz);
    return streaming_cleanup_old((uint64_t)maxAgeMs);
}

// Register streaming native methods
static JNINativeMethod gStreamingMethods[] = {
    {"nativeStreamingInit", "()I", 
        (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingInit},
    {"nativeStreamingComputeSourceHash", "([B[BJ)[B", 
        (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingComputeSourceHash},
    {"nativeStreamingStart", "(Ljava/lang/String;[BLjava/lang/String;Ljava/lang/String;IJ)Lcom/noleak/noleak/vault/StreamingStartResult;", 
        (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingStart},
    {"nativeStreamingWriteChunk", "([B[BI)I", 
        (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingWriteChunk},
    {"nativeStreamingFinish", "([B)[B", 
        (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingFinish},
    {"nativeStreamingAbort", "([B)I", 
        (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingAbort},
    {"nativeStreamingGetState", "([B)Lcom/noleak/noleak/vault/StreamingImportState;", 
        (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingGetState},
    {"nativeStreamingListPending", "()[Lcom/noleak/noleak/vault/StreamingImportState;", 
        (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingListPending},
    {"nativeStreamingCleanupOld", "(J)I", 
        (void*)Java_com_noleak_noleak_vault_VaultEngine_nativeStreamingCleanupOld},
};

// Called from main JNI_OnLoad to register streaming methods
int register_streaming_natives(JNIEnv* env) {
    jclass clazz = (*env)->FindClass(env, "com/noleak/noleak/vault/VaultEngine");
    if (!clazz) {
        LOGE("Failed to find VaultEngine class for streaming");
        return -1;
    }
    
    if ((*env)->RegisterNatives(env, clazz, gStreamingMethods, 
            sizeof(gStreamingMethods) / sizeof(gStreamingMethods[0])) < 0) {
        LOGE("Failed to register streaming native methods");
        return -1;
    }
    
    LOGI("Streaming JNI methods registered");
    return 0;
}
