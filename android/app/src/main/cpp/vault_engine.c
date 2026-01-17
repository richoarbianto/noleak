/**
 * NoLeak Vault Engine - Main Implementation
 */

#include "vault_engine.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <android/log.h>

#define LOG_TAG "VaultEngine"

// SECURITY: Disable logging unless explicitly enabled
#if defined(NDEBUG) || !VAULT_DEBUG_LOGS
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif

// Global vault state
vault_state_t g_vault = {0};
static int g_initialized = 0;
static int g_master_key_locked = 0;

int vault_init(void) {
    if (g_initialized) {
        return VAULT_OK;
    }
    
    if (sodium_init() < 0) {
        LOGE("Failed to initialize libsodium");
        return VAULT_ERR_CRYPTO;
    }
    
    // SECURITY: Lock master key memory to prevent swap
    // This prevents the key from appearing in crash dumps or swap
    if (sodium_mlock(g_vault.master_key, VAULT_KEY_LEN) == 0) {
        g_master_key_locked = 1;
        LOGI("Master key memory locked");
    } else {
        LOGI("sodium_mlock unavailable, using standard memory");
        // Not a fatal error - mlock may fail on some devices
    }
    
    g_initialized = 1;
    LOGI("Vault engine initialized");
    return VAULT_OK;
}

void vault_zeroize(void* ptr, size_t len) {
    if (ptr && len > 0) {
        sodium_memzero(ptr, len);
    }
}

void vault_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

void vault_free_entry(vault_entry_t* entry) {
    if (!entry) return;
    
    if (entry->name) {
        vault_zeroize(entry->name, strlen(entry->name));
        free(entry->name);
    }
    if (entry->mime) {
        vault_zeroize(entry->mime, strlen(entry->mime));
        free(entry->mime);
    }
    if (entry->wrapped_dek) {
        vault_zeroize(entry->wrapped_dek, entry->wrapped_dek_len);
        free(entry->wrapped_dek);
    }
    if (entry->chunks) {
        vault_zeroize(entry->chunks, entry->chunk_count * sizeof(entry->chunks[0]));
        free(entry->chunks);
    }
}

int vault_is_open(void) {
    return g_vault.is_open;
}

void vault_close(void) {
    if (!g_vault.is_open) {
        return;
    }
    
    // SECURITY: Zeroize master key before unlocking
    vault_zeroize(g_vault.master_key, VAULT_KEY_LEN);
    vault_zeroize(g_vault.salt, VAULT_SALT_LEN);
    vault_zeroize(g_vault.vault_id, VAULT_ID_LEN);
    vault_zeroize(g_vault.wrapped_mk, sizeof(g_vault.wrapped_mk));
    g_vault.wrapped_mk_len = 0;
    g_vault.kdf_mem = 0;
    g_vault.kdf_iter = 0;
    g_vault.kdf_parallel = 0;
    
    // Note: We keep the memory locked for future use
    // Unlocking would be done on engine destruction, not vault close
    
    // Free entries
    if (g_vault.entries) {
        for (uint32_t i = 0; i < g_vault.entry_count; i++) {
            vault_free_entry(&g_vault.entries[i]);
        }
        free(g_vault.entries);
        g_vault.entries = NULL;
    }
    
    // Free path
    if (g_vault.path) {
        free(g_vault.path);
        g_vault.path = NULL;
    }
    
    g_vault.is_open = 0;
    g_vault.entry_count = 0;
    g_vault.total_size = 0;
    g_vault.free_space = 0;
    g_vault.header_size = 0;
    g_vault.header_seq = 0;
    g_vault.header_slot_size = 0;
    g_vault.header_slot_count = 0;
    g_vault.header_is_journal = 0;
    g_vault.index_capacity = 0;
    g_vault.index_is_padded = 0;
    
    LOGI("Vault closed");
}

/**
 * SECURITY: Call on engine destruction to unlock protected memory
 */
void vault_cleanup(void) {
    vault_close();
    
    if (g_master_key_locked) {
        sodium_munlock(g_vault.master_key, VAULT_KEY_LEN);
        g_master_key_locked = 0;
        LOGI("Master key memory unlocked");
    }
    
    g_initialized = 0;
}
