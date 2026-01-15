/**
 * NoLeak Vault Engine - Cryptographic Operations
 *
 * Uses libsodium for all crypto:
 * - Argon2id for KDF
 * - XChaCha20-Poly1305 for AEAD
 */

#include "vault_engine.h"
#include <android/log.h>
#include <fcntl.h>
#include <sodium.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOG_TAG "VaultCrypto"

// SECURITY: Disable logging in release builds
#ifdef NDEBUG
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif

// Adaptive KDF parameters (set at runtime based on device)
// SECURITY: Start with LOW profile to prevent OOM, will be upgraded if device
// has enough RAM
static size_t g_kdf_mem = VAULT_KDF_MEM_LOW;
static uint32_t g_kdf_iter = VAULT_KDF_ITER_LOW;
static uint32_t g_kdf_parallel = VAULT_KDF_PARALLEL_LOW;
static int g_kdf_profile_set = 0;

void vault_set_kdf_profile_by_ram(size_t total_ram_mb) {
  if (total_ram_mb >= 4096) {
    // High-end device (4GB+ RAM)
    g_kdf_mem = VAULT_KDF_MEM_HIGH;
    g_kdf_iter = VAULT_KDF_ITER_HIGH;
    g_kdf_parallel = VAULT_KDF_PARALLEL_HIGH;
    LOGI("KDF profile: HIGH (RAM: %zu MB)", total_ram_mb);
  } else if (total_ram_mb >= 2048) {
    // Medium device (2-4GB RAM)
    g_kdf_mem = VAULT_KDF_MEM_MEDIUM;
    g_kdf_iter = VAULT_KDF_ITER_MEDIUM;
    g_kdf_parallel = VAULT_KDF_PARALLEL_MEDIUM;
    LOGI("KDF profile: MEDIUM (RAM: %zu MB)", total_ram_mb);
  } else {
    // Low-end device (<2GB RAM)
    g_kdf_mem = VAULT_KDF_MEM_LOW;
    g_kdf_iter = VAULT_KDF_ITER_LOW;
    g_kdf_parallel = VAULT_KDF_PARALLEL_LOW;
    LOGI("KDF profile: LOW (RAM: %zu MB)", total_ram_mb);
  }
  g_kdf_profile_set = 1;
}

void vault_get_kdf_params(size_t *mem_out, uint32_t *iter_out,
                          uint32_t *parallel_out) {
  if (mem_out)
    *mem_out = g_kdf_mem;
  if (iter_out)
    *iter_out = g_kdf_iter;
  if (parallel_out)
    *parallel_out = g_kdf_parallel;
}

int vault_kdf_derive(const uint8_t *passphrase, size_t pass_len,
                     const uint8_t salt[VAULT_SALT_LEN],
                     uint8_t key_out[VAULT_KEY_LEN]) {
  if (!passphrase || pass_len == 0 || !salt || !key_out) {
    return VAULT_ERR_INVALID_PARAM;
  }

  // Use Argon2id with adaptive parameters based on device capability
  // This prevents OOM on low-end devices while maintaining security
  int result = crypto_pwhash(key_out, VAULT_KEY_LEN, (const char *)passphrase,
                             pass_len, salt,
                             g_kdf_iter, // Adaptive: 3-12 iterations
                             g_kdf_mem,  // Adaptive: 32-256 MB
                             crypto_pwhash_ALG_ARGON2ID13);

  if (result != 0) {
    LOGE("Argon2id KDF failed (OOM with %zu MB)", g_kdf_mem / (1024 * 1024));

    // Fallback: Try with minimum parameters if high profile failed
    if (g_kdf_mem > VAULT_KDF_MEM_LOW) {
      LOGI("Retrying KDF with LOW profile");
      result = crypto_pwhash(key_out, VAULT_KEY_LEN, (const char *)passphrase,
                             pass_len, salt, VAULT_KDF_ITER_LOW,
                             VAULT_KDF_MEM_LOW, crypto_pwhash_ALG_ARGON2ID13);

      if (result == 0) {
        LOGI("KDF succeeded with fallback profile");
        // Update profile for future operations
        g_kdf_mem = VAULT_KDF_MEM_LOW;
        g_kdf_iter = VAULT_KDF_ITER_LOW;
        g_kdf_parallel = VAULT_KDF_PARALLEL_LOW;
        return VAULT_OK;
      }
    }

    return VAULT_ERR_MEMORY;
  }

  LOGI("KDF derived key (mem=%zuMB, iter=%u)", g_kdf_mem / (1024 * 1024),
       g_kdf_iter);
  return VAULT_OK;
}

/**
 * Derive key with explicit KDF parameters (used for opening existing vaults)
 * IMPORTANT: Use params stored in vault header, not global adaptive params
 */
int vault_kdf_derive_with_params(const uint8_t *passphrase, size_t pass_len,
                                 const uint8_t salt[VAULT_SALT_LEN],
                                 uint32_t mem_limit, uint32_t iterations,
                                 uint8_t key_out[VAULT_KEY_LEN]) {
  if (!passphrase || pass_len == 0 || !salt || !key_out) {
    return VAULT_ERR_INVALID_PARAM;
  }

  LOGI("KDF with stored params: mem=%uMB, iter=%u", mem_limit / (1024 * 1024),
       iterations);

  int result =
      crypto_pwhash(key_out, VAULT_KEY_LEN, (const char *)passphrase, pass_len,
                    salt, iterations, mem_limit, crypto_pwhash_ALG_ARGON2ID13);

  if (result != 0) {
    LOGE("Argon2id KDF failed with stored params (mem=%uMB, iter=%u)",
         mem_limit / (1024 * 1024), iterations);
    return VAULT_ERR_MEMORY;
  }

  LOGI("KDF derived key with stored params");
  return VAULT_OK;
}

int vault_aead_encrypt(const uint8_t key[VAULT_KEY_LEN], const uint8_t *nonce,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *plaintext, size_t pt_len,
                       uint8_t *ciphertext,
                       uint8_t nonce_out[VAULT_NONCE_LEN]) {
  if (!key || !plaintext || !ciphertext || !nonce_out) {
    return VAULT_ERR_INVALID_PARAM;
  }

  // Generate nonce if not provided
  if (nonce) {
    memcpy(nonce_out, nonce, VAULT_NONCE_LEN);
  } else {
    randombytes_buf(nonce_out, VAULT_NONCE_LEN);
  }

  unsigned long long ciphertext_len;

  int result = crypto_aead_xchacha20poly1305_ietf_encrypt(
      ciphertext, &ciphertext_len, plaintext, pt_len, aad, aad_len,
      NULL, // nsec (not used)
      nonce_out, key);

  if (result != 0) {
    LOGE("AEAD encryption failed");
    return VAULT_ERR_CRYPTO;
  }

  return VAULT_OK;
}

int vault_aead_decrypt(const uint8_t key[VAULT_KEY_LEN],
                       const uint8_t nonce[VAULT_NONCE_LEN], const uint8_t *aad,
                       size_t aad_len, const uint8_t *ciphertext, size_t ct_len,
                       uint8_t *plaintext, size_t *pt_len_out) {
  if (!key || !nonce || !ciphertext || !plaintext || !pt_len_out) {
    return VAULT_ERR_INVALID_PARAM;
  }

  if (ct_len < VAULT_TAG_LEN) {
    LOGE("Ciphertext too short");
    return VAULT_ERR_INVALID_PARAM;
  }

  unsigned long long plaintext_len;

  int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
      plaintext, &plaintext_len,
      NULL, // nsec (not used)
      ciphertext, ct_len, aad, aad_len, nonce, key);

  if (result != 0) {
    LOGE("AEAD decryption failed - authentication error");
    return VAULT_ERR_AUTH_FAIL;
  }

  *pt_len_out = (size_t)plaintext_len;
  return VAULT_OK;
}

// Helper: Generate random bytes
void vault_random_bytes(uint8_t *buf, size_t len) { randombytes_buf(buf, len); }

// Helper: Generate random file ID
void vault_generate_id(uint8_t id_out[VAULT_ID_LEN]) {
  randombytes_buf(id_out, VAULT_ID_LEN);
}

// Compute SHA256 hash of data
int vault_compute_hash(const uint8_t *data, size_t len,
                       uint8_t hash_out[VAULT_HASH_LEN]) {
  if (!data || !hash_out) {
    return VAULT_ERR_INVALID_PARAM;
  }

  // libsodium's crypto_hash_sha256
  if (crypto_hash_sha256(hash_out, data, len) != 0) {
    return VAULT_ERR_CRYPTO;
  }

  return VAULT_OK;
}

// Compute SHA256 hash of file (excluding last 32 bytes which is the hash
// itself)
int vault_compute_file_hash(int fd, size_t file_size,
                            uint8_t hash_out[VAULT_HASH_LEN]) {
  if (fd < 0 || file_size <= VAULT_HASH_LEN || !hash_out) {
    return VAULT_ERR_INVALID_PARAM;
  }

  // Hash everything except the last 32 bytes (the hash itself)
  size_t hash_data_len = file_size - VAULT_HASH_LEN;

  // Seek to beginning
  if (lseek(fd, 0, SEEK_SET) != 0) {
    return VAULT_ERR_IO;
  }

  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);

  uint8_t buffer[64 * 1024];
  size_t remaining = hash_data_len;

  while (remaining > 0) {
    size_t to_read = (remaining > sizeof(buffer)) ? sizeof(buffer) : remaining;
    ssize_t read_len = read(fd, buffer, to_read);
    if (read_len <= 0) {
      return VAULT_ERR_IO;
    }
    crypto_hash_sha256_update(&state, buffer, read_len);
    remaining -= read_len;
  }

  crypto_hash_sha256_final(&state, hash_out);
  return VAULT_OK;
}

// Secure overwrite memory/file with random data before deletion
void vault_secure_wipe(void *ptr, size_t len) {
  if (ptr && len > 0) {
    // Overwrite with random bytes first
    randombytes_buf(ptr, len);
    // Then zero
    sodium_memzero(ptr, len);
  }
}

// Secure wipe file contents before deletion
int vault_secure_wipe_file(const char *path) {
  if (!path)
    return VAULT_ERR_INVALID_PARAM;

  int fd = open(path, O_WRONLY);
  if (fd < 0)
    return VAULT_ERR_IO;

  struct stat st;
  if (fstat(fd, &st) != 0) {
    close(fd);
    return VAULT_ERR_IO;
  }

  size_t file_size = st.st_size;
  uint8_t buffer[64 * 1024];
  size_t remaining = file_size;

  // Overwrite with random data
  while (remaining > 0) {
    size_t to_write = (remaining > sizeof(buffer)) ? sizeof(buffer) : remaining;
    randombytes_buf(buffer, to_write);
    if (write(fd, buffer, to_write) != (ssize_t)to_write) {
      close(fd);
      return VAULT_ERR_IO;
    }
    remaining -= to_write;
  }

  // Sync to disk
  fsync(fd);
  close(fd);

  return VAULT_OK;
}
