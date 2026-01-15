/**
 * NoLeak Vault Engine
 * Core cryptographic operations and container management
 *
 * Security: All operations use libsodium for cryptography
 * - XChaCha20-Poly1305 for AEAD
 * - Argon2id for KDF
 * - Secure memory handling
 */

#ifndef VAULT_ENGINE_H
#define VAULT_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Constants
#define VAULT_MAGIC "VAULTv1"
#define VAULT_MAGIC_LEN 8
#define VAULT_VERSION 1

#define VAULT_KEY_LEN 32
#define VAULT_SALT_LEN 16
#define VAULT_NONCE_LEN 24
#define VAULT_TAG_LEN 16
#define VAULT_ID_LEN 16
#define VAULT_HASH_LEN 32 // SHA256 hash length

// KDF Profiles for different device capabilities
// Profile 0: High-end (4GB+ RAM) - Maximum security
#define VAULT_KDF_MEM_HIGH (256 * 1024 * 1024) // 256 MB
#define VAULT_KDF_ITER_HIGH 12
#define VAULT_KDF_PARALLEL_HIGH 2

// Profile 1: Medium (2-4GB RAM) - Good balance
#define VAULT_KDF_MEM_MEDIUM (128 * 1024 * 1024) // 128 MB
#define VAULT_KDF_ITER_MEDIUM 10
#define VAULT_KDF_PARALLEL_MEDIUM 2

// Profile 2: Low-end (<2GB RAM) - Lighter for weak devices
#define VAULT_KDF_MEM_LOW (32 * 1024 * 1024) // 32 MB
#define VAULT_KDF_ITER_LOW 3
#define VAULT_KDF_PARALLEL_LOW 1

// Default values (will be overridden by adaptive selection)
#define VAULT_KDF_MEM VAULT_KDF_MEM_HIGH
#define VAULT_KDF_ITER VAULT_KDF_ITER_HIGH
#define VAULT_KDF_PARALLEL VAULT_KDF_PARALLEL_HIGH

// KDF profile selection (set by vault_set_kdf_profile)
typedef enum {
  KDF_PROFILE_AUTO = 0, // Auto-detect based on device RAM
  KDF_PROFILE_HIGH = 1,
  KDF_PROFILE_MEDIUM = 2,
  KDF_PROFILE_LOW = 3
} vault_kdf_profile_t;

#define VAULT_CHUNK_SIZE (1024 * 1024) // 1 MB

// File types
#define VAULT_FILE_TYPE_TXT 1
#define VAULT_FILE_TYPE_IMG 2
#define VAULT_FILE_TYPE_VIDEO 3

// Error codes
#define VAULT_OK 0
#define VAULT_ERR_INVALID_PARAM -1
#define VAULT_ERR_MEMORY -2
#define VAULT_ERR_IO -3
#define VAULT_ERR_CRYPTO -4
#define VAULT_ERR_AUTH_FAIL -5
#define VAULT_ERR_CORRUPTED -6
#define VAULT_ERR_NOT_FOUND -7
#define VAULT_ERR_ALREADY_EXISTS -8
#define VAULT_ERR_NOT_OPEN -9
#define VAULT_ERR_PASSPHRASE_TOO_SHORT -10

// Minimum passphrase length
#define VAULT_MIN_PASSPHRASE_LEN 12

// AAD structure for AEAD operations
typedef struct {
  uint8_t vault_id[VAULT_ID_LEN];
  uint8_t file_id[VAULT_ID_LEN];
  uint32_t chunk_index;
  uint32_t format_version;
} vault_aad_t;

// File entry in index
typedef struct {
  uint8_t file_id[VAULT_ID_LEN];
  uint8_t type;
  uint64_t created_at;
  char *name;
  char *mime;
  uint64_t size;
  uint8_t *wrapped_dek;
  uint16_t wrapped_dek_len;

  // Data layout
  uint64_t data_offset;
  uint64_t data_length;

  // For video: chunk info
  uint32_t chunk_count;
  struct {
    uint64_t offset;
    uint32_t length;
    uint8_t nonce[VAULT_NONCE_LEN];
  } *chunks;
} vault_entry_t;

// Vault state
typedef struct {
  int is_open;
  char *path;
  uint8_t vault_id[VAULT_ID_LEN];
  uint8_t master_key[VAULT_KEY_LEN];
  uint8_t salt[VAULT_SALT_LEN];
  uint32_t kdf_mem;
  uint32_t kdf_iter;
  uint32_t kdf_parallel;

  // Index
  uint32_t entry_count;
  vault_entry_t *entries;

  // Free space tracking
  uint64_t total_size;
  uint64_t free_space;

  // Wrapped master key (stored from header for rewrites)
  uint8_t wrapped_mk[VAULT_NONCE_LEN + VAULT_KEY_LEN + VAULT_TAG_LEN];
  size_t wrapped_mk_len;
} vault_state_t;

// Payload holder for writing container data
typedef struct {
  // For text/image entries: nonce + ciphertext blob
  uint8_t *data;
  size_t data_len;

  // For video entries: per-chunk ciphertext
  uint8_t **chunks;
  size_t *chunk_lens;
  uint32_t chunk_count;
} vault_payload_t;

// Global vault state (lifetime controlled by vault_open/close)
extern vault_state_t g_vault;

// ============================================================================
// Core Crypto Functions
// ============================================================================

/**
 * Initialize the vault engine (must be called first)
 * @return VAULT_OK on success
 */
int vault_init(void);

/**
 * Set KDF profile based on device capabilities
 * SECURITY: Called once at init with device RAM size
 * @param total_ram_mb Device total RAM in megabytes
 */
void vault_set_kdf_profile_by_ram(size_t total_ram_mb);

/**
 * Get current KDF parameters (for debugging/logging)
 * @param mem_out Output: memory limit
 * @param iter_out Output: iteration count
 * @param parallel_out Output: parallelism
 */
void vault_get_kdf_params(size_t *mem_out, uint32_t *iter_out,
                          uint32_t *parallel_out);

/**
 * Derive key from passphrase using Argon2id
 * Uses global adaptive parameters (for vault creation)
 * @param passphrase User passphrase
 * @param pass_len Length of passphrase
 * @param salt 16-byte salt
 * @param key_out Output 32-byte key
 * @return VAULT_OK on success
 */
int vault_kdf_derive(const uint8_t *passphrase, size_t pass_len,
                     const uint8_t salt[VAULT_SALT_LEN],
                     uint8_t key_out[VAULT_KEY_LEN]);

/**
 * Derive key from passphrase with explicit KDF parameters
 * Used for opening existing vaults with stored params
 * @param passphrase User passphrase
 * @param pass_len Length of passphrase
 * @param salt 16-byte salt
 * @param mem_limit Memory limit in bytes
 * @param iterations Number of iterations
 * @param key_out Output 32-byte key
 * @return VAULT_OK on success
 */
int vault_kdf_derive_with_params(const uint8_t *passphrase, size_t pass_len,
                                 const uint8_t salt[VAULT_SALT_LEN],
                                 uint32_t mem_limit, uint32_t iterations,
                                 uint8_t key_out[VAULT_KEY_LEN]);

/**
 * AEAD encrypt using XChaCha20-Poly1305
 * @param key 32-byte key
 * @param nonce 24-byte nonce (will be generated if NULL)
 * @param aad Additional authenticated data
 * @param aad_len Length of AAD
 * @param plaintext Input plaintext
 * @param pt_len Length of plaintext
 * @param ciphertext Output buffer (must be pt_len + VAULT_TAG_LEN)
 * @param nonce_out Output nonce (24 bytes, can be same as nonce if provided)
 * @return VAULT_OK on success
 */
int vault_aead_encrypt(const uint8_t key[VAULT_KEY_LEN], const uint8_t *nonce,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *plaintext, size_t pt_len,
                       uint8_t *ciphertext, uint8_t nonce_out[VAULT_NONCE_LEN]);

/**
 * AEAD decrypt using XChaCha20-Poly1305
 * @param key 32-byte key
 * @param nonce 24-byte nonce
 * @param aad Additional authenticated data
 * @param aad_len Length of AAD
 * @param ciphertext Input ciphertext (includes tag)
 * @param ct_len Length of ciphertext
 * @param plaintext Output buffer (must be ct_len - VAULT_TAG_LEN)
 * @param pt_len_out Output plaintext length
 * @return VAULT_OK on success, VAULT_ERR_AUTH_FAIL if authentication fails
 */
int vault_aead_decrypt(const uint8_t key[VAULT_KEY_LEN],
                       const uint8_t nonce[VAULT_NONCE_LEN], const uint8_t *aad,
                       size_t aad_len, const uint8_t *ciphertext, size_t ct_len,
                       uint8_t *plaintext, size_t *pt_len_out);

/**
 * Securely zero memory
 * @param ptr Pointer to memory
 * @param len Length to zero
 */
void vault_zeroize(void *ptr, size_t len);

/**
 * Compute SHA256 hash of data
 * @param data Input data
 * @param len Length of data
 * @param hash_out Output hash (32 bytes)
 * @return VAULT_OK on success
 */
int vault_compute_hash(const uint8_t *data, size_t len,
                       uint8_t hash_out[VAULT_HASH_LEN]);

/**
 * Compute SHA256 hash of file (excluding last 32 bytes)
 * @param fd File descriptor
 * @param file_size Total file size
 * @param hash_out Output hash (32 bytes)
 * @return VAULT_OK on success
 */
int vault_compute_file_hash(int fd, size_t file_size,
                            uint8_t hash_out[VAULT_HASH_LEN]);

/**
 * Secure wipe memory with random data then zero
 * @param ptr Pointer to memory
 * @param len Length to wipe
 */
void vault_secure_wipe(void *ptr, size_t len);

/**
 * Secure wipe file contents before deletion
 * @param path Path to file
 * @return VAULT_OK on success
 */
int vault_secure_wipe_file(const char *path);

// ============================================================================
// Container Operations
// ============================================================================

/**
 * Create a new vault
 * @param path Path to vault file
 * @param passphrase User passphrase
 * @param pass_len Length of passphrase
 * @return VAULT_OK on success
 */
int vault_create(const char *path, const uint8_t *passphrase, size_t pass_len);

/**
 * Open an existing vault
 * @param path Path to vault file
 * @param passphrase User passphrase
 * @param pass_len Length of passphrase
 * @return VAULT_OK on success, VAULT_ERR_AUTH_FAIL if wrong passphrase
 */
int vault_open(const char *path, const uint8_t *passphrase, size_t pass_len);

/**
 * Close the vault and zeroize all keys
 */
void vault_close(void);

/**
 * Cleanup and destroy vault engine
 * SECURITY: Unlocks protected memory regions
 * Call on application exit
 */
void vault_cleanup(void);

/**
 * Check if vault is open
 * @return 1 if open, 0 if closed
 */
int vault_is_open(void);

// ============================================================================
// File Operations
// ============================================================================

/**
 * Import a file into the vault
 * @param data File data
 * @param len Length of data
 * @param type File type (VAULT_FILE_TYPE_*)
 * @param name Original filename
 * @param mime MIME type
 * @param file_id_out Output file ID (16 bytes)
 * @return VAULT_OK on success
 */
int vault_import_file(const uint8_t *data, size_t len, uint8_t type,
                      const char *name, const char *mime,
                      uint8_t file_id_out[VAULT_ID_LEN]);

/**
 * Read a file from the vault
 * @param file_id File ID
 * @param data_out Output data (caller must free with vault_free)
 * @param len_out Output length
 * @return VAULT_OK on success
 */
int vault_read_file(const uint8_t file_id[VAULT_ID_LEN], uint8_t **data_out,
                    size_t *len_out);

/**
 * Read a video chunk from the vault
 * @param file_id File ID
 * @param chunk_idx Chunk index
 * @param data_out Output data (caller must free with vault_free)
 * @param len_out Output length
 * @return VAULT_OK on success
 */
int vault_read_chunk(const uint8_t file_id[VAULT_ID_LEN], uint32_t chunk_idx,
                     uint8_t **data_out, size_t *len_out);

/**
 * Delete a file from the vault
 * @param file_id File ID
 * @return VAULT_OK on success
 */
int vault_delete_file(const uint8_t file_id[VAULT_ID_LEN]);

/**
 * Rename a file in the vault
 * @param file_id File ID
 * @param new_name New file name
 * @return VAULT_OK on success
 */
int vault_rename_file(const uint8_t file_id[VAULT_ID_LEN],
                      const char *new_name);

/**
 * Get list of files in vault
 * @param entries_out Output array (caller must free)
 * @param count_out Output count
 * @return VAULT_OK on success
 */
int vault_list_files(vault_entry_t **entries_out, uint32_t *count_out);

/**
 * Compact the vault (remove free space)
 * @return VAULT_OK on success
 */
int vault_compact(void);

/**
 * Change vault password
 * @param old_passphrase Current passphrase
 * @param old_pass_len Length of current passphrase
 * @param new_passphrase New passphrase
 * @param new_pass_len Length of new passphrase
 * @return VAULT_OK on success, VAULT_ERR_AUTH_FAIL if wrong current passphrase
 */
int vault_change_password(const uint8_t *old_passphrase, size_t old_pass_len,
                          const uint8_t *new_passphrase, size_t new_pass_len);

/**
 * Get vault statistics
 * @param total_size_out Total container size
 * @param free_space_out Free space from deleted files
 * @return VAULT_OK on success
 */
int vault_get_stats(uint64_t *total_size_out, uint64_t *free_space_out);

// ============================================================================
// Performance Optimization Functions
// ============================================================================

/**
 * Save only the index section without touching data blobs.
 * Used for metadata-only changes (rename, soft delete) - O(1) operation.
 *
 * SECURITY:
 * - Data blobs remain encrypted at their current offsets
 * - Integrity hash is recalculated
 * - Uses temp file + atomic rename for crash safety
 *
 * @return VAULT_OK on success
 */
int vault_save_index_only(void);

/**
 * Append a new entry to the vault without rebuilding entire container.
 * Appends encrypted payload at end of file and updates index only.
 *
 * SECURITY:
 * - New payload is encrypted before write
 * - Existing data blobs remain untouched
 * - Integrity hash is recalculated
 * - Uses temp file + atomic rename for crash safety
 *
 * @param new_entry Entry metadata (will be copied, caller retains ownership)
 * @param payload Encrypted payload data to append
 * @return VAULT_OK on success
 */
int vault_append_entry(const vault_entry_t *new_entry,
                       const vault_payload_t *payload);

// ============================================================================
// Memory Management
// ============================================================================

/**
 * Free memory allocated by vault functions
 * @param ptr Pointer to free
 */
void vault_free(void *ptr);

/**
 * Free a vault entry
 * @param entry Entry to free
 */
void vault_free_entry(vault_entry_t *entry);

/**
 * Rewrite the container file with provided entries and payloads.
 * @param entries Mutable entries array (offsets updated during write)
 * @param payloads Ciphertext payloads for each entry (nonce+ct for files,
 * per-chunk ct for video)
 * @param entry_count Number of entries
 */
int vault_save_container(vault_entry_t *entries,
                         const vault_payload_t *payloads, uint32_t entry_count);

#ifdef __cplusplus
}
#endif

#endif // VAULT_ENGINE_H
