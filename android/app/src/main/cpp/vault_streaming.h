/**
 * NoLeak Vault Engine - Streaming Import System
 * 
 * Enables memory-efficient import of large files (up to 50GB)
 * with resume support and progress tracking.
 * 
 * SECURITY:
 * - Per-chunk encryption with unique nonces
 * - DEK wrapped with master key, stored encrypted
 * - Immediate zeroization of plaintext after encryption
 * - Secure cleanup on abort
 */

#ifndef VAULT_STREAMING_H
#define VAULT_STREAMING_H

#include "vault_engine.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Streaming import constants
#define STREAMING_CHUNK_SIZE (4 * 1024 * 1024)  // 4MB chunks
#define STREAMING_MAX_FILE_SIZE (50ULL * 1024 * 1024 * 1024)  // 50GB max
#define STREAMING_STATE_VERSION 1
#define STREAMING_HASH_SAMPLE_SIZE (1024 * 1024)  // 1MB for source hash

// Streaming import state (persisted to disk for resume)
typedef struct {
    uint8_t import_id[VAULT_ID_LEN];      // Unique import session ID
    uint8_t file_id[VAULT_ID_LEN];        // Target file ID in vault
    char* source_uri;                      // Original source URI (not persisted)
    uint8_t source_hash[VAULT_HASH_LEN];  // Hash of source file (first+last 1MB + size)
    char* file_name;                       // Original filename
    char* mime_type;                       // MIME type
    uint8_t file_type;                     // VAULT_FILE_TYPE_*
    uint64_t file_size;                    // Total file size
    uint32_t chunk_size;                   // Chunk size used
    uint32_t total_chunks;                 // Total number of chunks
    uint32_t completed_chunks;             // Number of completed chunks
    uint64_t bytes_written;                // Total bytes written
    uint64_t created_at;                   // Timestamp when import started
    uint64_t updated_at;                   // Last update timestamp
    
    // Encrypted DEK (wrapped with master key)
    uint8_t* wrapped_dek;
    uint16_t wrapped_dek_len;
    
    // Runtime state (not persisted)
    int is_active;                         // Currently being processed
    char* pending_dir;                     // Directory for pending chunks
} streaming_import_state_t;

// Streaming import result codes
#define STREAMING_OK 0
#define STREAMING_ERR_INVALID_PARAM -1
#define STREAMING_ERR_MEMORY -2
#define STREAMING_ERR_IO -3
#define STREAMING_ERR_CRYPTO -4
#define STREAMING_ERR_NOT_FOUND -5
#define STREAMING_ERR_ALREADY_EXISTS -6
#define STREAMING_ERR_SOURCE_CHANGED -7
#define STREAMING_ERR_DISK_FULL -8
#define STREAMING_ERR_VAULT_NOT_OPEN -9
#define STREAMING_ERR_CHUNK_CORRUPTED -10
#define STREAMING_ERR_FILE_TOO_LARGE -11

// Progress callback type
typedef void (*streaming_progress_callback_t)(
    const uint8_t import_id[VAULT_ID_LEN],
    uint64_t bytes_written,
    uint64_t total_bytes,
    uint32_t chunks_completed,
    uint32_t total_chunks,
    void* user_data
);

/**
 * Initialize streaming import subsystem
 * Creates pending imports directory if needed
 * @return STREAMING_OK on success
 */
int streaming_init(void);

/**
 * Start a new streaming import or resume an existing one
 * 
 * @param source_uri Source file URI (for resume verification)
 * @param source_hash Hash of source file (first+last 1MB + size)
 * @param name Original filename
 * @param mime MIME type
 * @param type File type (VAULT_FILE_TYPE_*)
 * @param file_size Total file size in bytes
 * @param import_id_out Output: import session ID (new or existing)
 * @param resume_from_chunk_out Output: chunk index to resume from (0 if new)
 * @return STREAMING_OK on success
 */
int streaming_start(
    const char* source_uri,
    const uint8_t source_hash[VAULT_HASH_LEN],
    const char* name,
    const char* mime,
    uint8_t type,
    uint64_t file_size,
    uint8_t import_id_out[VAULT_ID_LEN],
    uint32_t* resume_from_chunk_out
);

/**
 * Write a single chunk of data
 * Encrypts and writes to pending directory
 * 
 * @param import_id Import session ID
 * @param plaintext Chunk data (will be zeroized after encryption)
 * @param len Length of chunk data
 * @param chunk_index Index of this chunk
 * @return STREAMING_OK on success
 */
int streaming_write_chunk(
    const uint8_t import_id[VAULT_ID_LEN],
    uint8_t* plaintext,
    size_t len,
    uint32_t chunk_index
);

/**
 * Finalize streaming import
 * Combines chunks into vault container, updates index
 * 
 * @param import_id Import session ID
 * @param file_id_out Output: final file ID in vault
 * @return STREAMING_OK on success
 */
int streaming_finish(
    const uint8_t import_id[VAULT_ID_LEN],
    uint8_t file_id_out[VAULT_ID_LEN]
);

/**
 * Abort streaming import and cleanup
 * Securely deletes all pending chunks and state
 * 
 * @param import_id Import session ID
 * @return STREAMING_OK on success
 */
int streaming_abort(const uint8_t import_id[VAULT_ID_LEN]);

/**
 * List all pending imports
 * 
 * @param states_out Output: array of pending import states (caller must free)
 * @param count_out Output: number of pending imports
 * @return STREAMING_OK on success
 */
int streaming_list_pending(
    streaming_import_state_t** states_out,
    uint32_t* count_out
);

/**
 * Get state of a specific import
 * 
 * @param import_id Import session ID
 * @param state_out Output: import state (caller must free strings)
 * @return STREAMING_OK on success
 */
int streaming_get_state(
    const uint8_t import_id[VAULT_ID_LEN],
    streaming_import_state_t* state_out
);

/**
 * Set progress callback for an import
 * 
 * @param import_id Import session ID
 * @param callback Progress callback function
 * @param user_data User data passed to callback
 * @return STREAMING_OK on success
 */
int streaming_set_progress_callback(
    const uint8_t import_id[VAULT_ID_LEN],
    streaming_progress_callback_t callback,
    void* user_data
);

/**
 * Cleanup completed/aborted imports older than max_age_ms
 * 
 * @param max_age_ms Maximum age in milliseconds (0 = cleanup all)
 * @return Number of imports cleaned up
 */
int streaming_cleanup_old(uint64_t max_age_ms);

/**
 * Free streaming import state
 * 
 * @param state State to free
 */
void streaming_free_state(streaming_import_state_t* state);

/**
 * Compute source file hash for resume verification
 * Hash = SHA256(first 1MB || last 1MB || file_size as 8 bytes)
 * 
 * @param first_mb First 1MB of file (or entire file if smaller)
 * @param first_mb_len Length of first_mb
 * @param last_mb Last 1MB of file (or NULL if file <= 2MB)
 * @param last_mb_len Length of last_mb
 * @param file_size Total file size
 * @param hash_out Output: 32-byte hash
 * @return STREAMING_OK on success
 */
int streaming_compute_source_hash(
    const uint8_t* first_mb,
    size_t first_mb_len,
    const uint8_t* last_mb,
    size_t last_mb_len,
    uint64_t file_size,
    uint8_t hash_out[VAULT_HASH_LEN]
);

#ifdef __cplusplus
}
#endif

#endif // VAULT_STREAMING_H
