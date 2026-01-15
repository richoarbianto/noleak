/**
 * NoLeak Vault Engine - Streaming Import Implementation
 *
 * Memory-efficient import for large files (up to 50GB)
 * with resume support and progress tracking.
 */

#include "vault_streaming.h"
#include <android/log.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define LOG_TAG "VaultStreaming"

// DEBUG: Always enable logging for troubleshooting
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// External declarations
extern vault_state_t g_vault;
void vault_random_bytes(uint8_t *buf, size_t len);
void vault_generate_id(uint8_t id_out[VAULT_ID_LEN]);

// State file magic and version
#define STATE_MAGIC "STRMV1"
#define STATE_MAGIC_LEN 6

// Active imports tracking (max 4 concurrent)
#define MAX_ACTIVE_IMPORTS 4
static streaming_import_state_t *g_active_imports[MAX_ACTIVE_IMPORTS] = {0};
static streaming_progress_callback_t g_progress_callbacks[MAX_ACTIVE_IMPORTS] =
    {0};
static void *g_progress_user_data[MAX_ACTIVE_IMPORTS] = {0};

// Pending imports directory path
static char *g_pending_dir = NULL;

// Helper: Get current timestamp in milliseconds
static uint64_t get_timestamp_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// Helper: Convert import_id to hex string
static void import_id_to_hex(const uint8_t import_id[VAULT_ID_LEN],
                             char *hex_out) {
  static const char hex_chars[] = "0123456789abcdef";
  for (int i = 0; i < VAULT_ID_LEN; i++) {
    hex_out[i * 2] = hex_chars[(import_id[i] >> 4) & 0xF];
    hex_out[i * 2 + 1] = hex_chars[import_id[i] & 0xF];
  }
  hex_out[VAULT_ID_LEN * 2] = '\0';
}

// Helper: Convert hex string to import_id
static int hex_to_import_id(const char *hex,
                            uint8_t import_id_out[VAULT_ID_LEN]) {
  if (strlen(hex) != VAULT_ID_LEN * 2)
    return -1;
  for (int i = 0; i < VAULT_ID_LEN; i++) {
    char high = hex[i * 2];
    char low = hex[i * 2 + 1];
    uint8_t val = 0;
    if (high >= '0' && high <= '9')
      val = (high - '0') << 4;
    else if (high >= 'a' && high <= 'f')
      val = (high - 'a' + 10) << 4;
    else
      return -1;
    if (low >= '0' && low <= '9')
      val |= (low - '0');
    else if (low >= 'a' && low <= 'f')
      val |= (low - 'a' + 10);
    else
      return -1;
    import_id_out[i] = val;
  }
  return 0;
}

// Helper: Get import directory path
static char *get_import_dir(const uint8_t import_id[VAULT_ID_LEN]) {
  if (!g_pending_dir)
    return NULL;
  char hex[VAULT_ID_LEN * 2 + 1];
  import_id_to_hex(import_id, hex);
  size_t len = strlen(g_pending_dir) + 1 + strlen(hex) + 1;
  char *path = malloc(len);
  if (path) {
    snprintf(path, len, "%s/%s", g_pending_dir, hex);
  }
  return path;
}

// Helper: Get state file path
static char *get_state_path(const uint8_t import_id[VAULT_ID_LEN]) {
  char *dir = get_import_dir(import_id);
  if (!dir)
    return NULL;
  size_t len = strlen(dir) + 8;
  char *path = malloc(len);
  if (path) {
    snprintf(path, len, "%s/.state", dir);
  }
  free(dir);
  return path;
}

// Helper: Get chunk file path
static char *get_chunk_path(const uint8_t import_id[VAULT_ID_LEN],
                            uint32_t chunk_index) {
  char *dir = get_import_dir(import_id);
  if (!dir)
    return NULL;
  size_t len = strlen(dir) + 20;
  char *path = malloc(len);
  if (path) {
    snprintf(path, len, "%s/chunk_%08u.enc", dir, chunk_index);
  }
  free(dir);
  return path;
}

// Helper: Find active import slot
static int find_active_slot(const uint8_t import_id[VAULT_ID_LEN]) {
  for (int i = 0; i < MAX_ACTIVE_IMPORTS; i++) {
    if (g_active_imports[i] &&
        memcmp(g_active_imports[i]->import_id, import_id, VAULT_ID_LEN) == 0) {
      return i;
    }
  }
  return -1;
}

// Helper: Get free active slot
static int get_free_slot(void) {
  for (int i = 0; i < MAX_ACTIVE_IMPORTS; i++) {
    if (!g_active_imports[i])
      return i;
  }
  return -1;
}

// Save state to disk
static int save_state(const streaming_import_state_t *state) {
  char *path = get_state_path(state->import_id);
  if (!path)
    return STREAMING_ERR_MEMORY;

  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  free(path);
  if (fd < 0)
    return STREAMING_ERR_IO;

  // Write magic
  if (write(fd, STATE_MAGIC, STATE_MAGIC_LEN) != STATE_MAGIC_LEN) {
    close(fd);
    return STREAMING_ERR_IO;
  }

  // Write version
  uint32_t version = STREAMING_STATE_VERSION;
  if (write(fd, &version, sizeof(version)) != sizeof(version)) {
    close(fd);
    return STREAMING_ERR_IO;
  }

  // Write fixed fields
  if (write(fd, state->import_id, VAULT_ID_LEN) != VAULT_ID_LEN ||
      write(fd, state->file_id, VAULT_ID_LEN) != VAULT_ID_LEN ||
      write(fd, state->source_hash, VAULT_HASH_LEN) != VAULT_HASH_LEN ||
      write(fd, &state->file_type, 1) != 1 ||
      write(fd, &state->file_size, sizeof(uint64_t)) != sizeof(uint64_t) ||
      write(fd, &state->chunk_size, sizeof(uint32_t)) != sizeof(uint32_t) ||
      write(fd, &state->total_chunks, sizeof(uint32_t)) != sizeof(uint32_t) ||
      write(fd, &state->completed_chunks, sizeof(uint32_t)) !=
          sizeof(uint32_t) ||
      write(fd, &state->bytes_written, sizeof(uint64_t)) != sizeof(uint64_t) ||
      write(fd, &state->created_at, sizeof(uint64_t)) != sizeof(uint64_t) ||
      write(fd, &state->updated_at, sizeof(uint64_t)) != sizeof(uint64_t)) {
    close(fd);
    return STREAMING_ERR_IO;
  }

  // Write strings with length prefix
  uint16_t len;

  // SECURITY: Do not persist source URI to disk
  len = 0;
  if (write(fd, &len, sizeof(len)) != sizeof(len)) {
    close(fd);
    return STREAMING_ERR_IO;
  }

  len = state->file_name ? (uint16_t)strlen(state->file_name) : 0;
  if (write(fd, &len, sizeof(len)) != sizeof(len)) {
    close(fd);
    return STREAMING_ERR_IO;
  }
  if (len > 0 && write(fd, state->file_name, len) != len) {
    close(fd);
    return STREAMING_ERR_IO;
  }

  len = state->mime_type ? (uint16_t)strlen(state->mime_type) : 0;
  if (write(fd, &len, sizeof(len)) != sizeof(len)) {
    close(fd);
    return STREAMING_ERR_IO;
  }
  if (len > 0 && write(fd, state->mime_type, len) != len) {
    close(fd);
    return STREAMING_ERR_IO;
  }

  // Write wrapped DEK
  if (write(fd, &state->wrapped_dek_len, sizeof(uint16_t)) !=
      sizeof(uint16_t)) {
    close(fd);
    return STREAMING_ERR_IO;
  }
  if (state->wrapped_dek_len > 0 && state->wrapped_dek) {
    if (write(fd, state->wrapped_dek, state->wrapped_dek_len) !=
        state->wrapped_dek_len) {
      close(fd);
      return STREAMING_ERR_IO;
    }
  }

  fsync(fd);
  close(fd);
  return STREAMING_OK;
}

// Load state from disk
static int load_state(const uint8_t import_id[VAULT_ID_LEN],
                      streaming_import_state_t *state) {
  char *path = get_state_path(import_id);
  if (!path)
    return STREAMING_ERR_MEMORY;

  int fd = open(path, O_RDONLY);
  free(path);
  if (fd < 0)
    return STREAMING_ERR_NOT_FOUND;

  memset(state, 0, sizeof(*state));

  // Read and verify magic
  char magic[STATE_MAGIC_LEN];
  if (read(fd, magic, STATE_MAGIC_LEN) != STATE_MAGIC_LEN ||
      memcmp(magic, STATE_MAGIC, STATE_MAGIC_LEN) != 0) {
    close(fd);
    return STREAMING_ERR_IO;
  }

  // Read and verify version
  uint32_t version;
  if (read(fd, &version, sizeof(version)) != sizeof(version) ||
      version != STREAMING_STATE_VERSION) {
    close(fd);
    return STREAMING_ERR_IO;
  }

  // Read fixed fields
  if (read(fd, state->import_id, VAULT_ID_LEN) != VAULT_ID_LEN ||
      read(fd, state->file_id, VAULT_ID_LEN) != VAULT_ID_LEN ||
      read(fd, state->source_hash, VAULT_HASH_LEN) != VAULT_HASH_LEN ||
      read(fd, &state->file_type, 1) != 1 ||
      read(fd, &state->file_size, sizeof(uint64_t)) != sizeof(uint64_t) ||
      read(fd, &state->chunk_size, sizeof(uint32_t)) != sizeof(uint32_t) ||
      read(fd, &state->total_chunks, sizeof(uint32_t)) != sizeof(uint32_t) ||
      read(fd, &state->completed_chunks, sizeof(uint32_t)) !=
          sizeof(uint32_t) ||
      read(fd, &state->bytes_written, sizeof(uint64_t)) != sizeof(uint64_t) ||
      read(fd, &state->created_at, sizeof(uint64_t)) != sizeof(uint64_t) ||
      read(fd, &state->updated_at, sizeof(uint64_t)) != sizeof(uint64_t)) {
    close(fd);
    return STREAMING_ERR_IO;
  }

  // Read strings
  uint16_t len;

  if (read(fd, &len, sizeof(len)) != sizeof(len)) {
    close(fd);
    return STREAMING_ERR_IO;
  }
  if (len > 0) {
    state->source_uri = malloc(len + 1);
    if (!state->source_uri || read(fd, state->source_uri, len) != len) {
      streaming_free_state(state);
      close(fd);
      return STREAMING_ERR_IO;
    }
    state->source_uri[len] = '\0';
  }

  if (read(fd, &len, sizeof(len)) != sizeof(len)) {
    streaming_free_state(state);
    close(fd);
    return STREAMING_ERR_IO;
  }
  if (len > 0) {
    state->file_name = malloc(len + 1);
    if (!state->file_name || read(fd, state->file_name, len) != len) {
      streaming_free_state(state);
      close(fd);
      return STREAMING_ERR_IO;
    }
    state->file_name[len] = '\0';
  }

  if (read(fd, &len, sizeof(len)) != sizeof(len)) {
    streaming_free_state(state);
    close(fd);
    return STREAMING_ERR_IO;
  }
  if (len > 0) {
    state->mime_type = malloc(len + 1);
    if (!state->mime_type || read(fd, state->mime_type, len) != len) {
      streaming_free_state(state);
      close(fd);
      return STREAMING_ERR_IO;
    }
    state->mime_type[len] = '\0';
  }

  // Read wrapped DEK
  if (read(fd, &state->wrapped_dek_len, sizeof(uint16_t)) != sizeof(uint16_t)) {
    streaming_free_state(state);
    close(fd);
    return STREAMING_ERR_IO;
  }
  if (state->wrapped_dek_len > 0) {
    state->wrapped_dek = malloc(state->wrapped_dek_len);
    if (!state->wrapped_dek ||
        read(fd, state->wrapped_dek, state->wrapped_dek_len) !=
            state->wrapped_dek_len) {
      streaming_free_state(state);
      close(fd);
      return STREAMING_ERR_IO;
    }
  }

  close(fd);

  // Set pending dir
  state->pending_dir = get_import_dir(import_id);

  return STREAMING_OK;
}

// Unwrap DEK from state
static int unwrap_dek(const streaming_import_state_t *state,
                      uint8_t dek_out[VAULT_KEY_LEN]) {
  if (!state->wrapped_dek ||
      state->wrapped_dek_len < VAULT_NONCE_LEN + VAULT_TAG_LEN) {
    return STREAMING_ERR_CRYPTO;
  }

  vault_aad_t aad = {0};
  memcpy(aad.vault_id, g_vault.vault_id, VAULT_ID_LEN);
  memcpy(aad.file_id, state->file_id, VAULT_ID_LEN);
  aad.chunk_index = 0;
  aad.format_version = VAULT_VERSION;

  uint8_t *nonce = state->wrapped_dek;
  uint8_t *ciphertext = state->wrapped_dek + VAULT_NONCE_LEN;
  size_t ct_len = state->wrapped_dek_len - VAULT_NONCE_LEN;
  size_t pt_len;

  return vault_aead_decrypt(g_vault.master_key, nonce, (uint8_t *)&aad,
                            sizeof(aad), ciphertext, ct_len, dek_out, &pt_len);
}

// ============================================================================
// Public API Implementation
// ============================================================================

int streaming_init(void) {
  if (!g_vault.is_open || !g_vault.path) {
    return STREAMING_ERR_VAULT_NOT_OPEN;
  }

  // Create pending imports directory next to vault file
  size_t path_len = strlen(g_vault.path);
  g_pending_dir = malloc(path_len + 20);
  if (!g_pending_dir)
    return STREAMING_ERR_MEMORY;

  // Get directory of vault file
  char *last_slash = strrchr(g_vault.path, '/');
  if (last_slash) {
    size_t dir_len = last_slash - g_vault.path;
    memcpy(g_pending_dir, g_vault.path, dir_len);
    g_pending_dir[dir_len] = '\0';
    strcat(g_pending_dir, "/.pending_imports");
  } else {
    strcpy(g_pending_dir, ".pending_imports");
  }

  // Create directory if needed
  struct stat st;
  if (stat(g_pending_dir, &st) != 0) {
    if (mkdir(g_pending_dir, 0700) != 0 && errno != EEXIST) {
      LOGE("Failed to create pending imports dir: %s", g_pending_dir);
      free(g_pending_dir);
      g_pending_dir = NULL;
      return STREAMING_ERR_IO;
    }
  }

  LOGI("Streaming init: pending_dir=%s", g_pending_dir);
  return STREAMING_OK;
}

int streaming_compute_source_hash(const uint8_t *first_mb, size_t first_mb_len,
                                  const uint8_t *last_mb, size_t last_mb_len,
                                  uint64_t file_size,
                                  uint8_t hash_out[VAULT_HASH_LEN]) {
  if (!first_mb || first_mb_len == 0 || !hash_out) {
    return STREAMING_ERR_INVALID_PARAM;
  }

  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);

  // Hash first MB
  crypto_hash_sha256_update(&state, first_mb, first_mb_len);

  // Hash last MB if provided
  if (last_mb && last_mb_len > 0) {
    crypto_hash_sha256_update(&state, last_mb, last_mb_len);
  }

  // Hash file size
  crypto_hash_sha256_update(&state, (uint8_t *)&file_size, sizeof(file_size));

  crypto_hash_sha256_final(&state, hash_out);
  return STREAMING_OK;
}

int streaming_start(const char *source_uri,
                    const uint8_t source_hash[VAULT_HASH_LEN], const char *name,
                    const char *mime, uint8_t type, uint64_t file_size,
                    uint8_t import_id_out[VAULT_ID_LEN],
                    uint32_t *resume_from_chunk_out) {
  if (!g_vault.is_open)
    return STREAMING_ERR_VAULT_NOT_OPEN;
  if (!source_uri || !source_hash || !name || !import_id_out ||
      !resume_from_chunk_out) {
    return STREAMING_ERR_INVALID_PARAM;
  }
  if (file_size > STREAMING_MAX_FILE_SIZE) {
    return STREAMING_ERR_FILE_TOO_LARGE;
  }

  // Initialize if needed
  if (!g_pending_dir) {
    int result = streaming_init();
    if (result != STREAMING_OK)
      return result;
  }

  // Check for existing import with same source hash
  streaming_import_state_t *states = NULL;
  uint32_t count = 0;
  if (streaming_list_pending(&states, &count) == STREAMING_OK && count > 0) {
    for (uint32_t i = 0; i < count; i++) {
      if (memcmp(states[i].source_hash, source_hash, VAULT_HASH_LEN) == 0) {
        // Found matching import - resume
        memcpy(import_id_out, states[i].import_id, VAULT_ID_LEN);
        *resume_from_chunk_out = states[i].completed_chunks;
        LOGI("Resuming import from chunk %u", states[i].completed_chunks);

        // Load into active slot
        int slot = get_free_slot();
        if (slot >= 0) {
          g_active_imports[slot] = malloc(sizeof(streaming_import_state_t));
          if (g_active_imports[slot]) {
            memcpy(g_active_imports[slot], &states[i],
                   sizeof(streaming_import_state_t));
            g_active_imports[slot]->is_active = 1;
            // Don't free strings - they're now owned by active import
            states[i].source_uri = NULL;
            states[i].file_name = NULL;
            states[i].mime_type = NULL;
            states[i].wrapped_dek = NULL;
            states[i].pending_dir = NULL;
          }
        }

        // Free remaining states
        for (uint32_t j = 0; j < count; j++) {
          streaming_free_state(&states[j]);
        }
        free(states);
        return STREAMING_OK;
      }
    }
    // Free states
    for (uint32_t i = 0; i < count; i++) {
      streaming_free_state(&states[i]);
    }
    free(states);
  }

  // Create new import
  LOGI("Starting new streaming import: %s, size=%llu", name,
       (unsigned long long)file_size);

  streaming_import_state_t *state = calloc(1, sizeof(streaming_import_state_t));
  if (!state)
    return STREAMING_ERR_MEMORY;

  // Generate IDs
  vault_generate_id(state->import_id);
  vault_generate_id(state->file_id);
  memcpy(import_id_out, state->import_id, VAULT_ID_LEN);
  *resume_from_chunk_out = 0;

  // Copy metadata
  memcpy(state->source_hash, source_hash, VAULT_HASH_LEN);
  state->source_uri = strdup(source_uri);
  state->file_name = strdup(name);
  state->mime_type = mime ? strdup(mime) : strdup("");
  state->file_type = type;
  state->file_size = file_size;
  state->chunk_size = STREAMING_CHUNK_SIZE;
  state->total_chunks =
      (file_size + STREAMING_CHUNK_SIZE - 1) / STREAMING_CHUNK_SIZE;
  state->completed_chunks = 0;
  state->bytes_written = 0;
  state->created_at = get_timestamp_ms();
  state->updated_at = state->created_at;

  if (!state->source_uri || !state->file_name || !state->mime_type) {
    streaming_free_state(state);
    free(state);
    return STREAMING_ERR_MEMORY;
  }

  // Generate and wrap DEK
  uint8_t dek[VAULT_KEY_LEN];
  vault_random_bytes(dek, VAULT_KEY_LEN);

  uint8_t dek_nonce[VAULT_NONCE_LEN];
  state->wrapped_dek_len = VAULT_NONCE_LEN + VAULT_KEY_LEN + VAULT_TAG_LEN;
  state->wrapped_dek = malloc(state->wrapped_dek_len);
  if (!state->wrapped_dek) {
    vault_zeroize(dek, VAULT_KEY_LEN);
    streaming_free_state(state);
    free(state);
    return STREAMING_ERR_MEMORY;
  }

  vault_aad_t aad = {0};
  memcpy(aad.vault_id, g_vault.vault_id, VAULT_ID_LEN);
  memcpy(aad.file_id, state->file_id, VAULT_ID_LEN);
  aad.chunk_index = 0;
  aad.format_version = VAULT_VERSION;

  int result = vault_aead_encrypt(
      g_vault.master_key, NULL, (uint8_t *)&aad, sizeof(aad), dek,
      VAULT_KEY_LEN, state->wrapped_dek + VAULT_NONCE_LEN, dek_nonce);
  vault_zeroize(dek, VAULT_KEY_LEN);

  if (result != VAULT_OK) {
    streaming_free_state(state);
    free(state);
    return STREAMING_ERR_CRYPTO;
  }
  memcpy(state->wrapped_dek, dek_nonce, VAULT_NONCE_LEN);

  // Create import directory
  state->pending_dir = get_import_dir(state->import_id);
  if (!state->pending_dir) {
    streaming_free_state(state);
    free(state);
    return STREAMING_ERR_MEMORY;
  }

  if (mkdir(state->pending_dir, 0700) != 0 && errno != EEXIST) {
    LOGE("Failed to create import dir: %s", state->pending_dir);
    streaming_free_state(state);
    free(state);
    return STREAMING_ERR_IO;
  }

  // Save state
  result = save_state(state);
  if (result != STREAMING_OK) {
    streaming_free_state(state);
    free(state);
    return result;
  }

  // Add to active imports
  int slot = get_free_slot();
  if (slot >= 0) {
    state->is_active = 1;
    g_active_imports[slot] = state;
  } else {
    streaming_free_state(state);
    free(state);
  }

  LOGI("Streaming import started: total_chunks=%u", state->total_chunks);
  return STREAMING_OK;
}

int streaming_write_chunk(const uint8_t import_id[VAULT_ID_LEN],
                          uint8_t *plaintext, size_t len,
                          uint32_t chunk_index) {
  if (!g_vault.is_open)
    return STREAMING_ERR_VAULT_NOT_OPEN;
  if (!import_id || !plaintext || len == 0)
    return STREAMING_ERR_INVALID_PARAM;

  // Find active import
  int slot = find_active_slot(import_id);
  streaming_import_state_t *state = NULL;

  if (slot >= 0) {
    state = g_active_imports[slot];
  } else {
    // Load from disk
    state = calloc(1, sizeof(streaming_import_state_t));
    if (!state) {
      vault_zeroize(plaintext, len);
      return STREAMING_ERR_MEMORY;
    }
    int result = load_state(import_id, state);
    if (result != STREAMING_OK) {
      free(state);
      vault_zeroize(plaintext, len);
      return result;
    }
    // Add to active slot
    slot = get_free_slot();
    if (slot >= 0) {
      state->is_active = 1;
      g_active_imports[slot] = state;
    }
  }

  if (chunk_index >= state->total_chunks) {
    vault_zeroize(plaintext, len);
    return STREAMING_ERR_INVALID_PARAM;
  }

  // Unwrap DEK
  uint8_t dek[VAULT_KEY_LEN];
  int result = unwrap_dek(state, dek);
  if (result != STREAMING_OK) {
    vault_zeroize(plaintext, len);
    return result;
  }

  // Encrypt chunk
  size_t ct_len = len + VAULT_TAG_LEN;
  uint8_t *ciphertext = malloc(VAULT_NONCE_LEN + ct_len);
  if (!ciphertext) {
    vault_zeroize(dek, VAULT_KEY_LEN);
    vault_zeroize(plaintext, len);
    return STREAMING_ERR_MEMORY;
  }

  vault_aad_t aad = {0};
  memcpy(aad.vault_id, g_vault.vault_id, VAULT_ID_LEN);
  memcpy(aad.file_id, state->file_id, VAULT_ID_LEN);
  aad.chunk_index = chunk_index;
  aad.format_version = VAULT_VERSION;

  uint8_t nonce[VAULT_NONCE_LEN];
  result =
      vault_aead_encrypt(dek, NULL, (uint8_t *)&aad, sizeof(aad), plaintext,
                         len, ciphertext + VAULT_NONCE_LEN, nonce);

  // SECURITY: Zeroize plaintext and DEK immediately
  vault_zeroize(dek, VAULT_KEY_LEN);
  vault_zeroize(plaintext, len);

  if (result != VAULT_OK) {
    vault_zeroize(ciphertext, VAULT_NONCE_LEN + ct_len);
    free(ciphertext);
    return STREAMING_ERR_CRYPTO;
  }
  memcpy(ciphertext, nonce, VAULT_NONCE_LEN);

  // Write to chunk file
  char *chunk_path = get_chunk_path(import_id, chunk_index);
  if (!chunk_path) {
    vault_zeroize(ciphertext, VAULT_NONCE_LEN + ct_len);
    free(ciphertext);
    return STREAMING_ERR_MEMORY;
  }

  int fd = open(chunk_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  free(chunk_path);
  if (fd < 0) {
    vault_zeroize(ciphertext, VAULT_NONCE_LEN + ct_len);
    free(ciphertext);
    return STREAMING_ERR_IO;
  }

  ssize_t written = write(fd, ciphertext, VAULT_NONCE_LEN + ct_len);
  fsync(fd);
  close(fd);

  vault_zeroize(ciphertext, VAULT_NONCE_LEN + ct_len);
  free(ciphertext);

  if (written != (ssize_t)(VAULT_NONCE_LEN + ct_len)) {
    return STREAMING_ERR_IO;
  }

  // Update state
  state->completed_chunks = chunk_index + 1;
  state->bytes_written += len;
  state->updated_at = get_timestamp_ms();

  // Save state periodically (every 10 chunks or on last chunk)
  if (chunk_index % 10 == 9 || state->completed_chunks == state->total_chunks) {
    save_state(state);
  }

  // Call progress callback
  if (slot >= 0 && g_progress_callbacks[slot]) {
    g_progress_callbacks[slot](import_id, state->bytes_written,
                               state->file_size, state->completed_chunks,
                               state->total_chunks, g_progress_user_data[slot]);
  }

  LOGI("Chunk %u/%u written (%zu bytes)", chunk_index + 1, state->total_chunks,
       len);
  return STREAMING_OK;
}

int streaming_finish(const uint8_t import_id[VAULT_ID_LEN],
                     uint8_t file_id_out[VAULT_ID_LEN]) {
  LOGD("streaming_finish: START");

  if (!g_vault.is_open) {
    LOGE("streaming_finish: vault not open");
    return STREAMING_ERR_VAULT_NOT_OPEN;
  }
  if (!import_id || !file_id_out) {
    LOGE("streaming_finish: invalid param");
    return STREAMING_ERR_INVALID_PARAM;
  }

  // Find or load state
  int slot = find_active_slot(import_id);
  streaming_import_state_t *state = NULL;
  int state_allocated = 0;

  LOGD("streaming_finish: slot=%d", slot);

  if (slot >= 0) {
    state = g_active_imports[slot];
    // IMPORTANT: Remove from active imports immediately to prevent stale state
    // If finish fails, the pending files will be cleaned up by streaming_abort
    g_active_imports[slot] = NULL;
    g_progress_callbacks[slot] = NULL;
    g_progress_user_data[slot] = NULL;
    state_allocated = 1; // We now own this state and must free it
    LOGD("streaming_finish: loaded from active slot");
  } else {
    state = calloc(1, sizeof(streaming_import_state_t));
    if (!state) {
      LOGE("streaming_finish: failed to alloc state");
      return STREAMING_ERR_MEMORY;
    }
    int result = load_state(import_id, state);
    if (result != STREAMING_OK) {
      LOGE("streaming_finish: load_state failed with %d", result);
      free(state);
      return result;
    }
    state_allocated = 1;
    LOGD("streaming_finish: loaded from disk");
  }

  // Verify all chunks are complete
  LOGD("streaming_finish: completed_chunks=%u, total_chunks=%u",
       state->completed_chunks, state->total_chunks);

  if (state->completed_chunks != state->total_chunks) {
    LOGE("Cannot finish: only %u/%u chunks complete", state->completed_chunks,
         state->total_chunks);
    if (state_allocated) {
      streaming_free_state(state);
      free(state);
    }
    // Cleanup pending files since we can't finish
    streaming_abort(import_id);
    return STREAMING_ERR_INVALID_PARAM;
  }

  LOGI("Finishing streaming import: %s (%u chunks, %llu bytes)",
       state->file_name, state->total_chunks,
       (unsigned long long)state->file_size);

  // Build vault entry
  vault_entry_t new_entry;
  memset(&new_entry, 0, sizeof(new_entry));

  memcpy(new_entry.file_id, state->file_id, VAULT_ID_LEN);
  new_entry.type = state->file_type;
  new_entry.created_at = state->created_at;
  new_entry.name = strdup(state->file_name);
  new_entry.mime = strdup(state->mime_type);
  new_entry.size = state->file_size;
  new_entry.wrapped_dek = malloc(state->wrapped_dek_len);
  new_entry.wrapped_dek_len = state->wrapped_dek_len;

  if (!new_entry.name || !new_entry.mime || !new_entry.wrapped_dek) {
    vault_free_entry(&new_entry);
    if (state_allocated) {
      streaming_free_state(state);
      free(state);
    }
    // Cleanup pending files on error
    streaming_abort(import_id);
    return STREAMING_ERR_MEMORY;
  }
  memcpy(new_entry.wrapped_dek, state->wrapped_dek, state->wrapped_dek_len);

  // Set up chunks for video-style storage
  new_entry.chunk_count = state->total_chunks;
  new_entry.chunks = calloc(state->total_chunks, sizeof(new_entry.chunks[0]));
  if (!new_entry.chunks) {
    vault_free_entry(&new_entry);
    if (state_allocated) {
      streaming_free_state(state);
      free(state);
    }
    // Cleanup pending files on error
    streaming_abort(import_id);
    return STREAMING_ERR_MEMORY;
  }

  LOGD("streaming_finish: building payload from %u chunk files",
       state->total_chunks);

  // Build payload from chunk files
  vault_payload_t new_payload;
  memset(&new_payload, 0, sizeof(new_payload));
  new_payload.chunk_count = state->total_chunks;
  new_payload.chunks = calloc(state->total_chunks, sizeof(uint8_t *));
  new_payload.chunk_lens = calloc(state->total_chunks, sizeof(size_t));

  if (!new_payload.chunks || !new_payload.chunk_lens) {
    LOGE("streaming_finish: failed to alloc payload arrays");
    vault_free_entry(&new_entry);
    if (new_payload.chunks)
      free(new_payload.chunks);
    if (new_payload.chunk_lens)
      free(new_payload.chunk_lens);
    if (state_allocated) {
      streaming_free_state(state);
      free(state);
    }
    // Cleanup pending files on error
    streaming_abort(import_id);
    return STREAMING_ERR_MEMORY;
  }

  // Read all chunk files
  int result = STREAMING_OK;
  size_t total_payload_size = 0;
  for (uint32_t i = 0; i < state->total_chunks; i++) {
    char *chunk_path = get_chunk_path(import_id, i);
    if (!chunk_path) {
      LOGE("streaming_finish: failed to get chunk path for %u", i);
      result = STREAMING_ERR_MEMORY;
      break;
    }

    struct stat st;
    if (stat(chunk_path, &st) != 0) {
      LOGE("streaming_finish: chunk %u not found: %s (errno=%d)", i, chunk_path,
           errno);
      free(chunk_path);
      result = STREAMING_ERR_NOT_FOUND;
      break;
    }

    int fd = open(chunk_path, O_RDONLY);
    free(chunk_path);
    if (fd < 0) {
      LOGE("streaming_finish: failed to open chunk %u (errno=%d)", i, errno);
      result = STREAMING_ERR_IO;
      break;
    }

    size_t chunk_len = st.st_size;
    uint8_t *chunk_data = malloc(chunk_len);
    if (!chunk_data) {
      LOGE("streaming_finish: failed to alloc %zu bytes for chunk %u",
           chunk_len, i);
      close(fd);
      result = STREAMING_ERR_MEMORY;
      break;
    }

    if (read(fd, chunk_data, chunk_len) != (ssize_t)chunk_len) {
      LOGE("streaming_finish: failed to read chunk %u (errno=%d)", i, errno);
      free(chunk_data);
      close(fd);
      result = STREAMING_ERR_IO;
      break;
    }
    close(fd);

    // Extract nonce from chunk file
    if (chunk_len < VAULT_NONCE_LEN + VAULT_TAG_LEN) {
      LOGE("streaming_finish: chunk %u too small: %zu bytes", i, chunk_len);
      free(chunk_data);
      result = STREAMING_ERR_CHUNK_CORRUPTED;
      break;
    }

    memcpy(new_entry.chunks[i].nonce, chunk_data, VAULT_NONCE_LEN);

    // Store ciphertext (without nonce prefix) for vault container
    size_t ct_only_len = chunk_len - VAULT_NONCE_LEN;
    uint8_t *ct_only = malloc(ct_only_len);
    if (!ct_only) {
      LOGE("streaming_finish: failed to alloc ct_only %zu bytes for chunk %u",
           ct_only_len, i);
      free(chunk_data);
      result = STREAMING_ERR_MEMORY;
      break;
    }
    memcpy(ct_only, chunk_data + VAULT_NONCE_LEN, ct_only_len);
    vault_zeroize(chunk_data, chunk_len);
    free(chunk_data);

    new_payload.chunks[i] = ct_only;
    new_payload.chunk_lens[i] = ct_only_len;
    new_entry.chunks[i].length = (uint32_t)ct_only_len;
    total_payload_size += ct_only_len;

    // Log progress every 10 chunks
    if ((i + 1) % 10 == 0 || i == state->total_chunks - 1) {
      LOGD("streaming_finish: loaded %u/%u chunks, total_size=%zu", i + 1,
           state->total_chunks, total_payload_size);
    }
  }

  if (result != STREAMING_OK) {
    LOGE("streaming_finish: chunk loading failed with %d", result);
    // Cleanup on error
    vault_free_entry(&new_entry);
    for (uint32_t i = 0; i < new_payload.chunk_count; i++) {
      if (new_payload.chunks[i]) {
        vault_zeroize(new_payload.chunks[i], new_payload.chunk_lens[i]);
        free(new_payload.chunks[i]);
      }
    }
    free(new_payload.chunks);
    free(new_payload.chunk_lens);
    if (state_allocated) {
      streaming_free_state(state);
      free(state);
    }
    // Cleanup pending files on error
    streaming_abort(import_id);
    return result;
  }

  LOGD("streaming_finish: all chunks loaded, total_payload_size=%zu",
       total_payload_size);

  // PERFORMANCE OPTIMIZATION: Use vault_append_entry instead of full container
  // rebuild This appends new data at end of file without loading existing
  // payloads O(1) instead of O(n)

  LOGI("streaming_finish: using vault_append_entry for efficient import");
  result = vault_append_entry(&new_entry, &new_payload);

  // Free the temporary entry and payload (vault_append_entry made deep copies)
  vault_free_entry(&new_entry);
  for (uint32_t i = 0; i < new_payload.chunk_count; i++) {
    if (new_payload.chunks[i]) {
      vault_zeroize(new_payload.chunks[i], new_payload.chunk_lens[i]);
      free(new_payload.chunks[i]);
    }
  }
  free(new_payload.chunks);
  free(new_payload.chunk_lens);

  if (result != VAULT_OK) {
    LOGE("streaming_finish: vault_append_entry failed with %d", result);
    if (state_allocated) {
      streaming_free_state(state);
      free(state);
    }
    streaming_abort(import_id);
    return STREAMING_ERR_IO;
  }

  memcpy(file_id_out, state->file_id, VAULT_ID_LEN);

  // Cleanup pending import (success case)
  LOGD("streaming_finish: cleaning up pending import");
  streaming_abort(import_id);

  LOGI("streaming_finish: SUCCESS - %s (%llu bytes)", state->file_name,
       (unsigned long long)state->file_size);

  if (state_allocated) {
    streaming_free_state(state);
    free(state);
  }

  return STREAMING_OK;
}

int streaming_abort(const uint8_t import_id[VAULT_ID_LEN]) {
  if (!import_id)
    return STREAMING_ERR_INVALID_PARAM;

  LOGD("streaming_abort: START");

  // Remove from active imports
  int slot = find_active_slot(import_id);
  LOGD("streaming_abort: slot=%d", slot);
  if (slot >= 0) {
    streaming_free_state(g_active_imports[slot]);
    free(g_active_imports[slot]);
    g_active_imports[slot] = NULL;
    g_progress_callbacks[slot] = NULL;
    g_progress_user_data[slot] = NULL;
  }

  // Get import directory
  char *import_dir = get_import_dir(import_id);
  if (!import_dir)
    return STREAMING_ERR_MEMORY;

  // Securely delete all files in directory
  DIR *dir = opendir(import_dir);
  if (dir) {
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
      if (entry->d_name[0] == '.' &&
          (entry->d_name[1] == '\0' ||
           (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
        continue;
      }

      size_t path_len = strlen(import_dir) + 1 + strlen(entry->d_name) + 1;
      char *file_path = malloc(path_len);
      if (file_path) {
        snprintf(file_path, path_len, "%s/%s", import_dir, entry->d_name);

        // Secure wipe before delete
        vault_secure_wipe_file(file_path);
        unlink(file_path);
        free(file_path);
      }
    }
    closedir(dir);
  }

  // Remove directory
  rmdir(import_dir);
  free(import_dir);

  return STREAMING_OK;
}

int streaming_list_pending(streaming_import_state_t **states_out,
                           uint32_t *count_out) {
  if (!states_out || !count_out)
    return STREAMING_ERR_INVALID_PARAM;
  if (!g_pending_dir) {
    *states_out = NULL;
    *count_out = 0;
    return STREAMING_OK;
  }

  DIR *dir = opendir(g_pending_dir);
  if (!dir) {
    *states_out = NULL;
    *count_out = 0;
    return STREAMING_OK;
  }

  // Count valid import directories
  uint32_t count = 0;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_type == DT_DIR && strlen(entry->d_name) == VAULT_ID_LEN * 2) {
      count++;
    }
  }

  if (count == 0) {
    closedir(dir);
    *states_out = NULL;
    *count_out = 0;
    return STREAMING_OK;
  }

  streaming_import_state_t *states =
      calloc(count, sizeof(streaming_import_state_t));
  if (!states) {
    closedir(dir);
    return STREAMING_ERR_MEMORY;
  }

  rewinddir(dir);
  uint32_t idx = 0;
  while ((entry = readdir(dir)) != NULL && idx < count) {
    if (entry->d_type == DT_DIR && strlen(entry->d_name) == VAULT_ID_LEN * 2) {
      uint8_t import_id[VAULT_ID_LEN];
      if (hex_to_import_id(entry->d_name, import_id) == 0) {
        if (load_state(import_id, &states[idx]) == STREAMING_OK) {
          idx++;
        }
      }
    }
  }
  closedir(dir);

  *states_out = states;
  *count_out = idx;
  return STREAMING_OK;
}

int streaming_get_state(const uint8_t import_id[VAULT_ID_LEN],
                        streaming_import_state_t *state_out) {
  if (!import_id || !state_out)
    return STREAMING_ERR_INVALID_PARAM;

  // Check active imports first
  int slot = find_active_slot(import_id);
  if (slot >= 0) {
    memcpy(state_out, g_active_imports[slot], sizeof(streaming_import_state_t));
    // Duplicate strings
    state_out->source_uri = g_active_imports[slot]->source_uri
                                ? strdup(g_active_imports[slot]->source_uri)
                                : NULL;
    state_out->file_name = g_active_imports[slot]->file_name
                               ? strdup(g_active_imports[slot]->file_name)
                               : NULL;
    state_out->mime_type = g_active_imports[slot]->mime_type
                               ? strdup(g_active_imports[slot]->mime_type)
                               : NULL;
    state_out->pending_dir = g_active_imports[slot]->pending_dir
                                 ? strdup(g_active_imports[slot]->pending_dir)
                                 : NULL;
    if (g_active_imports[slot]->wrapped_dek) {
      state_out->wrapped_dek = malloc(g_active_imports[slot]->wrapped_dek_len);
      if (state_out->wrapped_dek) {
        memcpy(state_out->wrapped_dek, g_active_imports[slot]->wrapped_dek,
               g_active_imports[slot]->wrapped_dek_len);
      }
    }
    return STREAMING_OK;
  }

  return load_state(import_id, state_out);
}

int streaming_set_progress_callback(const uint8_t import_id[VAULT_ID_LEN],
                                    streaming_progress_callback_t callback,
                                    void *user_data) {
  if (!import_id)
    return STREAMING_ERR_INVALID_PARAM;

  int slot = find_active_slot(import_id);
  if (slot < 0)
    return STREAMING_ERR_NOT_FOUND;

  g_progress_callbacks[slot] = callback;
  g_progress_user_data[slot] = user_data;
  return STREAMING_OK;
}

int streaming_cleanup_old(uint64_t max_age_ms) {
  streaming_import_state_t *states = NULL;
  uint32_t count = 0;

  if (streaming_list_pending(&states, &count) != STREAMING_OK || count == 0) {
    return 0;
  }

  uint64_t now = get_timestamp_ms();
  int cleaned = 0;

  for (uint32_t i = 0; i < count; i++) {
    uint64_t age = now - states[i].updated_at;
    if (max_age_ms == 0 || age > max_age_ms) {
      streaming_abort(states[i].import_id);
      cleaned++;
    }
    streaming_free_state(&states[i]);
  }
  free(states);

  return cleaned;
}

void streaming_free_state(streaming_import_state_t *state) {
  if (!state)
    return;
  if (state->source_uri) {
    free(state->source_uri);
    state->source_uri = NULL;
  }
  if (state->file_name) {
    free(state->file_name);
    state->file_name = NULL;
  }
  if (state->mime_type) {
    free(state->mime_type);
    state->mime_type = NULL;
  }
  if (state->pending_dir) {
    free(state->pending_dir);
    state->pending_dir = NULL;
  }
  if (state->wrapped_dek) {
    vault_zeroize(state->wrapped_dek, state->wrapped_dek_len);
    free(state->wrapped_dek);
    state->wrapped_dek = NULL;
  }
}
