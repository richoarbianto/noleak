/**
 * NoLeak Vault Engine - Index and File Operations
 */

#include "vault_engine.h"
#include <android/log.h>
#include <fcntl.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define LOG_TAG "VaultIndex"

// SECURITY: Disable logging unless explicitly enabled
#if defined(NDEBUG) || !VAULT_DEBUG_LOGS
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif

// External declarations
extern vault_state_t g_vault;
void vault_random_bytes(uint8_t *buf, size_t len);
void vault_generate_id(uint8_t id_out[VAULT_ID_LEN]);

// Forward declarations - some are non-static for use by vault_streaming.c
void free_entries_array(vault_entry_t *entries, uint32_t count);
static void free_payload(vault_payload_t *payload);
void free_payloads(vault_payload_t *payloads, uint32_t count);
int clone_entries(const vault_entry_t *source, uint32_t count,
                  vault_entry_t **dest_out);
int load_payloads_for_entries(const vault_entry_t *entries, uint32_t count,
                              vault_payload_t *payloads);
static int build_text_image_entry(const uint8_t *data, size_t len, uint8_t type,
                                  const char *name, const char *mime,
                                  vault_entry_t *entry_out,
                                  vault_payload_t *payload_out);
static int build_video_entry(const uint8_t *data, size_t len, const char *name,
                             const char *mime, vault_entry_t *entry_out,
                             vault_payload_t *payload_out);
static int rebuild_container(vault_entry_t *entries, vault_payload_t *payloads,
                             uint32_t count);
static int unwrap_dek(const vault_entry_t *entry,
                      uint8_t dek_out[VAULT_KEY_LEN]);
static int load_blob(uint64_t offset, uint64_t length, uint8_t **out);
static uint64_t compute_used_space(void);
static void clear_entry_allocations(vault_entry_t *entry);

static int is_allowed_system_name(const char *name) {
  if (!name)
    return 0;
  return strcmp(name, "__folder_map__") == 0 ||
         strcmp(name, "__folder_map__.tmp") == 0 ||
         strcmp(name, "__vault_title__") == 0 ||
         strcmp(name, "__vault_title__.tmp") == 0;
}

// Helper: Get current timestamp in milliseconds
static uint64_t get_timestamp_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int vault_import_file(const uint8_t *data, size_t len, uint8_t type,
                      const char *name, const char *mime,
                      uint8_t file_id_out[VAULT_ID_LEN]) {
  LOGI("vault_import_file: starting, len=%zu, type=%u, name=%s", len, type,
       name ? name : "null");

  if (!g_vault.is_open) {
    LOGE("vault_import_file: vault not open");
    return VAULT_ERR_NOT_OPEN;
  }
  if (!data || len == 0 || !name || !file_id_out) {
    LOGE("vault_import_file: invalid params");
    return VAULT_ERR_INVALID_PARAM;
  }
  if (type != VAULT_FILE_TYPE_TXT && type != VAULT_FILE_TYPE_IMG &&
      type != VAULT_FILE_TYPE_VIDEO) {
    LOGE("vault_import_file: invalid type %u", type);
    return VAULT_ERR_INVALID_PARAM;
  }

  int result = VAULT_OK;
  vault_entry_t new_entry;
  vault_payload_t new_payload;
  memset(&new_entry, 0, sizeof(new_entry));
  memset(&new_payload, 0, sizeof(new_payload));

  LOGI("vault_import_file: building entry");
  if (type == VAULT_FILE_TYPE_VIDEO) {
    result = build_video_entry(data, len, name, mime, &new_entry, &new_payload);
  } else {
    result = build_text_image_entry(data, len, type, name, mime, &new_entry,
                                    &new_payload);
  }
  if (result != VAULT_OK) {
    LOGE("vault_import_file: build entry failed with %d", result);
    free_payload(&new_payload);
    return result;
  }
  LOGI("vault_import_file: entry built successfully");

  // PERFORMANCE OPTIMIZATION: Use append-only instead of full rebuild
  // This appends new data at end of file without loading existing payloads
  // O(1) instead of O(n)
  result = vault_append_entry(&new_entry, &new_payload);

  // Copy file_id BEFORE freeing entry (vault_append_entry made deep copies)
  memcpy(file_id_out, new_entry.file_id, VAULT_ID_LEN);

  // Free the temporary entry and payload
  vault_free_entry(&new_entry);
  free_payload(&new_payload);

  if (result != VAULT_OK) {
    LOGE("vault_import_file: vault_append_entry failed with %d", result);
    return result;
  }

  LOGI("File imported: %s (type=%u, size=%zu)", name, type, len);
  return VAULT_OK;
}

int vault_read_file(const uint8_t file_id[VAULT_ID_LEN], uint8_t **data_out,
                    size_t *len_out) {
  if (!g_vault.is_open)
    return VAULT_ERR_NOT_OPEN;
  if (!file_id || !data_out || !len_out)
    return VAULT_ERR_INVALID_PARAM;

  vault_entry_t *entry = NULL;
  for (uint32_t i = 0; i < g_vault.entry_count; i++) {
    if (memcmp(g_vault.entries[i].file_id, file_id, VAULT_ID_LEN) == 0) {
      entry = &g_vault.entries[i];
      break;
    }
  }
  if (!entry)
    return VAULT_ERR_NOT_FOUND;
  // FIX: Reject chunked files - they should use vault_read_chunk instead
  // Streaming import stores all large files as chunked, regardless of type
  if (entry->chunk_count > 0)
    return VAULT_ERR_INVALID_PARAM;

  uint8_t dek[VAULT_KEY_LEN];
  int result = unwrap_dek(entry, dek);
  if (result != VAULT_OK) {
    return result;
  }

  // Read ciphertext blob (nonce + ciphertext)
  uint8_t *blob = NULL;
  result = load_blob(entry->data_offset, entry->data_length, &blob);
  if (result != VAULT_OK) {
    vault_zeroize(dek, VAULT_KEY_LEN);
    return result;
  }

  if (entry->data_length < VAULT_NONCE_LEN + VAULT_TAG_LEN) {
    vault_zeroize(dek, VAULT_KEY_LEN);
    free(blob);
    return VAULT_ERR_CORRUPTED;
  }

  uint8_t *nonce = blob;
  uint8_t *ciphertext = blob + VAULT_NONCE_LEN;
  size_t ct_len = entry->data_length - VAULT_NONCE_LEN;

  uint8_t *plaintext = malloc(ct_len - VAULT_TAG_LEN);
  if (!plaintext) {
    vault_zeroize(dek, VAULT_KEY_LEN);
    free(blob);
    return VAULT_ERR_MEMORY;
  }

  vault_aad_t aad = {0};
  memcpy(aad.vault_id, g_vault.vault_id, VAULT_ID_LEN);
  memcpy(aad.file_id, entry->file_id, VAULT_ID_LEN);
  aad.chunk_index = 0;
  aad.format_version = VAULT_VERSION;

  size_t pt_len = 0;
  result = vault_aead_decrypt(dek, nonce, (uint8_t *)&aad, sizeof(aad),
                              ciphertext, ct_len, plaintext, &pt_len);

  vault_zeroize(dek, VAULT_KEY_LEN);
  vault_zeroize(blob, entry->data_length);
  free(blob);

  if (result != VAULT_OK) {
    free(plaintext);
    return result;
  }

  *data_out = plaintext;
  *len_out = pt_len;
  return VAULT_OK;
}

int vault_read_chunk(const uint8_t file_id[VAULT_ID_LEN], uint32_t chunk_idx,
                     uint8_t **data_out, size_t *len_out) {
  if (!g_vault.is_open)
    return VAULT_ERR_NOT_OPEN;
  if (!file_id || !data_out || !len_out)
    return VAULT_ERR_INVALID_PARAM;

  vault_entry_t *entry = NULL;
  for (uint32_t i = 0; i < g_vault.entry_count; i++) {
    if (memcmp(g_vault.entries[i].file_id, file_id, VAULT_ID_LEN) == 0) {
      entry = &g_vault.entries[i];
      break;
    }
  }
  if (!entry)
    return VAULT_ERR_NOT_FOUND;
  // FIX: Allow reading chunks from any chunked file, not just VIDEO
  // Streaming import stores all large files as chunked, regardless of type
  if (entry->chunk_count == 0)
    return VAULT_ERR_INVALID_PARAM;
  if (chunk_idx >= entry->chunk_count)
    return VAULT_ERR_NOT_FOUND;

  uint8_t dek[VAULT_KEY_LEN];
  int result = unwrap_dek(entry, dek);
  if (result != VAULT_OK) {
    return result;
  }

  uint64_t offset = entry->chunks[chunk_idx].offset;
  uint64_t length = entry->chunks[chunk_idx].length;

  uint8_t *ciphertext = NULL;
  result = load_blob(offset, length, &ciphertext);
  if (result != VAULT_OK) {
    vault_zeroize(dek, VAULT_KEY_LEN);
    return result;
  }

  if (length < VAULT_TAG_LEN) {
    vault_zeroize(dek, VAULT_KEY_LEN);
    vault_zeroize(ciphertext, length);
    free(ciphertext);
    return VAULT_ERR_CORRUPTED;
  }

  uint8_t *plaintext = malloc(length - VAULT_TAG_LEN);
  if (!plaintext) {
    vault_zeroize(dek, VAULT_KEY_LEN);
    vault_zeroize(ciphertext, length);
    free(ciphertext);
    return VAULT_ERR_MEMORY;
  }

  vault_aad_t aad = {0};
  memcpy(aad.vault_id, g_vault.vault_id, VAULT_ID_LEN);
  memcpy(aad.file_id, entry->file_id, VAULT_ID_LEN);
  aad.chunk_index = chunk_idx;
  aad.format_version = VAULT_VERSION;

  size_t pt_len = 0;
  result =
      vault_aead_decrypt(dek, entry->chunks[chunk_idx].nonce, (uint8_t *)&aad,
                         sizeof(aad), ciphertext, length, plaintext, &pt_len);

  vault_zeroize(dek, VAULT_KEY_LEN);
  vault_zeroize(ciphertext, length);
  free(ciphertext);

  if (result != VAULT_OK) {
    free(plaintext);
    return result;
  }

  *data_out = plaintext;
  *len_out = pt_len;
  return VAULT_OK;
}

int vault_delete_file(const uint8_t file_id[VAULT_ID_LEN]) {
  if (!g_vault.is_open)
    return VAULT_ERR_NOT_OPEN;
  if (!file_id)
    return VAULT_ERR_INVALID_PARAM;

  int found_idx = -1;
  for (uint32_t i = 0; i < g_vault.entry_count; i++) {
    if (memcmp(g_vault.entries[i].file_id, file_id, VAULT_ID_LEN) == 0) {
      found_idx = (int)i;
      break;
    }
  }
  if (found_idx < 0)
    return VAULT_ERR_NOT_FOUND;

  // PERFORMANCE OPTIMIZATION: Soft delete - remove from index only
  // Data blob remains orphaned (will be reclaimed by vault_compact)
  // This is O(1) instead of O(n)

  uint32_t new_count = g_vault.entry_count - 1;

  // Free the entry being deleted
  vault_free_entry(&g_vault.entries[found_idx]);

  // Shift remaining entries down
  if ((uint32_t)found_idx < new_count) {
    memmove(&g_vault.entries[found_idx], &g_vault.entries[found_idx + 1],
            (new_count - found_idx) * sizeof(vault_entry_t));
  }

  // Update count
  g_vault.entry_count = new_count;

  // Resize array if needed (optional, can skip for performance)
  if (new_count > 0) {
    vault_entry_t *resized =
        realloc(g_vault.entries, new_count * sizeof(vault_entry_t));
    if (resized) {
      g_vault.entries = resized;
    }
    // If realloc fails, we still have valid data, just wasted space
  } else {
    free(g_vault.entries);
    g_vault.entries = NULL;
  }

  // Save only index section - doesn't load any payloads
  int result = vault_save_index_only();
  if (result != VAULT_OK) {
    LOGE("vault_delete_file: vault_save_index_only failed with %d", result);
  }

  return result;
}

int vault_rename_file(const uint8_t file_id[VAULT_ID_LEN],
                      const char *new_name) {
  if (!g_vault.is_open)
    return VAULT_ERR_NOT_OPEN;
  if (!file_id || !new_name)
    return VAULT_ERR_INVALID_PARAM;

  size_t name_len = strlen(new_name);
  if (name_len == 0 || name_len > 4096)
    return VAULT_ERR_INVALID_PARAM;
  const int new_is_system = is_allowed_system_name(new_name);
  if (strncmp(new_name, "__", 2) == 0 && !new_is_system) {
    return VAULT_ERR_INVALID_PARAM;
  }

  int found_idx = -1;
  for (uint32_t i = 0; i < g_vault.entry_count; i++) {
    if (memcmp(g_vault.entries[i].file_id, file_id, VAULT_ID_LEN) == 0) {
      found_idx = (int)i;
      break;
    }
  }
  if (found_idx < 0)
    return VAULT_ERR_NOT_FOUND;

  const char *current_name = g_vault.entries[found_idx].name;
  const int current_is_system = is_allowed_system_name(current_name);
  if (current_name && strncmp(current_name, "__", 2) == 0) {
    if (!current_is_system || !new_is_system) {
      return VAULT_ERR_INVALID_PARAM;
    }
  } else if (new_is_system) {
    return VAULT_ERR_INVALID_PARAM;
  }

  // PERFORMANCE OPTIMIZATION: Update name in-place, then save index only
  // No need to load all payloads - O(1) instead of O(n)
  char *new_name_copy = strdup(new_name);
  if (!new_name_copy) {
    return VAULT_ERR_MEMORY;
  }

  // Securely zeroize and free old name
  if (g_vault.entries[found_idx].name) {
    vault_zeroize(g_vault.entries[found_idx].name,
                  strlen(g_vault.entries[found_idx].name));
    free(g_vault.entries[found_idx].name);
  }
  g_vault.entries[found_idx].name = new_name_copy;

  // Save only index section - doesn't load any payloads
  int result = vault_save_index_only();
  if (result != VAULT_OK) {
    LOGE("vault_rename_file: vault_save_index_only failed with %d", result);
  }

  return result;
}

int vault_list_files(vault_entry_t **entries_out, uint32_t *count_out) {
  if (!g_vault.is_open) {
    return VAULT_ERR_NOT_OPEN;
  }

  if (!entries_out || !count_out) {
    return VAULT_ERR_INVALID_PARAM;
  }

  *entries_out = g_vault.entries;
  *count_out = g_vault.entry_count;

  return VAULT_OK;
}

int vault_compact(void) {
  if (!g_vault.is_open)
    return VAULT_ERR_NOT_OPEN;
  if (g_vault.total_size == 0)
    return VAULT_OK;

  uint64_t used_space = compute_used_space();
  if (used_space == 0 || g_vault.total_size == 0) {
    return VAULT_OK;
  }

  uint64_t free_space =
      (g_vault.total_size > used_space) ? (g_vault.total_size - used_space) : 0;
  if (free_space * 100 < g_vault.total_size * 25) {
    LOGI("Compaction not needed (free space %llu bytes)",
         (unsigned long long)free_space);
    return VAULT_OK;
  }

  // Repack container with current entries
  vault_entry_t *cloned_entries = NULL;
  int result =
      clone_entries(g_vault.entries, g_vault.entry_count, &cloned_entries);
  if (result != VAULT_OK) {
    return result;
  }

  vault_payload_t *payloads =
      calloc(g_vault.entry_count, sizeof(vault_payload_t));
  if (!payloads) {
    free_entries_array(cloned_entries, g_vault.entry_count);
    return VAULT_ERR_MEMORY;
  }

  result =
      load_payloads_for_entries(g_vault.entries, g_vault.entry_count, payloads);
  if (result != VAULT_OK) {
    free_entries_array(cloned_entries, g_vault.entry_count);
    free_payloads(payloads, g_vault.entry_count);
    return result;
  }

  result = rebuild_container(cloned_entries, payloads, g_vault.entry_count);
  free_payloads(payloads, g_vault.entry_count);

  if (result != VAULT_OK) {
    free_entries_array(cloned_entries, g_vault.entry_count);
  }
  return result;
}

int vault_get_stats(uint64_t *total_size_out, uint64_t *free_space_out) {
  if (!g_vault.is_open) {
    return VAULT_ERR_NOT_OPEN;
  }

  if (total_size_out) {
    *total_size_out = g_vault.total_size;
  }
  if (free_space_out) {
    *free_space_out = g_vault.free_space;
  }

  return VAULT_OK;
}

// ========================================================================
// Helpers
// ========================================================================

static void clear_entry_allocations(vault_entry_t *entry) {
  if (!entry)
    return;
  if (entry->name) {
    free(entry->name);
    entry->name = NULL;
  }
  if (entry->mime) {
    free(entry->mime);
    entry->mime = NULL;
  }
  if (entry->wrapped_dek) {
    vault_zeroize(entry->wrapped_dek, entry->wrapped_dek_len);
    free(entry->wrapped_dek);
    entry->wrapped_dek = NULL;
    entry->wrapped_dek_len = 0;
  }
  if (entry->chunks) {
    free(entry->chunks);
    entry->chunks = NULL;
  }
  entry->chunk_count = 0;
}

void free_entries_array(vault_entry_t *entries, uint32_t count) {
  if (!entries)
    return;
  for (uint32_t i = 0; i < count; i++) {
    vault_free_entry(&entries[i]);
  }
  free(entries);
}

static void free_payload(vault_payload_t *payload) {
  if (!payload)
    return;
  if (payload->data) {
    vault_zeroize(payload->data, payload->data_len);
    free(payload->data);
  }
  if (payload->chunks) {
    for (uint32_t i = 0; i < payload->chunk_count; i++) {
      if (payload->chunks[i]) {
        vault_zeroize(payload->chunks[i], payload->chunk_lens[i]);
        free(payload->chunks[i]);
      }
    }
    free(payload->chunks);
  }
  if (payload->chunk_lens) {
    free(payload->chunk_lens);
  }
  memset(payload, 0, sizeof(*payload));
}

void free_payloads(vault_payload_t *payloads, uint32_t count) {
  if (!payloads)
    return;
  for (uint32_t i = 0; i < count; i++) {
    free_payload(&payloads[i]);
  }
  free(payloads);
}

int clone_entries(const vault_entry_t *source, uint32_t count,
                  vault_entry_t **dest_out) {
  if (count == 0) {
    *dest_out = NULL;
    return VAULT_OK;
  }

  vault_entry_t *dest = calloc(count, sizeof(vault_entry_t));
  if (!dest)
    return VAULT_ERR_MEMORY;

  for (uint32_t i = 0; i < count; i++) {
    const vault_entry_t *src = &source[i];
    vault_entry_t *dst = &dest[i];

    memcpy(dst->file_id, src->file_id, VAULT_ID_LEN);
    dst->type = src->type;
    dst->created_at = src->created_at;
    dst->size = src->size;
    dst->data_offset = src->data_offset;
    dst->data_length = src->data_length;
    dst->chunk_count = src->chunk_count;

    dst->name = src->name ? strdup(src->name) : strdup("");
    dst->mime = src->mime ? strdup(src->mime) : strdup("");
    if (!dst->name || !dst->mime) {
      free_entries_array(dest, count);
      return VAULT_ERR_MEMORY;
    }

    if (src->wrapped_dek_len > 0) {
      dst->wrapped_dek = malloc(src->wrapped_dek_len);
      if (!dst->wrapped_dek) {
        free_entries_array(dest, count);
        return VAULT_ERR_MEMORY;
      }
      memcpy(dst->wrapped_dek, src->wrapped_dek, src->wrapped_dek_len);
      dst->wrapped_dek_len = src->wrapped_dek_len;
    }

    // FIX: Use chunk_count > 0 to determine if entry has chunks
    // Streaming import stores all large files as chunked, regardless of type
    if (src->chunk_count > 0) {
      dst->chunks = calloc(src->chunk_count, sizeof(dst->chunks[0]));
      if (!dst->chunks) {
        free_entries_array(dest, count);
        return VAULT_ERR_MEMORY;
      }
      for (uint32_t c = 0; c < src->chunk_count; c++) {
        dst->chunks[c].offset = src->chunks[c].offset;
        dst->chunks[c].length = src->chunks[c].length;
        memcpy(dst->chunks[c].nonce, src->chunks[c].nonce, VAULT_NONCE_LEN);
      }
    }
  }

  *dest_out = dest;
  return VAULT_OK;
}

int load_payloads_for_entries(const vault_entry_t *entries, uint32_t count,
                              vault_payload_t *payloads) {
  if (!entries || !payloads)
    return VAULT_ERR_INVALID_PARAM;

  int fd = open(g_vault.path, O_RDONLY);
  if (fd < 0) {
    return VAULT_ERR_IO;
  }

  for (uint32_t i = 0; i < count; i++) {
    const vault_entry_t *entry = &entries[i];
    vault_payload_t *payload = &payloads[i];

    // FIX: Check chunk_count > 0 instead of just type == VIDEO
    // Streaming import stores all large files as chunked, regardless of type
    if (entry->chunk_count > 0) {
      payload->chunk_count = entry->chunk_count;
      payload->chunk_lens = calloc(entry->chunk_count, sizeof(size_t));
      payload->chunks = calloc(entry->chunk_count, sizeof(uint8_t *));
      if (!payload->chunk_lens || !payload->chunks) {
        close(fd);
        return VAULT_ERR_MEMORY;
      }

      for (uint32_t c = 0; c < entry->chunk_count; c++) {
        uint64_t len = entry->chunks[c].length;
        if (len == 0) {
          close(fd);
          return VAULT_ERR_CORRUPTED;
        }
        uint8_t *buf = malloc(len);
        if (!buf) {
          close(fd);
          return VAULT_ERR_MEMORY;
        }
        ssize_t read_len = pread(fd, buf, len, entry->chunks[c].offset);
        if (read_len != (ssize_t)len) {
          vault_zeroize(buf, len);
          free(buf);
          close(fd);
          return VAULT_ERR_IO;
        }
        payload->chunks[c] = buf;
        payload->chunk_lens[c] = len;
      }
    } else {
      if (entry->data_length == 0) {
        close(fd);
        return VAULT_ERR_CORRUPTED;
      }
      payload->data_len = entry->data_length;
      payload->data = malloc(entry->data_length);
      if (!payload->data) {
        close(fd);
        return VAULT_ERR_MEMORY;
      }
      ssize_t read_len =
          pread(fd, payload->data, entry->data_length, entry->data_offset);
      if (read_len != (ssize_t)entry->data_length) {
        vault_zeroize(payload->data, entry->data_length);
        free(payload->data);
        payload->data = NULL;
        close(fd);
        return VAULT_ERR_IO;
      }
    }
  }

  close(fd);
  return VAULT_OK;
}

static int build_text_image_entry(const uint8_t *data, size_t len, uint8_t type,
                                  const char *name, const char *mime,
                                  vault_entry_t *entry_out,
                                  vault_payload_t *payload_out) {
  if (!data || !entry_out || !payload_out)
    return VAULT_ERR_INVALID_PARAM;

  uint8_t dek[VAULT_KEY_LEN];
  vault_random_bytes(dek, VAULT_KEY_LEN);

  vault_generate_id(entry_out->file_id);
  entry_out->type = type;
  entry_out->created_at = get_timestamp_ms();
  entry_out->name = strdup(name);
  entry_out->mime = mime ? strdup(mime) : strdup("");
  entry_out->size = len;

  if (!entry_out->name || !entry_out->mime) {
    vault_zeroize(dek, VAULT_KEY_LEN);
    clear_entry_allocations(entry_out);
    return VAULT_ERR_MEMORY;
  }

  // Wrap DEK
  uint8_t dek_nonce[VAULT_NONCE_LEN];
  uint8_t *wrapped_dek =
      malloc(VAULT_NONCE_LEN + VAULT_KEY_LEN + VAULT_TAG_LEN);
  if (!wrapped_dek) {
    vault_zeroize(dek, VAULT_KEY_LEN);
    clear_entry_allocations(entry_out);
    return VAULT_ERR_MEMORY;
  }
  vault_aad_t aad = {0};
  memcpy(aad.vault_id, g_vault.vault_id, VAULT_ID_LEN);
  memcpy(aad.file_id, entry_out->file_id, VAULT_ID_LEN);
  aad.chunk_index = 0;
  aad.format_version = VAULT_VERSION;

  int result = vault_aead_encrypt(g_vault.master_key, NULL, (uint8_t *)&aad,
                                  sizeof(aad), dek, VAULT_KEY_LEN,
                                  wrapped_dek + VAULT_NONCE_LEN, dek_nonce);
  if (result != VAULT_OK) {
    vault_zeroize(dek, VAULT_KEY_LEN);
    free(wrapped_dek);
    clear_entry_allocations(entry_out);
    return result;
  }
  memcpy(wrapped_dek, dek_nonce, VAULT_NONCE_LEN);
  entry_out->wrapped_dek = wrapped_dek;
  entry_out->wrapped_dek_len = VAULT_NONCE_LEN + VAULT_KEY_LEN + VAULT_TAG_LEN;

  // Encrypt content
  size_t ct_len = len + VAULT_TAG_LEN;
  size_t blob_len = VAULT_NONCE_LEN + ct_len;
  uint8_t *blob = malloc(blob_len);
  if (!blob) {
    vault_zeroize(dek, VAULT_KEY_LEN);
    clear_entry_allocations(entry_out);
    return VAULT_ERR_MEMORY;
  }

  uint8_t content_nonce[VAULT_NONCE_LEN];
  result = vault_aead_encrypt(dek, NULL, (uint8_t *)&aad, sizeof(aad), data,
                              len, blob + VAULT_NONCE_LEN, content_nonce);
  if (result != VAULT_OK) {
    vault_zeroize(dek, VAULT_KEY_LEN);
    vault_zeroize(blob, blob_len);
    free(blob);
    clear_entry_allocations(entry_out);
    return result;
  }
  memcpy(blob, content_nonce, VAULT_NONCE_LEN);

  payload_out->data = blob;
  payload_out->data_len = blob_len;

  vault_zeroize(dek, VAULT_KEY_LEN);
  return VAULT_OK;
}

static int build_video_entry(const uint8_t *data, size_t len, const char *name,
                             const char *mime, vault_entry_t *entry_out,
                             vault_payload_t *payload_out) {
  if (!data || !entry_out || !payload_out)
    return VAULT_ERR_INVALID_PARAM;

  uint8_t dek[VAULT_KEY_LEN];
  vault_random_bytes(dek, VAULT_KEY_LEN);

  vault_generate_id(entry_out->file_id);
  entry_out->type = VAULT_FILE_TYPE_VIDEO;
  entry_out->created_at = get_timestamp_ms();
  entry_out->name = strdup(name);
  entry_out->mime = mime ? strdup(mime) : strdup("video/mp4");
  entry_out->size = len;

  if (!entry_out->name || !entry_out->mime) {
    vault_zeroize(dek, VAULT_KEY_LEN);
    clear_entry_allocations(entry_out);
    return VAULT_ERR_MEMORY;
  }

  // Wrap DEK
  uint8_t dek_nonce[VAULT_NONCE_LEN];
  uint8_t *wrapped_dek =
      malloc(VAULT_NONCE_LEN + VAULT_KEY_LEN + VAULT_TAG_LEN);
  if (!wrapped_dek) {
    vault_zeroize(dek, VAULT_KEY_LEN);
    clear_entry_allocations(entry_out);
    return VAULT_ERR_MEMORY;
  }

  vault_aad_t aad_base = {0};
  memcpy(aad_base.vault_id, g_vault.vault_id, VAULT_ID_LEN);
  memcpy(aad_base.file_id, entry_out->file_id, VAULT_ID_LEN);
  aad_base.format_version = VAULT_VERSION;

  int result = vault_aead_encrypt(
      g_vault.master_key, NULL, (uint8_t *)&aad_base, sizeof(aad_base), dek,
      VAULT_KEY_LEN, wrapped_dek + VAULT_NONCE_LEN, dek_nonce);
  if (result != VAULT_OK) {
    vault_zeroize(dek, VAULT_KEY_LEN);
    free(wrapped_dek);
    clear_entry_allocations(entry_out);
    return result;
  }
  memcpy(wrapped_dek, dek_nonce, VAULT_NONCE_LEN);
  entry_out->wrapped_dek = wrapped_dek;
  entry_out->wrapped_dek_len = VAULT_NONCE_LEN + VAULT_KEY_LEN + VAULT_TAG_LEN;

  // Chunk encryption
  uint32_t chunk_count = (len + VAULT_CHUNK_SIZE - 1) / VAULT_CHUNK_SIZE;
  entry_out->chunk_count = chunk_count;
  entry_out->chunks = calloc(chunk_count, sizeof(entry_out->chunks[0]));
  payload_out->chunks = calloc(chunk_count, sizeof(uint8_t *));
  payload_out->chunk_lens = calloc(chunk_count, sizeof(size_t));
  if (!entry_out->chunks || !payload_out->chunks || !payload_out->chunk_lens) {
    vault_zeroize(dek, VAULT_KEY_LEN);
    result = VAULT_ERR_MEMORY;
    goto error;
  }
  payload_out->chunk_count = chunk_count;

  size_t offset = 0;
  for (uint32_t i = 0; i < chunk_count; i++) {
    size_t chunk_pt_len =
        (i == chunk_count - 1) ? (len - offset) : VAULT_CHUNK_SIZE;
    size_t chunk_ct_len = chunk_pt_len + VAULT_TAG_LEN;

    uint8_t *chunk_buf = malloc(chunk_ct_len);
    if (!chunk_buf) {
      vault_zeroize(dek, VAULT_KEY_LEN);
      result = VAULT_ERR_MEMORY;
      goto error;
    }

    vault_aad_t aad = aad_base;
    aad.chunk_index = i;

    uint8_t chunk_nonce[VAULT_NONCE_LEN];
    result =
        vault_aead_encrypt(dek, NULL, (uint8_t *)&aad, sizeof(aad),
                           data + offset, chunk_pt_len, chunk_buf, chunk_nonce);
    if (result != VAULT_OK) {
      vault_zeroize(dek, VAULT_KEY_LEN);
      vault_zeroize(chunk_buf, chunk_ct_len);
      free(chunk_buf);
      goto error;
    }

    memcpy(entry_out->chunks[i].nonce, chunk_nonce, VAULT_NONCE_LEN);
    entry_out->chunks[i].length = (uint32_t)chunk_ct_len;
    payload_out->chunks[i] = chunk_buf;
    payload_out->chunk_lens[i] = chunk_ct_len;

    offset += chunk_pt_len;
  }

  vault_zeroize(dek, VAULT_KEY_LEN);
  return VAULT_OK;

error:
  clear_entry_allocations(entry_out);
  free_payload(payload_out);
  vault_zeroize(dek, VAULT_KEY_LEN);
  return result;
}

static int rebuild_container(vault_entry_t *entries, vault_payload_t *payloads,
                             uint32_t count) {
  int result = vault_save_container(entries, payloads, count);
  if (result != VAULT_OK) {
    return result;
  }

  // Replace in-memory entries
  if (g_vault.entries) {
    for (uint32_t i = 0; i < g_vault.entry_count; i++) {
      vault_free_entry(&g_vault.entries[i]);
    }
    free(g_vault.entries);
  }
  g_vault.entries = entries;
  g_vault.entry_count = count;
  return VAULT_OK;
}

static int unwrap_dek(const vault_entry_t *entry,
                      uint8_t dek_out[VAULT_KEY_LEN]) {
  if (!entry || !entry->wrapped_dek ||
      entry->wrapped_dek_len < VAULT_NONCE_LEN + VAULT_TAG_LEN) {
    return VAULT_ERR_CORRUPTED;
  }
  vault_aad_t aad = {0};
  memcpy(aad.vault_id, g_vault.vault_id, VAULT_ID_LEN);
  memcpy(aad.file_id, entry->file_id, VAULT_ID_LEN);
  aad.chunk_index = 0;
  aad.format_version = VAULT_VERSION;

  uint8_t *dek_nonce = entry->wrapped_dek;
  uint8_t *dek_ct = entry->wrapped_dek + VAULT_NONCE_LEN;
  size_t dek_ct_len = entry->wrapped_dek_len - VAULT_NONCE_LEN;
  size_t dek_len = 0;

  return vault_aead_decrypt(g_vault.master_key, dek_nonce, (uint8_t *)&aad,
                            sizeof(aad), dek_ct, dek_ct_len, dek_out, &dek_len);
}

static int load_blob(uint64_t offset, uint64_t length, uint8_t **out) {
  if (length == 0 || !out)
    return VAULT_ERR_INVALID_PARAM;
  int fd = open(g_vault.path, O_RDONLY);
  if (fd < 0) {
    return VAULT_ERR_IO;
  }

  uint8_t *buf = malloc(length);
  if (!buf) {
    close(fd);
    return VAULT_ERR_MEMORY;
  }

  ssize_t read_len = pread(fd, buf, length, offset);
  close(fd);
  if (read_len != (ssize_t)length) {
    vault_zeroize(buf, length);
    free(buf);
    return VAULT_ERR_IO;
  }

  *out = buf;
  return VAULT_OK;
}

static uint64_t compute_used_space(void) {
  uint64_t max_offset = 0;
  for (uint32_t i = 0; i < g_vault.entry_count; i++) {
    const vault_entry_t *entry = &g_vault.entries[i];
    // FIX: Use chunk_count > 0 to determine if entry has chunks
    if (entry->chunk_count > 0) {
      for (uint32_t c = 0; c < entry->chunk_count; c++) {
        uint64_t end = entry->chunks[c].offset + entry->chunks[c].length;
        if (end > max_offset)
          max_offset = end;
      }
    } else {
      uint64_t end = entry->data_offset + entry->data_length;
      if (end > max_offset)
        max_offset = end;
    }
  }
  return max_offset;
}
