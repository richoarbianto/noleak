/**
 * NoLeak Vault Engine - Container Operations
 *
 * Handles vault file format:
 * - Header (plaintext metadata + wrapped MK)
 * - Encrypted Index
 * - Encrypted Data Section
 */

#include "vault_engine.h"
#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOG_TAG "VaultContainer"

// SECURITY: Disable logging in release builds
#ifdef NDEBUG
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

// Forward declarations
static int read_index(int fd, const uint8_t mk[VAULT_KEY_LEN]);
static uint32_t calculate_crc32(const uint8_t *data, size_t len);
static size_t header_total_size(const void *header);
static int calculate_index_plaintext_size(const vault_entry_t *entries,
                                          uint32_t count, size_t *size_out);
static int serialize_index(const vault_entry_t *entries, uint32_t count,
                           uint8_t **out, size_t *len_out);
static int deserialize_index(const uint8_t *data, size_t len,
                             vault_entry_t **entries_out, uint32_t *count_out);
static void free_entries_array(vault_entry_t *entries, uint32_t count);
static int validate_kdf_params(uint32_t mem_limit, uint32_t iterations,
                               uint32_t parallel);
static int append_integrity_hash(int fd);
static void fsync_parent_dir(const char *path);
static int migrate_journal_to_v1(const char *path, size_t old_header_size,
                                 int has_integrity_hash);
static int migrate_active_to_log(const char *path);
extern int clone_entries(const vault_entry_t *source, uint32_t count,
                         vault_entry_t **dest_out);

// Header structure (binary layout)
#pragma pack(push, 1)
typedef struct {
  char magic[VAULT_MAGIC_LEN];
  uint32_t version;
  uint8_t vault_id[VAULT_ID_LEN];
  uint8_t kdf_salt[VAULT_SALT_LEN];
  uint32_t kdf_mem;
  uint32_t kdf_iter;
  uint32_t kdf_parallel;
  uint32_t wrapped_mk_len;
  // followed by: wrapped_mk[wrapped_mk_len]
  // followed by: header_crc (uint32_t)
} vault_header_t;
#pragma pack(pop)

#define HEADER_BASE_SIZE sizeof(vault_header_t)
#define WRAPPED_MK_SIZE (VAULT_KEY_LEN + VAULT_TAG_LEN + VAULT_NONCE_LEN)
#define WRAPPED_INDEX_KEY_SIZE WRAPPED_MK_SIZE
#define VAULT_JOURNAL_MAGIC "VAULTJ1"
#define VAULT_JOURNAL_SLOT_COUNT 2
#define VAULT_INDEX_PAD_FLAG 0x80000000u
#define VAULT_INDEX_COUNT_MASK 0x7FFFFFFFu
#define VAULT_CONTAINER_V1 1u
#define VAULT_CONTAINER_LOG 2u
#define VAULT_CONTAINER_LOG_LEGACY 3u
#define VAULT_LOG_MAGIC "VAULTL2"
#define VAULT_LOG_VERSION 2u
#define VAULT_LOG_SLOT_COUNT 2u
#define VAULT_ROOT_TAG_LEN 16u

#pragma pack(push, 1)
typedef struct {
  char magic[VAULT_MAGIC_LEN];
  uint32_t version;
  uint32_t slot_size;
  uint32_t slot_count;
  uint32_t flags;
  uint32_t crc;
} vault_journal_super_t;

typedef struct {
  uint32_t seq;
  uint8_t vault_id[VAULT_ID_LEN];
  uint8_t kdf_salt[VAULT_SALT_LEN];
  uint32_t kdf_mem;
  uint32_t kdf_iter;
  uint32_t kdf_parallel;
  uint32_t wrapped_mk_len;
  uint8_t wrapped_mk[WRAPPED_MK_SIZE];
  uint32_t crc;
} vault_journal_slot_t;

typedef struct {
  char magic[VAULT_MAGIC_LEN];
  uint32_t version;
  uint32_t slot_size;
  uint32_t slot_count;
  uint32_t flags;
  uint32_t crc;
} vault_log_super_t;

typedef struct {
  uint64_t seq;
  uint8_t vault_id[VAULT_ID_LEN];
  uint8_t kdf_salt[VAULT_SALT_LEN];
  uint32_t kdf_mem;
  uint32_t kdf_iter;
  uint32_t kdf_parallel;
  uint32_t wrapped_mk_len;
  uint8_t wrapped_mk[WRAPPED_MK_SIZE];
  uint8_t wrapped_index_key[WRAPPED_INDEX_KEY_SIZE];
  uint64_t index_offset;
  uint64_t index_length;
  uint64_t committed_size;
  uint8_t root_tag[VAULT_ROOT_TAG_LEN];
  uint32_t crc;
} vault_log_slot_t;

// Compatibility layout used by the first VAULTL2 builds. Those builds
// encrypted the index directly with the master key and therefore did not
// store a wrapped per-commit index key in the root slot.
typedef struct {
  uint64_t seq;
  uint8_t vault_id[VAULT_ID_LEN];
  uint8_t kdf_salt[VAULT_SALT_LEN];
  uint32_t kdf_mem;
  uint32_t kdf_iter;
  uint32_t kdf_parallel;
  uint32_t wrapped_mk_len;
  uint8_t wrapped_mk[WRAPPED_MK_SIZE];
  uint64_t index_offset;
  uint64_t index_length;
  uint64_t committed_size;
  uint8_t root_tag[VAULT_ROOT_TAG_LEN];
  uint32_t crc;
} vault_log_legacy_slot_t;

typedef struct {
  char domain[VAULT_MAGIC_LEN];
  uint8_t vault_id[VAULT_ID_LEN];
  uint64_t sequence;
} vault_log_index_aad_t;
#pragma pack(pop)

_Static_assert(sizeof(vault_log_legacy_slot_t) == 172,
               "Unexpected legacy VAULTL2 root size");
_Static_assert(sizeof(vault_log_slot_t) == 244,
               "Unexpected current VAULTL2 root size");

static size_t header_total_size(const void *header_ptr) {
  const vault_header_t *header = (const vault_header_t *)header_ptr;
  if (!header)
    return 0;
  return sizeof(vault_header_t) + header->wrapped_mk_len + sizeof(uint32_t);
}

static size_t journal_total_size(const vault_journal_super_t *super) {
  if (!super)
    return 0;
  return sizeof(vault_journal_super_t) +
         (size_t)super->slot_count * (size_t)super->slot_size;
}

static uint32_t journal_super_crc(const vault_journal_super_t *super) {
  return calculate_crc32((const uint8_t *)super,
                         offsetof(vault_journal_super_t, crc));
}

static uint32_t journal_slot_crc(const vault_journal_slot_t *slot) {
  return calculate_crc32((const uint8_t *)slot,
                         offsetof(vault_journal_slot_t, crc));
}

static int journal_read_super(int fd, vault_journal_super_t *super) {
  if (pread(fd, super, sizeof(*super), 0) != sizeof(*super)) {
    return VAULT_ERR_IO;
  }
  if (memcmp(super->magic, VAULT_JOURNAL_MAGIC, VAULT_MAGIC_LEN) != 0 ||
      super->version != VAULT_VERSION ||
      super->slot_count != VAULT_JOURNAL_SLOT_COUNT ||
      super->slot_size != sizeof(vault_journal_slot_t) ||
      super->crc != journal_super_crc(super)) {
    return VAULT_ERR_CORRUPTED;
  }
  return VAULT_OK;
}

static int journal_read_slot(int fd, const vault_journal_super_t *super,
                             uint32_t slot_index,
                             vault_journal_slot_t *slot) {
  if (!super || !slot || slot_index >= super->slot_count)
    return VAULT_ERR_INVALID_PARAM;

  off_t offset = (off_t)sizeof(vault_journal_super_t) +
                 (off_t)slot_index * (off_t)super->slot_size;
  if (pread(fd, slot, sizeof(*slot), offset) != sizeof(*slot)) {
    return VAULT_ERR_IO;
  }
  if (slot->seq == 0) {
    return VAULT_ERR_NOT_FOUND;
  }
  if (slot->wrapped_mk_len != WRAPPED_MK_SIZE ||
      slot->crc != journal_slot_crc(slot)) {
    return VAULT_ERR_CORRUPTED;
  }
  return VAULT_OK;
}

static int journal_select_slot(int fd, const vault_journal_super_t *super,
                               vault_journal_slot_t *slot_out) {
  int found = 0;
  uint32_t best_seq = 0;
  vault_journal_slot_t best_slot;
  memset(&best_slot, 0, sizeof(best_slot));

  for (uint32_t i = 0; i < super->slot_count; i++) {
    vault_journal_slot_t slot;
    if (journal_read_slot(fd, super, i, &slot) != VAULT_OK) {
      continue;
    }
    if (!found || slot.seq > best_seq) {
      found = 1;
      best_seq = slot.seq;
      best_slot = slot;
    }
  }

  if (!found)
    return VAULT_ERR_CORRUPTED;
  *slot_out = best_slot;
  return VAULT_OK;
}

static int read_all_at(int fd, void *buffer, size_t len, uint64_t offset) {
  uint8_t *cursor = (uint8_t *)buffer;
  while (len > 0) {
    ssize_t n = pread(fd, cursor, len, (off_t)offset);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return VAULT_ERR_IO;
    cursor += n;
    len -= (size_t)n;
    offset += (uint64_t)n;
  }
  return VAULT_OK;
}

static int write_all(int fd, const void *buffer, size_t len) {
  const uint8_t *cursor = (const uint8_t *)buffer;
  while (len > 0) {
    ssize_t n = write(fd, cursor, len);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return VAULT_ERR_IO;
    cursor += n;
    len -= (size_t)n;
  }
  return VAULT_OK;
}

static int write_all_at(int fd, const void *buffer, size_t len,
                        uint64_t offset) {
  const uint8_t *cursor = (const uint8_t *)buffer;
  while (len > 0) {
    ssize_t n = pwrite(fd, cursor, len, (off_t)offset);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return VAULT_ERR_IO;
    cursor += n;
    len -= (size_t)n;
    offset += (uint64_t)n;
  }
  return VAULT_OK;
}

static size_t log_header_size(void) {
  return sizeof(vault_log_super_t) +
         VAULT_LOG_SLOT_COUNT * sizeof(vault_log_slot_t);
}

static size_t log_legacy_header_size(void) {
  return sizeof(vault_log_super_t) +
         VAULT_LOG_SLOT_COUNT * sizeof(vault_log_legacy_slot_t);
}

static uint32_t log_super_crc(const vault_log_super_t *super) {
  return calculate_crc32((const uint8_t *)super,
                         offsetof(vault_log_super_t, crc));
}

static uint32_t log_slot_crc(const vault_log_slot_t *slot) {
  return calculate_crc32((const uint8_t *)slot,
                         offsetof(vault_log_slot_t, crc));
}

static uint32_t
log_legacy_slot_crc(const vault_log_legacy_slot_t *slot) {
  return calculate_crc32((const uint8_t *)slot,
                         offsetof(vault_log_legacy_slot_t, crc));
}

static int log_set_root_tag(vault_log_slot_t *slot,
                            const uint8_t master_key[VAULT_KEY_LEN]) {
  if (crypto_generichash(slot->root_tag, sizeof(slot->root_tag),
                         (const uint8_t *)slot,
                         offsetof(vault_log_slot_t, root_tag), master_key,
                         VAULT_KEY_LEN) != 0) {
    return VAULT_ERR_CRYPTO;
  }
  return VAULT_OK;
}

static int log_root_tag_valid(const vault_log_slot_t *slot,
                              const uint8_t master_key[VAULT_KEY_LEN]) {
  uint8_t expected[VAULT_ROOT_TAG_LEN];
  int result = crypto_generichash(
      expected, sizeof(expected), (const uint8_t *)slot,
      offsetof(vault_log_slot_t, root_tag), master_key, VAULT_KEY_LEN);
  if (result != 0)
    return 0;
  result = sodium_memcmp(expected, slot->root_tag, sizeof(expected)) == 0;
  vault_zeroize(expected, sizeof(expected));
  return result;
}

static int log_legacy_root_tag_valid(
    const vault_log_legacy_slot_t *slot,
    const uint8_t master_key[VAULT_KEY_LEN]) {
  uint8_t expected[VAULT_ROOT_TAG_LEN];
  int result = crypto_generichash(
      expected, sizeof(expected), (const uint8_t *)slot,
      offsetof(vault_log_legacy_slot_t, root_tag), master_key, VAULT_KEY_LEN);
  if (result != 0)
    return 0;
  result = sodium_memcmp(expected, slot->root_tag, sizeof(expected)) == 0;
  vault_zeroize(expected, sizeof(expected));
  return result;
}

static int log_read_super(int fd, vault_log_super_t *super) {
  if (read_all_at(fd, super, sizeof(*super), 0) != VAULT_OK)
    return VAULT_ERR_IO;
  if (memcmp(super->magic, VAULT_LOG_MAGIC, VAULT_MAGIC_LEN) != 0 ||
      super->version != VAULT_LOG_VERSION ||
      super->slot_count != VAULT_LOG_SLOT_COUNT ||
      (super->slot_size != sizeof(vault_log_slot_t) &&
       super->slot_size != sizeof(vault_log_legacy_slot_t)) ||
      super->crc != log_super_crc(super)) {
    return VAULT_ERR_CORRUPTED;
  }
  return VAULT_OK;
}

static int log_read_slot(int fd, const vault_log_super_t *super,
                         uint32_t slot_index, uint64_t file_size,
                         vault_log_slot_t *slot) {
  if (!super || !slot || slot_index >= super->slot_count)
    return VAULT_ERR_INVALID_PARAM;
  if (super->slot_size != sizeof(vault_log_slot_t))
    return VAULT_ERR_CORRUPTED;

  uint64_t slot_offset = sizeof(vault_log_super_t) +
                         (uint64_t)slot_index * super->slot_size;
  if (read_all_at(fd, slot, sizeof(*slot), slot_offset) != VAULT_OK)
    return VAULT_ERR_IO;
  if (slot->seq == 0)
    return VAULT_ERR_NOT_FOUND;
  if (slot->wrapped_mk_len != WRAPPED_MK_SIZE ||
      slot->crc != log_slot_crc(slot) ||
      !validate_kdf_params(slot->kdf_mem, slot->kdf_iter,
                           slot->kdf_parallel) ||
      slot->index_offset < log_header_size() ||
      slot->index_length < VAULT_NONCE_LEN + sizeof(uint64_t) + VAULT_TAG_LEN ||
      slot->index_offset > UINT64_MAX - slot->index_length ||
      slot->committed_size != slot->index_offset + slot->index_length ||
      slot->committed_size > file_size) {
    return VAULT_ERR_CORRUPTED;
  }
  return VAULT_OK;
}

static int log_read_legacy_slot(int fd, const vault_log_super_t *super,
                                uint32_t slot_index, uint64_t file_size,
                                vault_log_legacy_slot_t *slot) {
  if (!super || !slot || slot_index >= super->slot_count)
    return VAULT_ERR_INVALID_PARAM;
  if (super->slot_size != sizeof(vault_log_legacy_slot_t))
    return VAULT_ERR_CORRUPTED;

  uint64_t slot_offset = sizeof(vault_log_super_t) +
                         (uint64_t)slot_index * super->slot_size;
  if (read_all_at(fd, slot, sizeof(*slot), slot_offset) != VAULT_OK)
    return VAULT_ERR_IO;
  if (slot->seq == 0)
    return VAULT_ERR_NOT_FOUND;
  if (slot->wrapped_mk_len != WRAPPED_MK_SIZE ||
      slot->crc != log_legacy_slot_crc(slot) ||
      !validate_kdf_params(slot->kdf_mem, slot->kdf_iter,
                           slot->kdf_parallel) ||
      slot->index_offset < log_legacy_header_size() ||
      slot->index_length < VAULT_NONCE_LEN + sizeof(uint64_t) + VAULT_TAG_LEN ||
      slot->index_offset > UINT64_MAX - slot->index_length ||
      slot->committed_size != slot->index_offset + slot->index_length ||
      slot->committed_size > file_size) {
    return VAULT_ERR_CORRUPTED;
  }
  return VAULT_OK;
}

static int log_select_slot(int fd, const vault_log_super_t *super,
                           uint64_t file_size, vault_log_slot_t *slot_out,
                           uint32_t *slot_index_out) {
  int found = 0;
  vault_log_slot_t best;
  uint32_t best_index = 0;
  memset(&best, 0, sizeof(best));

  for (uint32_t i = 0; i < super->slot_count; i++) {
    vault_log_slot_t candidate;
    if (log_read_slot(fd, super, i, file_size, &candidate) != VAULT_OK)
      continue;
    if (!found || candidate.seq > best.seq) {
      found = 1;
      best = candidate;
      best_index = i;
    }
  }

  if (!found)
    return VAULT_ERR_CORRUPTED;
  *slot_out = best;
  if (slot_index_out)
    *slot_index_out = best_index;
  return VAULT_OK;
}

static int log_select_legacy_slot(int fd, const vault_log_super_t *super,
                                  uint64_t file_size,
                                  vault_log_legacy_slot_t *slot_out,
                                  uint32_t *slot_index_out) {
  int found = 0;
  vault_log_legacy_slot_t best;
  uint32_t best_index = 0;
  memset(&best, 0, sizeof(best));

  for (uint32_t i = 0; i < super->slot_count; i++) {
    vault_log_legacy_slot_t candidate;
    if (log_read_legacy_slot(fd, super, i, file_size, &candidate) != VAULT_OK)
      continue;
    if (!found || candidate.seq > best.seq) {
      found = 1;
      best = candidate;
      best_index = i;
    }
  }

  if (!found)
    return VAULT_ERR_CORRUPTED;
  *slot_out = best;
  if (slot_index_out)
    *slot_index_out = best_index;
  return VAULT_OK;
}

static int validate_kdf_params(uint32_t mem_limit, uint32_t iterations,
                               uint32_t parallel) {
  return vault_kdf_params_valid(mem_limit, iterations, parallel);
}

int vault_inspect_kdf_params(const char *path, uint32_t *mem_out,
                             uint32_t *iter_out, uint32_t *parallel_out) {
  if (!path || !mem_out || !iter_out || !parallel_out)
    return VAULT_ERR_INVALID_PARAM;

  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return VAULT_ERR_IO;

  int result = VAULT_OK;
  uint32_t memory = 0;
  uint32_t iterations = 0;
  uint32_t parallelism = 0;
  uint8_t magic[VAULT_MAGIC_LEN];
  struct stat st;

  if (fstat(fd, &st) != 0 || st.st_size <= 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  if (pread(fd, magic, sizeof(magic), 0) != sizeof(magic)) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  if (memcmp(magic, VAULT_LOG_MAGIC, VAULT_MAGIC_LEN) == 0) {
    vault_log_super_t super;
    result = log_read_super(fd, &super);
    if (result != VAULT_OK)
      goto cleanup;
    if (super.slot_size == sizeof(vault_log_legacy_slot_t)) {
      vault_log_legacy_slot_t slot;
      result = log_select_legacy_slot(fd, &super, (uint64_t)st.st_size, &slot,
                                      NULL);
      if (result != VAULT_OK)
        goto cleanup;
      memory = slot.kdf_mem;
      iterations = slot.kdf_iter;
      parallelism = slot.kdf_parallel;
    } else {
      vault_log_slot_t slot;
      result = log_select_slot(fd, &super, (uint64_t)st.st_size, &slot, NULL);
      if (result != VAULT_OK)
        goto cleanup;
      memory = slot.kdf_mem;
      iterations = slot.kdf_iter;
      parallelism = slot.kdf_parallel;
    }
  } else if (memcmp(magic, VAULT_JOURNAL_MAGIC, VAULT_MAGIC_LEN) == 0) {
    vault_journal_super_t super;
    vault_journal_slot_t slot;
    result = journal_read_super(fd, &super);
    if (result != VAULT_OK)
      goto cleanup;
    result = journal_select_slot(fd, &super, &slot);
    if (result != VAULT_OK)
      goto cleanup;
    memory = slot.kdf_mem;
    iterations = slot.kdf_iter;
    parallelism = slot.kdf_parallel;
  } else if (memcmp(magic, VAULT_MAGIC, VAULT_MAGIC_LEN) == 0) {
    vault_header_t header;
    if (pread(fd, &header, sizeof(header), 0) != sizeof(header)) {
      result = VAULT_ERR_IO;
      goto cleanup;
    }
    if (header.version != VAULT_VERSION ||
        header.wrapped_mk_len != WRAPPED_MK_SIZE) {
      result = VAULT_ERR_CORRUPTED;
      goto cleanup;
    }

    uint32_t stored_crc;
    off_t crc_offset = (off_t)sizeof(header) + (off_t)header.wrapped_mk_len;
    if (pread(fd, &stored_crc, sizeof(stored_crc), crc_offset) !=
            sizeof(stored_crc) ||
        stored_crc != calculate_crc32((const uint8_t *)&header,
                                      sizeof(header))) {
      result = VAULT_ERR_CORRUPTED;
      goto cleanup;
    }
    memory = header.kdf_mem;
    iterations = header.kdf_iter;
    parallelism = header.kdf_parallel;
  } else {
    result = VAULT_ERR_CORRUPTED;
    goto cleanup;
  }

  if (!validate_kdf_params(memory, iterations, parallelism)) {
    result = VAULT_ERR_CORRUPTED;
    goto cleanup;
  }

  *mem_out = memory;
  *iter_out = iterations;
  *parallel_out = parallelism;

cleanup:
  close(fd);
  return result;
}

static void fsync_parent_dir(const char *path) {
  if (!path)
    return;
  char *copy = strdup(path);
  if (!copy)
    return;
  char *slash = strrchr(copy, '/');
  if (slash) {
    *slash = '\0';
  } else {
    strcpy(copy, ".");
  }
  int dir_fd = open(copy[0] ? copy : "/", O_RDONLY | O_DIRECTORY);
  if (dir_fd >= 0) {
    fsync(dir_fd);
    close(dir_fd);
  }
  free(copy);
}

static void remove_stale_temp_file(const char *path) {
  if (!path)
    return;
  size_t path_len = strlen(path);
  char *temp_path = malloc(path_len + 5);
  if (!temp_path)
    return;
  snprintf(temp_path, path_len + 5, "%s.tmp", path);
  unlink(temp_path);
  free(temp_path);
}

static int append_integrity_hash(int fd) {
  fsync(fd);
  off_t current_pos = lseek(fd, 0, SEEK_CUR);
  if (current_pos < 0) {
    return VAULT_ERR_IO;
  }
  if (lseek(fd, 0, SEEK_SET) != 0) {
    return VAULT_ERR_IO;
  }

  crypto_hash_sha256_state hash_state;
  crypto_hash_sha256_init(&hash_state);

  uint8_t hash_buffer[64 * 1024];
  uint64_t remaining = (uint64_t)current_pos;
  while (remaining > 0) {
    size_t to_read = remaining > sizeof(hash_buffer) ? sizeof(hash_buffer)
                                                     : (size_t)remaining;
    ssize_t read_len = read(fd, hash_buffer, to_read);
    if (read_len <= 0) {
      return VAULT_ERR_IO;
    }
    crypto_hash_sha256_update(&hash_state, hash_buffer, read_len);
    remaining -= read_len;
  }

  uint8_t file_hash[VAULT_HASH_LEN];
  crypto_hash_sha256_final(&hash_state, file_hash);
  if (lseek(fd, 0, SEEK_END) < 0 ||
      write(fd, file_hash, VAULT_HASH_LEN) != VAULT_HASH_LEN) {
    return VAULT_ERR_IO;
  }
  return VAULT_OK;
}

// Ensure buffer has enough capacity
static int ensure_capacity(uint8_t **buffer, size_t *capacity, size_t needed) {
  if (*capacity >= needed)
    return VAULT_OK;

  size_t new_cap = *capacity == 0 ? needed : *capacity;
  while (new_cap < needed) {
    new_cap *= 2;
  }

  uint8_t *new_buf = realloc(*buffer, new_cap);
  if (!new_buf) {
    return VAULT_ERR_MEMORY;
  }

  *buffer = new_buf;
  *capacity = new_cap;
  return VAULT_OK;
}

// Compute plaintext index size (without encryption overhead)
static int calculate_index_plaintext_size(const vault_entry_t *entries,
                                          uint32_t count, size_t *size_out) {
  if (!size_out)
    return VAULT_ERR_INVALID_PARAM;

  size_t total = sizeof(uint32_t); // entry_count

  for (uint32_t i = 0; i < count; i++) {
    const vault_entry_t *entry = &entries[i];
    size_t name_len = entry->name ? strlen(entry->name) : 0;
    size_t mime_len = entry->mime ? strlen(entry->mime) : 0;

    total += VAULT_ID_LEN;     // file_id
    total += 1;                // type
    total += sizeof(uint64_t); // created_at
    total += sizeof(uint16_t) + name_len;
    total += sizeof(uint16_t) + mime_len;
    total += sizeof(uint64_t); // size
    total += sizeof(uint16_t) + entry->wrapped_dek_len;

    // FIX: Always write chunk_count first, then either chunk data or
    // offset/length This allows deserialize to read chunk_count and decide
    // which format to use
    total += sizeof(uint32_t); // chunk_count (always present)

    if (entry->chunk_count > 0) {
      // Chunked format: chunk data follows
      total += entry->chunk_count *
               (sizeof(uint64_t) + sizeof(uint32_t) + VAULT_NONCE_LEN);
    } else {
      // Non-chunked format: offset/length follows
      total += sizeof(uint64_t) * 2; // data_offset + data_length
    }
  }

  *size_out = total;
  return VAULT_OK;
}

// Serialize entries into plaintext index buffer
static int serialize_index(const vault_entry_t *entries, uint32_t count,
                           uint8_t **out, size_t *len_out) {
  if (!out || !len_out)
    return VAULT_ERR_INVALID_PARAM;

  size_t capacity = 0;
  uint8_t *buffer = NULL;
  size_t offset = 0;

  size_t expected_size;
  int res = calculate_index_plaintext_size(entries, count, &expected_size);
  if (res != VAULT_OK)
    return res;

  res = ensure_capacity(&buffer, &capacity, expected_size);
  if (res != VAULT_OK)
    return res;

  // entry_count
  memcpy(buffer + offset, &count, sizeof(uint32_t));
  offset += sizeof(uint32_t);

  for (uint32_t i = 0; i < count; i++) {
    const vault_entry_t *entry = &entries[i];
    uint16_t name_len = entry->name ? (uint16_t)strlen(entry->name) : 0;
    uint16_t mime_len = entry->mime ? (uint16_t)strlen(entry->mime) : 0;

    memcpy(buffer + offset, entry->file_id, VAULT_ID_LEN);
    offset += VAULT_ID_LEN;

    buffer[offset++] = entry->type;

    memcpy(buffer + offset, &entry->created_at, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    memcpy(buffer + offset, &name_len, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    if (name_len > 0) {
      memcpy(buffer + offset, entry->name, name_len);
      offset += name_len;
    }

    memcpy(buffer + offset, &mime_len, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    if (mime_len > 0) {
      memcpy(buffer + offset, entry->mime, mime_len);
      offset += mime_len;
    }

    memcpy(buffer + offset, &entry->size, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    memcpy(buffer + offset, &entry->wrapped_dek_len, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    if (entry->wrapped_dek_len > 0) {
      memcpy(buffer + offset, entry->wrapped_dek, entry->wrapped_dek_len);
      offset += entry->wrapped_dek_len;
    }

    // FIX: Always write chunk_count first, then either chunk data or
    // offset/length This allows deserialize to read chunk_count and decide
    // which format to use
    memcpy(buffer + offset, &entry->chunk_count, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    if (entry->chunk_count > 0) {
      // Chunked format: write chunk data
      for (uint32_t c = 0; c < entry->chunk_count; c++) {
        memcpy(buffer + offset, &entry->chunks[c].offset, sizeof(uint64_t));
        offset += sizeof(uint64_t);
        memcpy(buffer + offset, &entry->chunks[c].length, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        memcpy(buffer + offset, entry->chunks[c].nonce, VAULT_NONCE_LEN);
        offset += VAULT_NONCE_LEN;
      }
    } else {
      // Non-chunked format: write offset/length
      memcpy(buffer + offset, &entry->data_offset, sizeof(uint64_t));
      offset += sizeof(uint64_t);
      memcpy(buffer + offset, &entry->data_length, sizeof(uint64_t));
      offset += sizeof(uint64_t);
    }
  }

  *out = buffer;
  *len_out = offset;
  return VAULT_OK;
}

// Parse plaintext index into vault entries (caller owns returned entries)
static int deserialize_index(const uint8_t *data, size_t len,
                             vault_entry_t **entries_out, uint32_t *count_out) {
  if (!data || !entries_out || !count_out)
    return VAULT_ERR_INVALID_PARAM;
  if (len < sizeof(uint32_t))
    return VAULT_ERR_CORRUPTED;

  size_t offset = 0;
  uint32_t count_field = 0;
  memcpy(&count_field, data + offset, sizeof(uint32_t));
  uint32_t count = count_field & VAULT_INDEX_COUNT_MASK;
  offset += sizeof(uint32_t);

  if (count > 1000000) {
    return VAULT_ERR_CORRUPTED;
  }

  vault_entry_t *entries = count ? calloc(count, sizeof(vault_entry_t)) : NULL;
  if (count && !entries)
    return VAULT_ERR_MEMORY;

  for (uint32_t i = 0; i < count; i++) {
    if (offset + VAULT_ID_LEN + 1 + sizeof(uint64_t) > len) {
      free_entries_array(entries, i);
      return VAULT_ERR_CORRUPTED;
    }

    vault_entry_t *entry = &entries[i];
    memcpy(entry->file_id, data + offset, VAULT_ID_LEN);
    offset += VAULT_ID_LEN;

    entry->type = data[offset++];

    memcpy(&entry->created_at, data + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    if (offset + sizeof(uint16_t) > len) {
      free_entries_array(entries, i + 1);
      return VAULT_ERR_CORRUPTED;
    }
    uint16_t name_len;
    memcpy(&name_len, data + offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    if (name_len > 0) {
      if (offset + name_len > len || name_len > 4096) {
        free_entries_array(entries, i + 1);
        return VAULT_ERR_CORRUPTED;
      }
      entry->name = calloc(name_len + 1, 1);
      if (!entry->name) {
        free_entries_array(entries, i + 1);
        return VAULT_ERR_MEMORY;
      }
      memcpy(entry->name, data + offset, name_len);
      offset += name_len;
    } else {
      entry->name = strdup("");
    }

    if (offset + sizeof(uint16_t) > len) {
      free_entries_array(entries, i + 1);
      return VAULT_ERR_CORRUPTED;
    }
    uint16_t mime_len;
    memcpy(&mime_len, data + offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    if (mime_len > 0) {
      if (offset + mime_len > len || mime_len > 512) {
        free_entries_array(entries, i + 1);
        return VAULT_ERR_CORRUPTED;
      }
      entry->mime = calloc(mime_len + 1, 1);
      if (!entry->mime) {
        free_entries_array(entries, i + 1);
        return VAULT_ERR_MEMORY;
      }
      memcpy(entry->mime, data + offset, mime_len);
      offset += mime_len;
    } else {
      entry->mime = strdup("");
    }

    if (offset + sizeof(uint64_t) > len) {
      free_entries_array(entries, i + 1);
      return VAULT_ERR_CORRUPTED;
    }
    memcpy(&entry->size, data + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    if (offset + sizeof(uint16_t) > len) {
      free_entries_array(entries, i + 1);
      return VAULT_ERR_CORRUPTED;
    }
    memcpy(&entry->wrapped_dek_len, data + offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    if (entry->wrapped_dek_len > 0) {
      if (offset + entry->wrapped_dek_len > len ||
          entry->wrapped_dek_len > 512) {
        free_entries_array(entries, i + 1);
        return VAULT_ERR_CORRUPTED;
      }
      entry->wrapped_dek = malloc(entry->wrapped_dek_len);
      if (!entry->wrapped_dek) {
        free_entries_array(entries, i + 1);
        return VAULT_ERR_MEMORY;
      }
      memcpy(entry->wrapped_dek, data + offset, entry->wrapped_dek_len);
      offset += entry->wrapped_dek_len;
    }

    // FIX: Read chunk_count first (always present in new format)
    // Then decide whether to read chunk data or offset/length based on its
    // value
    if (offset + sizeof(uint32_t) > len) {
      free_entries_array(entries, i + 1);
      return VAULT_ERR_CORRUPTED;
    }
    memcpy(&entry->chunk_count, data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    if (entry->chunk_count > 0) {
      // Chunked format: read chunk data
      entry->chunks = calloc(entry->chunk_count, sizeof(entry->chunks[0]));
      if (!entry->chunks) {
        free_entries_array(entries, i + 1);
        return VAULT_ERR_MEMORY;
      }

      for (uint32_t c = 0; c < entry->chunk_count; c++) {
        if (offset + sizeof(uint64_t) + sizeof(uint32_t) + VAULT_NONCE_LEN >
            len) {
          free_entries_array(entries, i + 1);
          return VAULT_ERR_CORRUPTED;
        }
        memcpy(&entry->chunks[c].offset, data + offset, sizeof(uint64_t));
        offset += sizeof(uint64_t);
        memcpy(&entry->chunks[c].length, data + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        memcpy(entry->chunks[c].nonce, data + offset, VAULT_NONCE_LEN);
        offset += VAULT_NONCE_LEN;
      }
    } else {
      // Non-chunked format: read offset/length
      if (offset + sizeof(uint64_t) * 2 > len) {
        free_entries_array(entries, i + 1);
        return VAULT_ERR_CORRUPTED;
      }
      memcpy(&entry->data_offset, data + offset, sizeof(uint64_t));
      offset += sizeof(uint64_t);
      memcpy(&entry->data_length, data + offset, sizeof(uint64_t));
      offset += sizeof(uint64_t);
    }
  }

  *entries_out = entries;
  *count_out = count;
  return VAULT_OK;
}

static void log_index_aad_init(vault_log_index_aad_t *aad,
                               const uint8_t vault_id[VAULT_ID_LEN],
                               uint64_t sequence) {
  memset(aad, 0, sizeof(*aad));
  memcpy(aad->domain, "IDXLOG2", VAULT_MAGIC_LEN);
  memcpy(aad->vault_id, vault_id, VAULT_ID_LEN);
  aad->sequence = sequence;
}

static void log_index_key_aad_init(vault_log_index_aad_t *aad,
                                   const uint8_t vault_id[VAULT_ID_LEN],
                                   uint64_t sequence) {
  memset(aad, 0, sizeof(*aad));
  memcpy(aad->domain, "IDXKEY2", VAULT_MAGIC_LEN);
  memcpy(aad->vault_id, vault_id, VAULT_ID_LEN);
  aad->sequence = sequence;
}

static int log_wrap_index_key(
    const uint8_t master_key[VAULT_KEY_LEN],
    const uint8_t vault_id[VAULT_ID_LEN], uint64_t sequence,
    const uint8_t index_key[VAULT_KEY_LEN],
    uint8_t wrapped_index_key[WRAPPED_INDEX_KEY_SIZE]) {
  vault_log_index_aad_t aad;
  log_index_key_aad_init(&aad, vault_id, sequence);
  return vault_aead_encrypt(
      master_key, NULL, (const uint8_t *)&aad, sizeof(aad), index_key,
      VAULT_KEY_LEN, wrapped_index_key + VAULT_NONCE_LEN, wrapped_index_key);
}

static int log_unwrap_index_key(
    const uint8_t master_key[VAULT_KEY_LEN],
    const uint8_t vault_id[VAULT_ID_LEN], uint64_t sequence,
    const uint8_t wrapped_index_key[WRAPPED_INDEX_KEY_SIZE],
    uint8_t index_key[VAULT_KEY_LEN]) {
  vault_log_index_aad_t aad;
  log_index_key_aad_init(&aad, vault_id, sequence);
  size_t index_key_len = 0;
  int result = vault_aead_decrypt(
      master_key, wrapped_index_key, (const uint8_t *)&aad, sizeof(aad),
      wrapped_index_key + VAULT_NONCE_LEN, VAULT_KEY_LEN + VAULT_TAG_LEN,
      index_key, &index_key_len);
  if (result != VAULT_OK || index_key_len != VAULT_KEY_LEN) {
    vault_zeroize(index_key, VAULT_KEY_LEN);
    return result == VAULT_OK ? VAULT_ERR_CORRUPTED : result;
  }
  return VAULT_OK;
}

static int build_log_index_record(const vault_entry_t *entries,
                                  uint32_t count,
                                  const uint8_t index_key[VAULT_KEY_LEN],
                                  const uint8_t vault_id[VAULT_ID_LEN],
                                  uint64_t sequence, uint8_t **record_out,
                                  size_t *record_len_out) {
  uint8_t *plaintext = NULL;
  uint8_t *record = NULL;
  size_t plaintext_len = 0;
  int result = serialize_index(entries, count, &plaintext, &plaintext_len);
  if (result != VAULT_OK)
    return result;

  size_t ciphertext_len = plaintext_len + VAULT_TAG_LEN;
  size_t record_len = VAULT_NONCE_LEN + sizeof(uint64_t) + ciphertext_len;
  record = malloc(record_len);
  if (!record) {
    result = VAULT_ERR_MEMORY;
    goto cleanup;
  }

  uint64_t ciphertext_len_u64 = ciphertext_len;
  memcpy(record + VAULT_NONCE_LEN, &ciphertext_len_u64,
         sizeof(ciphertext_len_u64));

  vault_log_index_aad_t aad;
  log_index_aad_init(&aad, vault_id, sequence);
  result = vault_aead_encrypt(
      index_key, NULL, (const uint8_t *)&aad, sizeof(aad), plaintext,
      plaintext_len, record + VAULT_NONCE_LEN + sizeof(uint64_t), record);
  if (result != VAULT_OK)
    goto cleanup;

  *record_out = record;
  *record_len_out = record_len;
  record = NULL;

cleanup:
  if (plaintext) {
    vault_zeroize(plaintext, plaintext_len);
    free(plaintext);
  }
  if (record) {
    vault_zeroize(record, record_len);
    free(record);
  }
  return result;
}

static int read_log_index(int fd, const vault_log_slot_t *slot,
                          const uint8_t index_key[VAULT_KEY_LEN]) {
  if (!slot || slot->index_length > 100 * 1024 * 1024 +
                                        VAULT_NONCE_LEN + sizeof(uint64_t) +
                                        VAULT_TAG_LEN) {
    return VAULT_ERR_CORRUPTED;
  }

  size_t record_len = (size_t)slot->index_length;
  uint8_t *record = malloc(record_len);
  if (!record)
    return VAULT_ERR_MEMORY;

  int result = read_all_at(fd, record, record_len, slot->index_offset);
  if (result != VAULT_OK)
    goto cleanup;

  uint64_t ciphertext_len = 0;
  memcpy(&ciphertext_len, record + VAULT_NONCE_LEN, sizeof(ciphertext_len));
  if (ciphertext_len < VAULT_TAG_LEN ||
      ciphertext_len !=
          record_len - VAULT_NONCE_LEN - sizeof(uint64_t)) {
    result = VAULT_ERR_CORRUPTED;
    goto cleanup;
  }

  size_t plaintext_len = (size_t)ciphertext_len - VAULT_TAG_LEN;
  uint8_t *plaintext = malloc(plaintext_len);
  if (!plaintext) {
    result = VAULT_ERR_MEMORY;
    goto cleanup;
  }

  vault_log_index_aad_t aad;
  log_index_aad_init(&aad, slot->vault_id, slot->seq);
  size_t actual_len = 0;
  result = vault_aead_decrypt(
      index_key, record, (const uint8_t *)&aad, sizeof(aad),
      record + VAULT_NONCE_LEN + sizeof(uint64_t), (size_t)ciphertext_len,
      plaintext, &actual_len);
  if (result == VAULT_OK) {
    vault_entry_t *entries = NULL;
    uint32_t count = 0;
    result = deserialize_index(plaintext, actual_len, &entries, &count);
    if (result == VAULT_OK) {
      if (g_vault.entries)
        free_entries_array(g_vault.entries, g_vault.entry_count);
      g_vault.entries = entries;
      g_vault.entry_count = count;
    }
  }

  vault_zeroize(plaintext, plaintext_len);
  free(plaintext);

cleanup:
  vault_zeroize(record, record_len);
  free(record);
  return result;
}

static void log_init_super(vault_log_super_t *super) {
  memset(super, 0, sizeof(*super));
  memcpy(super->magic, VAULT_LOG_MAGIC, VAULT_MAGIC_LEN);
  super->version = VAULT_LOG_VERSION;
  super->slot_size = sizeof(vault_log_slot_t);
  super->slot_count = VAULT_LOG_SLOT_COUNT;
  super->crc = log_super_crc(super);
}

static int log_fill_slot(vault_log_slot_t *slot, uint64_t sequence,
                         const uint8_t vault_id[VAULT_ID_LEN],
                         const uint8_t salt[VAULT_SALT_LEN], uint32_t kdf_mem,
                         uint32_t kdf_iter, uint32_t kdf_parallel,
                         const uint8_t wrapped_mk[WRAPPED_MK_SIZE],
                         const uint8_t wrapped_index_key[WRAPPED_INDEX_KEY_SIZE],
                         uint64_t index_offset, uint64_t index_length,
                         uint64_t committed_size,
                         const uint8_t master_key[VAULT_KEY_LEN]) {
  memset(slot, 0, sizeof(*slot));
  slot->seq = sequence;
  memcpy(slot->vault_id, vault_id, VAULT_ID_LEN);
  memcpy(slot->kdf_salt, salt, VAULT_SALT_LEN);
  slot->kdf_mem = kdf_mem;
  slot->kdf_iter = kdf_iter;
  slot->kdf_parallel = kdf_parallel;
  slot->wrapped_mk_len = WRAPPED_MK_SIZE;
  memcpy(slot->wrapped_mk, wrapped_mk, WRAPPED_MK_SIZE);
  memcpy(slot->wrapped_index_key, wrapped_index_key,
         WRAPPED_INDEX_KEY_SIZE);
  slot->index_offset = index_offset;
  slot->index_length = index_length;
  slot->committed_size = committed_size;
  int result = log_set_root_tag(slot, master_key);
  if (result != VAULT_OK)
    return result;
  slot->crc = log_slot_crc(slot);
  return VAULT_OK;
}

static int log_write_slot(int fd, uint32_t slot_index,
                          const vault_log_slot_t *slot) {
  if (slot_index >= VAULT_LOG_SLOT_COUNT)
    return VAULT_ERR_INVALID_PARAM;
  uint64_t offset = sizeof(vault_log_super_t) +
                    (uint64_t)slot_index * sizeof(vault_log_slot_t);
  return write_all_at(fd, slot, sizeof(*slot), offset);
}

static int log_validate_entry_ranges(const vault_log_slot_t *slot,
                                     size_t minimum_data_offset) {
  for (uint32_t i = 0; i < g_vault.entry_count; i++) {
    const vault_entry_t *entry = &g_vault.entries[i];
    if (entry->chunk_count > 0) {
      for (uint32_t c = 0; c < entry->chunk_count; c++) {
        uint64_t offset = entry->chunks[c].offset;
        uint64_t length = entry->chunks[c].length;
        if (length < VAULT_TAG_LEN || offset < minimum_data_offset ||
            offset > UINT64_MAX - length ||
            offset + length > slot->index_offset) {
          return VAULT_ERR_CORRUPTED;
        }
      }
    } else {
      uint64_t offset = entry->data_offset;
      uint64_t length = entry->data_length;
      if (length < VAULT_NONCE_LEN + VAULT_TAG_LEN ||
          offset < minimum_data_offset || offset > UINT64_MAX - length ||
          offset + length > slot->index_offset) {
        return VAULT_ERR_CORRUPTED;
      }
    }
  }
  return VAULT_OK;
}

static void log_refresh_metrics(void) {
  uint64_t used = log_header_size() + g_vault.index_length;
  for (uint32_t i = 0; i < g_vault.entry_count; i++) {
    const vault_entry_t *entry = &g_vault.entries[i];
    if (entry->chunk_count > 0) {
      for (uint32_t c = 0; c < entry->chunk_count; c++)
        used += entry->chunks[c].length;
    } else {
      used += entry->data_length;
    }
  }
  g_vault.total_size = g_vault.committed_size;
  g_vault.free_space =
      g_vault.committed_size > used ? g_vault.committed_size - used : 0;
}

static void legacy_refresh_metrics(const char *path) {
  struct stat st;
  if (!path || stat(path, &st) != 0)
    return;
  g_vault.total_size = st.st_size > 0 ? (uint64_t)st.st_size : 0;
  uint64_t max_offset = 0;
  for (uint32_t i = 0; i < g_vault.entry_count; i++) {
    const vault_entry_t *entry = &g_vault.entries[i];
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
  g_vault.free_space = g_vault.total_size > max_offset
                           ? g_vault.total_size - max_offset
                           : 0;
}

static void free_entries_array(vault_entry_t *entries, uint32_t count) {
  if (!entries)
    return;
  for (uint32_t i = 0; i < count; i++) {
    vault_free_entry(&entries[i]);
  }
  free(entries);
}

int vault_create(const char *path, const uint8_t *passphrase, size_t pass_len) {
  if (!path || !passphrase)
    return VAULT_ERR_INVALID_PARAM;

  int result = vault_init();
  if (result != VAULT_OK)
    return result;
  if (pass_len < VAULT_MIN_PASSPHRASE_LEN)
    return VAULT_ERR_PASSPHRASE_TOO_SHORT;

  remove_stale_temp_file(path);
  if (access(path, F_OK) == 0)
    return VAULT_ERR_ALREADY_EXISTS;

  char *path_copy = strdup(path);
  if (!path_copy)
    return VAULT_ERR_MEMORY;
  char *last_slash = strrchr(path_copy, '/');
  if (last_slash) {
    *last_slash = '\0';
    struct stat directory;
    if (stat(path_copy, &directory) != 0 &&
        mkdir(path_copy, 0700) != 0 && errno != EEXIST) {
      free(path_copy);
      return VAULT_ERR_IO;
    }
  }
  free(path_copy);

  int fd = -1;
  char *temp_path = NULL;
  uint8_t salt[VAULT_SALT_LEN];
  uint8_t kek[VAULT_KEY_LEN];
  uint8_t master_key[VAULT_KEY_LEN];
  uint8_t wrapped_mk[WRAPPED_MK_SIZE];
  uint8_t index_key[VAULT_KEY_LEN];
  uint8_t wrapped_index_key[WRAPPED_INDEX_KEY_SIZE];
  uint8_t nonce[VAULT_NONCE_LEN];
  uint8_t vault_id[VAULT_ID_LEN];
  uint8_t *index_record = NULL;
  size_t index_record_len = 0;
  memset(kek, 0, sizeof(kek));
  memset(master_key, 0, sizeof(master_key));
  memset(wrapped_mk, 0, sizeof(wrapped_mk));
  memset(index_key, 0, sizeof(index_key));
  memset(wrapped_index_key, 0, sizeof(wrapped_index_key));

  vault_random_bytes(salt, sizeof(salt));
  vault_random_bytes(master_key, sizeof(master_key));
  vault_generate_id(vault_id);

  result = vault_kdf_derive(passphrase, pass_len, salt, kek);
  if (result != VAULT_OK)
    goto cleanup;

  vault_random_bytes(nonce, sizeof(nonce));
  memcpy(wrapped_mk, nonce, sizeof(nonce));
  result = vault_aead_encrypt(
      kek, nonce, vault_id, VAULT_ID_LEN, master_key, VAULT_KEY_LEN,
      wrapped_mk + VAULT_NONCE_LEN, nonce);
  if (result != VAULT_OK)
    goto cleanup;

  size_t kdf_mem_size = 0;
  uint32_t kdf_iter = 0;
  uint32_t kdf_parallel = 0;
  vault_get_kdf_params(&kdf_mem_size, &kdf_iter, &kdf_parallel);
  uint32_t kdf_mem = (uint32_t)kdf_mem_size;

  size_t path_len = strlen(path);
  temp_path = malloc(path_len + 5);
  if (!temp_path) {
    result = VAULT_ERR_MEMORY;
    goto cleanup;
  }
  snprintf(temp_path, path_len + 5, "%s.tmp", path);
  fd = open(temp_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  vault_log_super_t super;
  log_init_super(&super);
  vault_log_slot_t empty_slots[VAULT_LOG_SLOT_COUNT];
  memset(empty_slots, 0, sizeof(empty_slots));
  result = write_all(fd, &super, sizeof(super));
  if (result == VAULT_OK)
    result = write_all(fd, empty_slots, sizeof(empty_slots));
  if (result != VAULT_OK)
    goto cleanup;

  const uint64_t sequence = 1;
  vault_random_bytes(index_key, sizeof(index_key));
  result = log_wrap_index_key(master_key, vault_id, sequence, index_key,
                              wrapped_index_key);
  if (result != VAULT_OK)
    goto cleanup;
  result = build_log_index_record(NULL, 0, index_key, vault_id, sequence,
                                  &index_record, &index_record_len);
  if (result != VAULT_OK)
    goto cleanup;

  uint64_t index_offset = log_header_size();
  result = write_all(fd, index_record, index_record_len);
  if (result != VAULT_OK || fsync(fd) != 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  uint64_t committed_size = index_offset + index_record_len;
  vault_log_slot_t root;
  result = log_fill_slot(&root, sequence, vault_id, salt, kdf_mem, kdf_iter,
                         kdf_parallel, wrapped_mk, wrapped_index_key,
                         index_offset,
                         index_record_len, committed_size, master_key);
  if (result != VAULT_OK)
    goto cleanup;
  result = log_write_slot(fd, 0, &root);
  if (result == VAULT_OK)
    result = log_write_slot(fd, 1, &root);
  if (result != VAULT_OK || fsync(fd) != 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  close(fd);
  fd = -1;
  if (rename(temp_path, path) != 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  fsync_parent_dir(path);
  result = VAULT_OK;

cleanup:
  vault_zeroize(kek, sizeof(kek));
  vault_zeroize(master_key, sizeof(master_key));
  vault_zeroize(wrapped_mk, sizeof(wrapped_mk));
  vault_zeroize(index_key, sizeof(index_key));
  vault_zeroize(wrapped_index_key, sizeof(wrapped_index_key));
  if (index_record) {
    vault_zeroize(index_record, index_record_len);
    free(index_record);
  }
  if (fd >= 0)
    close(fd);
  if (result != VAULT_OK && temp_path)
    unlink(temp_path);
  free(temp_path);
  return result;
}

static int open_log_container(int fd, uint64_t file_size, const char *path,
                              const uint8_t *passphrase, size_t pass_len) {
  vault_log_super_t super;
  vault_log_slot_t slot;
  uint32_t slot_index = 0;
  uint8_t kek[VAULT_KEY_LEN];
  uint8_t index_key[VAULT_KEY_LEN];
  memset(kek, 0, sizeof(kek));
  memset(index_key, 0, sizeof(index_key));

  int result = log_read_super(fd, &super);
  if (result != VAULT_OK)
    goto cleanup;
  if (super.slot_size == sizeof(vault_log_legacy_slot_t)) {
    vault_log_legacy_slot_t legacy_slot;
    result = log_select_legacy_slot(fd, &super, file_size, &legacy_slot,
                                    &slot_index);
    if (result != VAULT_OK)
      goto cleanup;

    result = vault_kdf_derive_with_params(
        passphrase, pass_len, legacy_slot.kdf_salt, legacy_slot.kdf_mem,
        legacy_slot.kdf_iter, kek);
    if (result != VAULT_OK)
      goto cleanup;

    size_t master_key_len = 0;
    result = vault_aead_decrypt(
        kek, legacy_slot.wrapped_mk, legacy_slot.vault_id, VAULT_ID_LEN,
        legacy_slot.wrapped_mk + VAULT_NONCE_LEN,
        VAULT_KEY_LEN + VAULT_TAG_LEN, g_vault.master_key, &master_key_len);
    if (result != VAULT_OK || master_key_len != VAULT_KEY_LEN) {
      result = VAULT_ERR_AUTH_FAIL;
      goto cleanup;
    }
    if (!log_legacy_root_tag_valid(&legacy_slot, g_vault.master_key)) {
      result = VAULT_ERR_CORRUPTED;
      goto cleanup;
    }

    memset(&slot, 0, sizeof(slot));
    slot.seq = legacy_slot.seq;
    memcpy(slot.vault_id, legacy_slot.vault_id, VAULT_ID_LEN);
    memcpy(slot.kdf_salt, legacy_slot.kdf_salt, VAULT_SALT_LEN);
    slot.kdf_mem = legacy_slot.kdf_mem;
    slot.kdf_iter = legacy_slot.kdf_iter;
    slot.kdf_parallel = legacy_slot.kdf_parallel;
    slot.wrapped_mk_len = legacy_slot.wrapped_mk_len;
    memcpy(slot.wrapped_mk, legacy_slot.wrapped_mk, WRAPPED_MK_SIZE);
    slot.index_offset = legacy_slot.index_offset;
    slot.index_length = legacy_slot.index_length;
    slot.committed_size = legacy_slot.committed_size;

    memcpy(g_vault.vault_id, slot.vault_id, VAULT_ID_LEN);
    memcpy(g_vault.salt, slot.kdf_salt, VAULT_SALT_LEN);
    memcpy(g_vault.wrapped_mk, slot.wrapped_mk, WRAPPED_MK_SIZE);
    g_vault.wrapped_mk_len = WRAPPED_MK_SIZE;
    g_vault.kdf_mem = slot.kdf_mem;
    g_vault.kdf_iter = slot.kdf_iter;
    g_vault.kdf_parallel = slot.kdf_parallel;
    g_vault.container_format = VAULT_CONTAINER_LOG_LEGACY;
    g_vault.commit_sequence = slot.seq;
    g_vault.committed_size = slot.committed_size;
    g_vault.index_offset = slot.index_offset;
    g_vault.index_length = slot.index_length;
    g_vault.active_root_slot = slot_index;
    g_vault.path = strdup(path);
    if (!g_vault.path) {
      result = VAULT_ERR_MEMORY;
      goto cleanup;
    }

    // The legacy VAULTL2 index was encrypted directly with the master key.
    result = read_log_index(fd, &slot, g_vault.master_key);
    if (result != VAULT_OK)
      goto cleanup;
    result = log_validate_entry_ranges(&slot, log_legacy_header_size());
    if (result != VAULT_OK)
      goto cleanup;

    g_vault.is_open = 1;
    result = migrate_active_to_log(path);
    if (result != VAULT_OK) {
      LOGE("Legacy VAULTL2 migration failed: %d", result);
      goto cleanup;
    }
    LOGI("Legacy VAULTL2 migrated to protected index-key roots");
    goto cleanup;
  }
  result = log_select_slot(fd, &super, file_size, &slot, &slot_index);
  if (result != VAULT_OK)
    goto cleanup;

  result = vault_kdf_derive_with_params(
      passphrase, pass_len, slot.kdf_salt, slot.kdf_mem, slot.kdf_iter, kek);
  if (result != VAULT_OK)
    goto cleanup;

  size_t master_key_len = 0;
  result = vault_aead_decrypt(
      kek, slot.wrapped_mk, slot.vault_id, VAULT_ID_LEN,
      slot.wrapped_mk + VAULT_NONCE_LEN, VAULT_KEY_LEN + VAULT_TAG_LEN,
      g_vault.master_key, &master_key_len);
  if (result != VAULT_OK || master_key_len != VAULT_KEY_LEN) {
    result = VAULT_ERR_AUTH_FAIL;
    goto cleanup;
  }
  if (!log_root_tag_valid(&slot, g_vault.master_key)) {
    result = VAULT_ERR_CORRUPTED;
    goto cleanup;
  }
  result = log_unwrap_index_key(g_vault.master_key, slot.vault_id, slot.seq,
                                slot.wrapped_index_key, index_key);
  if (result != VAULT_OK) {
    result = VAULT_ERR_CORRUPTED;
    goto cleanup;
  }

  memcpy(g_vault.vault_id, slot.vault_id, VAULT_ID_LEN);
  memcpy(g_vault.salt, slot.kdf_salt, VAULT_SALT_LEN);
  memcpy(g_vault.wrapped_mk, slot.wrapped_mk, WRAPPED_MK_SIZE);
  g_vault.wrapped_mk_len = WRAPPED_MK_SIZE;
  g_vault.kdf_mem = slot.kdf_mem;
  g_vault.kdf_iter = slot.kdf_iter;
  g_vault.kdf_parallel = slot.kdf_parallel;
  g_vault.container_format = VAULT_CONTAINER_LOG;
  g_vault.commit_sequence = slot.seq;
  g_vault.committed_size = slot.committed_size;
  g_vault.index_offset = slot.index_offset;
  g_vault.index_length = slot.index_length;
  g_vault.active_root_slot = slot_index;
  g_vault.path = strdup(path);
  if (!g_vault.path) {
    result = VAULT_ERR_MEMORY;
    goto cleanup;
  }

  result = read_log_index(fd, &slot, index_key);
  if (result != VAULT_OK)
    goto cleanup;
  result = log_validate_entry_ranges(&slot, log_header_size());
  if (result != VAULT_OK)
    goto cleanup;

  uint32_t mirror_slot_index =
      (slot_index + 1) % VAULT_LOG_SLOT_COUNT;
  vault_log_slot_t mirror_slot;
  int needs_root_heal =
      log_read_slot(fd, &super, mirror_slot_index, file_size, &mirror_slot) !=
          VAULT_OK ||
      memcmp(&mirror_slot, &slot, sizeof(slot)) != 0;

  if (file_size > slot.committed_size || needs_root_heal) {
    int write_fd = open(path, O_RDWR);
    if (write_fd < 0) {
      result = VAULT_ERR_IO;
      goto cleanup;
    }
    if (file_size > slot.committed_size &&
        ftruncate(write_fd, (off_t)slot.committed_size) != 0)
      result = VAULT_ERR_IO;
    if (result == VAULT_OK && needs_root_heal)
      result = log_write_slot(write_fd, mirror_slot_index, &slot);
    if (result == VAULT_OK && fsync(write_fd) != 0)
      result = VAULT_ERR_IO;
    close(write_fd);
    if (result != VAULT_OK)
      goto cleanup;
  }

  g_vault.is_open = 1;
  log_refresh_metrics();

cleanup:
  vault_zeroize(kek, sizeof(kek));
  vault_zeroize(index_key, sizeof(index_key));
  if (result != VAULT_OK)
    vault_close();
  return result;
}

int vault_open(const char *path, const uint8_t *passphrase, size_t pass_len) {
  if (!path || !passphrase) {
    return VAULT_ERR_INVALID_PARAM;
  }

  if (g_vault.is_open) {
    vault_close();
  }

  remove_stale_temp_file(path);

  int result = VAULT_OK;
  int fd = -1;
  uint8_t kek[VAULT_KEY_LEN];
  uint8_t wrapped_mk[WRAPPED_MK_SIZE];

  fd = open(path, O_RDONLY);
  if (fd < 0) {
    LOGE("Failed to open vault: %s", path);
    return VAULT_ERR_IO;
  }

  struct stat st;
  if (fstat(fd, &st) != 0) {
    LOGE("Failed to stat vault file");
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  uint8_t file_magic[VAULT_MAGIC_LEN];
  if (read_all_at(fd, file_magic, sizeof(file_magic), 0) != VAULT_OK) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  if (memcmp(file_magic, VAULT_LOG_MAGIC, VAULT_MAGIC_LEN) == 0) {
    result = open_log_container(fd, (uint64_t)st.st_size, path, passphrase,
                                pass_len);
    close(fd);
    return result;
  }

  if (st.st_size <= VAULT_HASH_LEN) {
    result = VAULT_ERR_CORRUPTED;
    goto cleanup;
  }

  int has_integrity_hash = 1;
  uint8_t stored_hash[VAULT_HASH_LEN];
  uint8_t calculated_hash[VAULT_HASH_LEN];
  if (lseek(fd, st.st_size - VAULT_HASH_LEN, SEEK_SET) < 0 ||
      read(fd, stored_hash, VAULT_HASH_LEN) != VAULT_HASH_LEN) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  result = vault_compute_file_hash(fd, (uint64_t)st.st_size, calculated_hash);
  if (result != VAULT_OK) {
    goto cleanup;
  }
  if (sodium_memcmp(stored_hash, calculated_hash, VAULT_HASH_LEN) != 0) {
    uint8_t legacy_magic[VAULT_MAGIC_LEN];
    if (pread(fd, legacy_magic, sizeof(legacy_magic), 0) ==
            sizeof(legacy_magic) &&
        memcmp(legacy_magic, VAULT_JOURNAL_MAGIC, VAULT_MAGIC_LEN) == 0) {
      has_integrity_hash = 0;
    } else {
      LOGE("Container integrity hash mismatch");
      result = VAULT_ERR_CORRUPTED;
      goto cleanup;
    }
  }
  if (lseek(fd, 0, SEEK_SET) != 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  LOGI("Vault file size: %lld bytes", (long long)st.st_size);

  uint8_t header_vault_id[VAULT_ID_LEN];
  uint8_t header_salt[VAULT_SALT_LEN];
  uint32_t header_kdf_mem = 0;
  uint32_t header_kdf_iter = 0;
  uint32_t header_kdf_parallel = 0;
  uint32_t header_wrapped_mk_len = WRAPPED_MK_SIZE;
  size_t header_size = 0;
  int is_journal = 0;

  uint8_t magic[VAULT_MAGIC_LEN];
  if (pread(fd, magic, sizeof(magic), 0) != sizeof(magic)) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  if (memcmp(magic, VAULT_JOURNAL_MAGIC, VAULT_MAGIC_LEN) == 0) {
    vault_journal_super_t super;
    vault_journal_slot_t slot;

    result = journal_read_super(fd, &super);
    if (result != VAULT_OK) {
      goto cleanup;
    }
    result = journal_select_slot(fd, &super, &slot);
    if (result != VAULT_OK) {
      goto cleanup;
    }

    is_journal = 1;
    header_size = journal_total_size(&super);
    memcpy(header_vault_id, slot.vault_id, VAULT_ID_LEN);
    memcpy(header_salt, slot.kdf_salt, VAULT_SALT_LEN);
    header_kdf_mem = slot.kdf_mem;
    header_kdf_iter = slot.kdf_iter;
    header_kdf_parallel = slot.kdf_parallel;
    header_wrapped_mk_len = slot.wrapped_mk_len;
    memcpy(wrapped_mk, slot.wrapped_mk, WRAPPED_MK_SIZE);
  } else if (memcmp(magic, VAULT_MAGIC, VAULT_MAGIC_LEN) == 0) {
    vault_header_t header;
    if (pread(fd, &header, sizeof(header), 0) != sizeof(header)) {
      result = VAULT_ERR_IO;
      goto cleanup;
    }

    // Verify version
    if (header.version != VAULT_VERSION) {
      LOGE("Unsupported vault version: %u", header.version);
      result = VAULT_ERR_CORRUPTED;
      goto cleanup;
    }

    // Read wrapped MK
    if (header.wrapped_mk_len != WRAPPED_MK_SIZE) {
      result = VAULT_ERR_CORRUPTED;
      goto cleanup;
    }

    if (pread(fd, wrapped_mk, WRAPPED_MK_SIZE, sizeof(header)) !=
        WRAPPED_MK_SIZE) {
      result = VAULT_ERR_IO;
      goto cleanup;
    }

    // Read and verify CRC
    uint32_t stored_crc, calculated_crc;
    off_t crc_offset = (off_t)sizeof(header) + (off_t)header.wrapped_mk_len;
    if (pread(fd, &stored_crc, sizeof(stored_crc), crc_offset) !=
        sizeof(stored_crc)) {
      result = VAULT_ERR_IO;
      goto cleanup;
    }

    calculated_crc = calculate_crc32((uint8_t *)&header, sizeof(header));
    if (stored_crc != calculated_crc) {
      LOGE("Header CRC mismatch");
      result = VAULT_ERR_CORRUPTED;
      goto cleanup;
    }

    memcpy(header_vault_id, header.vault_id, VAULT_ID_LEN);
    memcpy(header_salt, header.kdf_salt, VAULT_SALT_LEN);
    header_kdf_mem = header.kdf_mem;
    header_kdf_iter = header.kdf_iter;
    header_kdf_parallel = header.kdf_parallel;
    header_wrapped_mk_len = header.wrapped_mk_len;
    header_size = header_total_size(&header);
  } else {
    LOGE("Invalid vault magic");
    result = VAULT_ERR_CORRUPTED;
    goto cleanup;
  }

  if (!validate_kdf_params(header_kdf_mem, header_kdf_iter,
                           header_kdf_parallel)) {
    LOGE("Invalid KDF parameters in header");
    result = VAULT_ERR_CORRUPTED;
    goto cleanup;
  }

  // Derive KEK using params stored in vault header (NOT global adaptive)
  // This ensures vaults created with different profiles can always be opened
  result = vault_kdf_derive_with_params(passphrase, pass_len, header_salt,
                                        header_kdf_mem, header_kdf_iter, kek);
  if (result != VAULT_OK) {
    goto cleanup;
  }

  // Unwrap MK
  // wrapped_mk = nonce || ciphertext || tag
  uint8_t *nonce = wrapped_mk;
  uint8_t *ciphertext = wrapped_mk + VAULT_NONCE_LEN;
  size_t ct_len = VAULT_KEY_LEN + VAULT_TAG_LEN;
  size_t pt_len;

  result = vault_aead_decrypt(kek, nonce, header_vault_id,
                              VAULT_ID_LEN, // AAD = vault_id
                              ciphertext, ct_len, g_vault.master_key, &pt_len);

  if (result != VAULT_OK) {
    LOGE("Failed to unwrap master key - wrong passphrase?");
    result = VAULT_ERR_AUTH_FAIL;
    goto cleanup;
  }

  // Store vault state
  memcpy(g_vault.vault_id, header_vault_id, VAULT_ID_LEN);
  memcpy(g_vault.salt, header_salt, VAULT_SALT_LEN);
  g_vault.kdf_mem = header_kdf_mem;
  g_vault.kdf_iter = header_kdf_iter;
  g_vault.kdf_parallel = header_kdf_parallel;
  g_vault.container_format = VAULT_CONTAINER_V1;
  g_vault.path = strdup(path);
  g_vault.wrapped_mk_len = header_wrapped_mk_len;
  memcpy(g_vault.wrapped_mk, wrapped_mk, header_wrapped_mk_len);

  // Read index
  if (lseek(fd, (off_t)header_size, SEEK_SET) < 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  result = read_index(fd, g_vault.master_key);
  if (result != VAULT_OK) {
    goto cleanup;
  }

  g_vault.is_open = 1;

  if (is_journal) {
    close(fd);
    fd = -1;
    result = migrate_journal_to_v1(path, header_size, has_integrity_hash);
    if (result != VAULT_OK) {
      goto cleanup;
    }
  }

  if (fd >= 0) {
    close(fd);
    fd = -1;
  }
  result = migrate_active_to_log(path);
  if (result != VAULT_OK) {
    LOGE("Vault migration deferred; continuing with legacy container");
    legacy_refresh_metrics(path);
    result = VAULT_OK;
  }
  LOGI("Vault opened successfully");

cleanup:
  vault_zeroize(kek, VAULT_KEY_LEN);
  vault_zeroize(wrapped_mk, WRAPPED_MK_SIZE);

  if (fd >= 0) {
    close(fd);
  }

  if (result != VAULT_OK) {
    vault_close();
  }

  return result;
}

static int migrate_journal_to_v1(const char *path, size_t old_header_size,
                                 int has_integrity_hash) {
  if (!path || !g_vault.is_open || old_header_size == 0)
    return VAULT_ERR_INVALID_PARAM;

  int result = VAULT_OK;
  int fd_in = -1;
  int fd_out = -1;
  char *temp_path = NULL;
  vault_entry_t *entries_copy = NULL;
  uint8_t *index_pt = NULL;
  uint8_t *index_ct = NULL;
  uint8_t index_nonce[VAULT_NONCE_LEN];
  size_t pt_len = 0;
  size_t ct_len = 0;

  fd_in = open(path, O_RDONLY);
  if (fd_in < 0)
    return VAULT_ERR_IO;

  struct stat st;
  if (fstat(fd_in, &st) != 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  uint64_t file_size = st.st_size > 0 ? (uint64_t)st.st_size : 0;
  uint64_t content_size =
      (has_integrity_hash && file_size > VAULT_HASH_LEN)
          ? file_size - VAULT_HASH_LEN
          : file_size;
  if (content_size <= old_header_size + VAULT_NONCE_LEN + sizeof(uint64_t)) {
    result = VAULT_ERR_CORRUPTED;
    goto cleanup;
  }

  uint64_t old_idx_ct_len = 0;
  if (lseek(fd_in, (off_t)(old_header_size + VAULT_NONCE_LEN), SEEK_SET) < 0 ||
      read(fd_in, &old_idx_ct_len, sizeof(old_idx_ct_len)) !=
          sizeof(old_idx_ct_len)) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  if (old_idx_ct_len < VAULT_TAG_LEN ||
      old_idx_ct_len > 100 * 1024 * 1024) {
    result = VAULT_ERR_CORRUPTED;
    goto cleanup;
  }

  size_t old_index_section_size =
      VAULT_NONCE_LEN + sizeof(uint64_t) + (size_t)old_idx_ct_len;
  if (old_header_size + old_index_section_size > content_size) {
    result = VAULT_ERR_CORRUPTED;
    goto cleanup;
  }

  uint64_t old_data_start = old_header_size + old_index_section_size;
  uint64_t old_data_size = content_size - old_data_start;

  result = clone_entries(g_vault.entries, g_vault.entry_count, &entries_copy);
  if (result != VAULT_OK)
    goto cleanup;

  result =
      serialize_index(entries_copy, g_vault.entry_count, &index_pt, &pt_len);
  if (result != VAULT_OK)
    goto cleanup;

  ct_len = pt_len + VAULT_TAG_LEN;
  size_t new_index_section_size = VAULT_NONCE_LEN + sizeof(uint64_t) + ct_len;

  vault_header_t header;
  memset(&header, 0, sizeof(header));
  memcpy(header.magic, VAULT_MAGIC, VAULT_MAGIC_LEN);
  header.version = VAULT_VERSION;
  memcpy(header.vault_id, g_vault.vault_id, VAULT_ID_LEN);
  memcpy(header.kdf_salt, g_vault.salt, VAULT_SALT_LEN);
  header.kdf_mem = g_vault.kdf_mem;
  header.kdf_iter = g_vault.kdf_iter;
  header.kdf_parallel = g_vault.kdf_parallel;
  header.wrapped_mk_len = (uint32_t)g_vault.wrapped_mk_len;

  size_t new_header_size = header_total_size(&header);
  int64_t offset_delta =
      (int64_t)(new_header_size + new_index_section_size) -
      (int64_t)(old_header_size + old_index_section_size);

  for (uint32_t i = 0; i < g_vault.entry_count; i++) {
    vault_entry_t *entry = &entries_copy[i];
    if (entry->chunk_count > 0) {
      for (uint32_t c = 0; c < entry->chunk_count; c++) {
        int64_t adjusted = (int64_t)entry->chunks[c].offset + offset_delta;
        if (adjusted < 0) {
          result = VAULT_ERR_CORRUPTED;
          goto cleanup;
        }
        entry->chunks[c].offset = (uint64_t)adjusted;
      }
    } else {
      int64_t adjusted = (int64_t)entry->data_offset + offset_delta;
      if (adjusted < 0) {
        result = VAULT_ERR_CORRUPTED;
        goto cleanup;
      }
      entry->data_offset = (uint64_t)adjusted;
    }
  }

  vault_zeroize(index_pt, pt_len);
  free(index_pt);
  index_pt = NULL;
  result =
      serialize_index(entries_copy, g_vault.entry_count, &index_pt, &pt_len);
  if (result != VAULT_OK)
    goto cleanup;

  ct_len = pt_len + VAULT_TAG_LEN;
  index_ct = malloc(ct_len);
  if (!index_ct) {
    result = VAULT_ERR_MEMORY;
    goto cleanup;
  }

  result = vault_aead_encrypt(g_vault.master_key, NULL, NULL, 0, index_pt,
                              pt_len, index_ct, index_nonce);
  if (result != VAULT_OK)
    goto cleanup;

  size_t path_len = strlen(path);
  temp_path = malloc(path_len + 5);
  if (!temp_path) {
    result = VAULT_ERR_MEMORY;
    goto cleanup;
  }
  snprintf(temp_path, path_len + 5, "%s.tmp", path);

  fd_out = open(temp_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (fd_out < 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  if (write(fd_out, &header, sizeof(header)) != sizeof(header) ||
      write(fd_out, g_vault.wrapped_mk, g_vault.wrapped_mk_len) !=
          (ssize_t)g_vault.wrapped_mk_len) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  uint32_t crc = calculate_crc32((uint8_t *)&header, sizeof(header));
  uint64_t ct_len_u64 = ct_len;
  if (write(fd_out, &crc, sizeof(crc)) != sizeof(crc) ||
      write(fd_out, index_nonce, VAULT_NONCE_LEN) != VAULT_NONCE_LEN ||
      write(fd_out, &ct_len_u64, sizeof(ct_len_u64)) != sizeof(ct_len_u64) ||
      write(fd_out, index_ct, ct_len) != (ssize_t)ct_len) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  if (old_data_size > 0) {
    if (lseek(fd_in, (off_t)old_data_start, SEEK_SET) < 0) {
      result = VAULT_ERR_IO;
      goto cleanup;
    }
    uint8_t buffer[256 * 1024];
    uint64_t remaining = old_data_size;
    while (remaining > 0) {
      size_t to_read =
          remaining > sizeof(buffer) ? sizeof(buffer) : (size_t)remaining;
      ssize_t read_len = read(fd_in, buffer, to_read);
      if (read_len <= 0 || write(fd_out, buffer, read_len) != read_len) {
        result = VAULT_ERR_IO;
        goto cleanup;
      }
      remaining -= (uint64_t)read_len;
    }
  }

  result = append_integrity_hash(fd_out);
  if (result != VAULT_OK)
    goto cleanup;

  fsync(fd_out);
  close(fd_out);
  fd_out = -1;
  close(fd_in);
  fd_in = -1;

  if (rename(temp_path, path) != 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  fsync_parent_dir(path);

  if (g_vault.entries) {
    free_entries_array(g_vault.entries, g_vault.entry_count);
  }
  g_vault.entries = entries_copy;
  entries_copy = NULL;

cleanup:
  if (fd_in >= 0)
    close(fd_in);
  if (fd_out >= 0)
    close(fd_out);
  if (result != VAULT_OK && temp_path)
    unlink(temp_path);
  free(temp_path);
  if (entries_copy)
    free_entries_array(entries_copy, g_vault.entry_count);
  if (index_pt) {
    vault_zeroize(index_pt, pt_len);
    free(index_pt);
  }
  if (index_ct) {
    vault_zeroize(index_ct, ct_len);
    free(index_ct);
  }
  return result;
}

static int copy_ciphertext_range(int fd_in, uint64_t source_offset,
                                 uint64_t length, int fd_out,
                                 uint8_t *buffer, size_t buffer_size) {
  while (length > 0) {
    size_t chunk = length > buffer_size ? buffer_size : (size_t)length;
    int result = read_all_at(fd_in, buffer, chunk, source_offset);
    if (result != VAULT_OK)
      return result;
    result = write_all(fd_out, buffer, chunk);
    if (result != VAULT_OK)
      return result;
    source_offset += chunk;
    length -= chunk;
  }
  return VAULT_OK;
}

static int migrate_active_to_log(const char *path) {
  if (!path || !g_vault.is_open)
    return VAULT_ERR_INVALID_PARAM;

  int result = VAULT_OK;
  int fd_in = -1;
  int fd_out = -1;
  char *temp_path = NULL;
  uint8_t *copy_buffer = NULL;
  uint8_t *index_record = NULL;
  size_t index_record_len = 0;
  uint8_t index_key[VAULT_KEY_LEN] = {0};
  uint8_t wrapped_index_key[WRAPPED_INDEX_KEY_SIZE] = {0};
  vault_entry_t *entries = NULL;

  result = clone_entries(g_vault.entries, g_vault.entry_count, &entries);
  if (result != VAULT_OK)
    return result;

  fd_in = open(path, O_RDONLY);
  if (fd_in < 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  size_t path_len = strlen(path);
  temp_path = malloc(path_len + 5);
  if (!temp_path) {
    result = VAULT_ERR_MEMORY;
    goto cleanup;
  }
  snprintf(temp_path, path_len + 5, "%s.tmp", path);
  fd_out = open(temp_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (fd_out < 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  vault_log_super_t super;
  log_init_super(&super);
  vault_log_slot_t empty_slots[VAULT_LOG_SLOT_COUNT];
  memset(empty_slots, 0, sizeof(empty_slots));
  result = write_all(fd_out, &super, sizeof(super));
  if (result == VAULT_OK)
    result = write_all(fd_out, empty_slots, sizeof(empty_slots));
  if (result != VAULT_OK)
    goto cleanup;

  copy_buffer = malloc(1024 * 1024);
  if (!copy_buffer) {
    result = VAULT_ERR_MEMORY;
    goto cleanup;
  }

  uint64_t output_offset = log_header_size();
  for (uint32_t i = 0; i < g_vault.entry_count; i++) {
    const vault_entry_t *source = &g_vault.entries[i];
    vault_entry_t *destination = &entries[i];
    if (source->chunk_count > 0) {
      for (uint32_t c = 0; c < source->chunk_count; c++) {
        uint64_t length = source->chunks[c].length;
        destination->chunks[c].offset = output_offset;
        result = copy_ciphertext_range(fd_in, source->chunks[c].offset,
                                       length, fd_out, copy_buffer,
                                       1024 * 1024);
        if (result != VAULT_OK)
          goto cleanup;
        output_offset += length;
      }
    } else {
      uint64_t length = source->data_length;
      destination->data_offset = output_offset;
      result = copy_ciphertext_range(fd_in, source->data_offset, length,
                                     fd_out, copy_buffer, 1024 * 1024);
      if (result != VAULT_OK)
        goto cleanup;
      output_offset += length;
    }
  }

  const uint64_t sequence = 1;
  vault_random_bytes(index_key, sizeof(index_key));
  result = log_wrap_index_key(g_vault.master_key, g_vault.vault_id, sequence,
                              index_key, wrapped_index_key);
  if (result != VAULT_OK)
    goto cleanup;
  result = build_log_index_record(
      entries, g_vault.entry_count, index_key, g_vault.vault_id,
      sequence, &index_record, &index_record_len);
  if (result != VAULT_OK)
    goto cleanup;

  uint64_t index_offset = output_offset;
  result = write_all(fd_out, index_record, index_record_len);
  if (result != VAULT_OK)
    goto cleanup;
  uint64_t committed_size = index_offset + index_record_len;

  if (fsync(fd_out) != 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  vault_log_slot_t root;
  result = log_fill_slot(
      &root, sequence, g_vault.vault_id, g_vault.salt, g_vault.kdf_mem,
      g_vault.kdf_iter, g_vault.kdf_parallel, g_vault.wrapped_mk,
      wrapped_index_key, index_offset, index_record_len, committed_size,
      g_vault.master_key);
  if (result != VAULT_OK)
    goto cleanup;
  result = log_write_slot(fd_out, 0, &root);
  if (result == VAULT_OK)
    result = log_write_slot(fd_out, 1, &root);
  if (result != VAULT_OK || fsync(fd_out) != 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  close(fd_out);
  fd_out = -1;
  close(fd_in);
  fd_in = -1;
  if (rename(temp_path, path) != 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  fsync_parent_dir(path);

  free_entries_array(g_vault.entries, g_vault.entry_count);
  g_vault.entries = entries;
  entries = NULL;
  g_vault.container_format = VAULT_CONTAINER_LOG;
  g_vault.commit_sequence = sequence;
  g_vault.committed_size = committed_size;
  g_vault.index_offset = index_offset;
  g_vault.index_length = index_record_len;
  g_vault.active_root_slot = 0;
  log_refresh_metrics();

cleanup:
  if (fd_in >= 0)
    close(fd_in);
  if (fd_out >= 0)
    close(fd_out);
  if (result != VAULT_OK && temp_path)
    unlink(temp_path);
  free(temp_path);
  free(copy_buffer);
  vault_zeroize(index_key, sizeof(index_key));
  vault_zeroize(wrapped_index_key, sizeof(wrapped_index_key));
  if (index_record) {
    vault_zeroize(index_record, index_record_len);
    free(index_record);
  }
  if (entries)
    free_entries_array(entries, g_vault.entry_count);
  return result;
}

int vault_compact_storage(void) {
  if (!g_vault.is_open || !g_vault.path)
    return VAULT_ERR_NOT_OPEN;
  return migrate_active_to_log(g_vault.path);
}

// Read and decrypt index
static int read_index(int fd, const uint8_t mk[VAULT_KEY_LEN]) {
  uint8_t nonce[VAULT_NONCE_LEN];
  uint64_t ct_len;

  if (read(fd, nonce, VAULT_NONCE_LEN) != VAULT_NONCE_LEN) {
    return VAULT_ERR_IO;
  }

  if (read(fd, &ct_len, sizeof(ct_len)) != sizeof(ct_len)) {
    return VAULT_ERR_IO;
  }

  if (ct_len < VAULT_TAG_LEN ||
      ct_len > 100 * 1024 * 1024) { // Sanity check: max 100MB index
    return VAULT_ERR_CORRUPTED;
  }

  uint8_t *ciphertext = malloc(ct_len);
  if (!ciphertext) {
    return VAULT_ERR_MEMORY;
  }

  if (read(fd, ciphertext, ct_len) != (ssize_t)ct_len) {
    free(ciphertext);
    return VAULT_ERR_IO;
  }

  size_t pt_len = ct_len - VAULT_TAG_LEN;
  uint8_t *plaintext = malloc(pt_len);
  if (!plaintext) {
    free(ciphertext);
    return VAULT_ERR_MEMORY;
  }

  size_t actual_pt_len;
  int result =
      vault_aead_decrypt(mk, nonce, NULL, 0, // No AAD for index
                         ciphertext, ct_len, plaintext, &actual_pt_len);

  free(ciphertext);

  if (result != VAULT_OK) {
    vault_zeroize(plaintext, pt_len);
    free(plaintext);
    return result;
  }

  // Parse index
  vault_entry_t *entries = NULL;
  uint32_t count = 0;
  result = deserialize_index(plaintext, actual_pt_len, &entries, &count);
  if (result == VAULT_OK) {
    // Free previous entries if any
    if (g_vault.entries) {
      free_entries_array(g_vault.entries, g_vault.entry_count);
    }
    g_vault.entries = entries;
    g_vault.entry_count = count;
  }

  vault_zeroize(plaintext, pt_len);
  free(plaintext);
  return result;
}

// Simple CRC32 implementation
static uint32_t calculate_crc32(const uint8_t *data, size_t len) {
  uint32_t crc = 0xFFFFFFFF;

  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (int j = 0; j < 8; j++) {
      crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
  }

  return ~crc;
}

/**
 * Rewrite container file with provided entries and ciphertext payloads.
 * Updates offsets to pack data contiguously after header+index.
 */
int vault_save_container(vault_entry_t *entries,
                         const vault_payload_t *payloads,
                         uint32_t entry_count) {
  LOGI("vault_save_container: starting, entry_count=%u", entry_count);

  if (!g_vault.is_open || !g_vault.path) {
    LOGE("vault_save_container: vault not open");
    return VAULT_ERR_NOT_OPEN;
  }

  // Calculate index sizes to determine data start offset
  size_t pt_len = 0;
  int result = calculate_index_plaintext_size(entries, entry_count, &pt_len);
  if (result != VAULT_OK) {
    LOGE("vault_save_container: calculate_index_plaintext_size failed with %d",
         result);
    return result;
  }
  LOGI("vault_save_container: index pt_len=%zu", pt_len);

  size_t ct_len = pt_len + VAULT_TAG_LEN;
  size_t index_section_size = VAULT_NONCE_LEN + sizeof(uint64_t) + ct_len;

  vault_header_t header;
  memset(&header, 0, sizeof(header));
  memcpy(header.magic, VAULT_MAGIC, VAULT_MAGIC_LEN);
  header.version = VAULT_VERSION;
  memcpy(header.vault_id, g_vault.vault_id, VAULT_ID_LEN);
  memcpy(header.kdf_salt, g_vault.salt, VAULT_SALT_LEN);
  if (g_vault.kdf_mem == 0 || g_vault.kdf_iter == 0) {
    size_t kdf_mem;
    uint32_t kdf_iter, kdf_parallel;
    vault_get_kdf_params(&kdf_mem, &kdf_iter, &kdf_parallel);
    header.kdf_mem = (uint32_t)kdf_mem;
    header.kdf_iter = kdf_iter;
    header.kdf_parallel = kdf_parallel;
    g_vault.kdf_mem = header.kdf_mem;
    g_vault.kdf_iter = header.kdf_iter;
    g_vault.kdf_parallel = header.kdf_parallel;
  } else {
    header.kdf_mem = g_vault.kdf_mem;
    header.kdf_iter = g_vault.kdf_iter;
    header.kdf_parallel = g_vault.kdf_parallel;
  }
  header.wrapped_mk_len = (uint32_t)g_vault.wrapped_mk_len;

  size_t header_size = header_total_size(&header);
  uint64_t data_offset = header_size + index_section_size;

  // Assign offsets based on payload sizes
  for (uint32_t i = 0; i < entry_count; i++) {
    vault_entry_t *entry = &entries[i];
    const vault_payload_t *payload = &payloads[i];

    // FIX: Use chunk_count > 0 to determine chunked storage
    // Streaming import stores all large files as chunked, regardless of type
    if (entry->chunk_count > 0) {
      if (entry->chunk_count != payload->chunk_count) {
        return VAULT_ERR_INVALID_PARAM;
      }
      for (uint32_t c = 0; c < entry->chunk_count; c++) {
        entry->chunks[c].offset = data_offset;
        entry->chunks[c].length = (uint32_t)payload->chunk_lens[c];
        data_offset += payload->chunk_lens[c];
      }
    } else {
      entry->data_offset = data_offset;
      entry->data_length = payload->data_len;
      data_offset += payload->data_len;
    }
  }

  // Prepare index plaintext and ciphertext
  uint8_t *index_pt = NULL;
  uint8_t *index_ct = NULL;
  uint8_t index_nonce[VAULT_NONCE_LEN];
  char *temp_path = NULL;
  int fd = -1;

  result = serialize_index(entries, entry_count, &index_pt, &pt_len);
  if (result != VAULT_OK)
    goto cleanup_buffers;

  ct_len = pt_len + VAULT_TAG_LEN;
  index_ct = malloc(ct_len);
  if (!index_ct) {
    result = VAULT_ERR_MEMORY;
    goto cleanup_buffers;
  }

  result = vault_aead_encrypt(g_vault.master_key, NULL, NULL, 0, index_pt,
                              pt_len, index_ct, index_nonce);
  if (result != VAULT_OK)
    goto cleanup_buffers;

  // Write to temp file
  size_t path_len = strlen(g_vault.path);
  temp_path = malloc(path_len + 5);
  if (!temp_path) {
    result = VAULT_ERR_MEMORY;
    goto cleanup_buffers;
  }
  snprintf(temp_path, path_len + 5, "%s.tmp", g_vault.path);
  LOGI("vault_save_container: opening temp file %s", temp_path);

  fd = open(temp_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    LOGE("vault_save_container: failed to open temp file, errno=%d", errno);
    result = VAULT_ERR_IO;
    goto cleanup_buffers;
  }
  LOGI("vault_save_container: temp file opened, fd=%d", fd);

  // Write header
  LOGI("vault_save_container: writing header");
  if (write(fd, &header, sizeof(header)) != sizeof(header)) {
    LOGE("vault_save_container: failed to write header");
    result = VAULT_ERR_IO;
    goto write_cleanup;
  }
  if (write(fd, g_vault.wrapped_mk, g_vault.wrapped_mk_len) !=
      (ssize_t)g_vault.wrapped_mk_len) {
    LOGE("vault_save_container: failed to write wrapped_mk");
    result = VAULT_ERR_IO;
    goto write_cleanup;
  }

  uint32_t crc = calculate_crc32((uint8_t *)&header, sizeof(header));
  if (write(fd, &crc, sizeof(crc)) != sizeof(crc)) {
    LOGE("vault_save_container: failed to write crc");
    result = VAULT_ERR_IO;
    goto write_cleanup;
  }
  LOGI("vault_save_container: header written");

  // Write index section
  LOGI("vault_save_container: writing index section");
  uint64_t ct_len_u64 = ct_len;
  if (write(fd, index_nonce, VAULT_NONCE_LEN) != VAULT_NONCE_LEN ||
      write(fd, &ct_len_u64, sizeof(ct_len_u64)) != sizeof(ct_len_u64) ||
      write(fd, index_ct, ct_len) != (ssize_t)ct_len) {
    LOGE("vault_save_container: failed to write index section");
    result = VAULT_ERR_IO;
    goto write_cleanup;
  }
  LOGI("vault_save_container: index section written");

  // Write data payloads
  LOGI("vault_save_container: writing %u data payloads", entry_count);
  for (uint32_t i = 0; i < entry_count; i++) {
    const vault_entry_t *entry = &entries[i];
    const vault_payload_t *payload = &payloads[i];

    // FIX: Use chunk_count > 0 to determine chunked storage
    if (entry->chunk_count > 0) {
      for (uint32_t c = 0; c < payload->chunk_count; c++) {
        if (write(fd, payload->chunks[c], payload->chunk_lens[c]) !=
            (ssize_t)payload->chunk_lens[c]) {
          LOGE("vault_save_container: failed to write chunk %u/%u", c, i);
          result = VAULT_ERR_IO;
          goto write_cleanup;
        }
      }
    } else {
      if (write(fd, payload->data, payload->data_len) !=
          (ssize_t)payload->data_len) {
        LOGE("vault_save_container: failed to write payload %u", i);
        result = VAULT_ERR_IO;
        goto write_cleanup;
      }
    }
  }
  LOGI("vault_save_container: payloads written");

  // Sync data before computing hash
  fsync(fd);
  LOGI("vault_save_container: computing integrity hash");

  // Compute SHA256 hash of entire file content and append it
  {
    // Get current file size
    off_t current_pos = lseek(fd, 0, SEEK_CUR);
    if (current_pos < 0) {
      LOGE("vault_save_container: lseek failed");
      result = VAULT_ERR_IO;
      goto write_cleanup;
    }
    LOGI("vault_save_container: file size before hash = %lld",
         (long long)current_pos);
    // Read entire file for hashing
    lseek(fd, 0, SEEK_SET);

    crypto_hash_sha256_state hash_state;
    crypto_hash_sha256_init(&hash_state);

    uint8_t hash_buffer[64 * 1024];
    uint64_t remaining = (uint64_t)current_pos;

    while (remaining > 0) {
      size_t to_read = remaining > sizeof(hash_buffer)
                           ? sizeof(hash_buffer)
                           : (size_t)remaining;
      ssize_t read_len = read(fd, hash_buffer, to_read);
      if (read_len <= 0) {
        result = VAULT_ERR_IO;
        goto write_cleanup;
      }
      crypto_hash_sha256_update(&hash_state, hash_buffer, read_len);
      remaining -= read_len;
    }

    uint8_t file_hash[VAULT_HASH_LEN];
    crypto_hash_sha256_final(&hash_state, file_hash);

    // Seek back to end and write hash
    lseek(fd, 0, SEEK_END);
    if (write(fd, file_hash, VAULT_HASH_LEN) != VAULT_HASH_LEN) {
      result = VAULT_ERR_IO;
      goto write_cleanup;
    }

    LOGI("Container hash computed and appended (SHA256)");
  }

  // Sync and replace
  fsync(fd);
  close(fd);
  fd = -1;

  if (rename(temp_path, g_vault.path) != 0) {
    unlink(temp_path);
    free(temp_path);
    temp_path = NULL;
    result = VAULT_ERR_IO;
    goto cleanup_buffers;
  }
  fsync_parent_dir(g_vault.path);

  free(temp_path);
  temp_path = NULL;
  g_vault.total_size = data_offset;
  g_vault.free_space = 0;

  result = VAULT_OK;

write_cleanup:
  if (fd >= 0) {
    close(fd);
    if (temp_path) {
      unlink(temp_path);
      free(temp_path);
      temp_path = NULL;
    }
  }
cleanup_buffers:
  if (index_pt) {
    vault_zeroize(index_pt, pt_len);
    free(index_pt);
  }
  if (index_ct) {
    vault_zeroize(index_ct, ct_len);
    free(index_ct);
  }
  if (temp_path) {
    free(temp_path);
  }
  return result;
}

static int log_commit_index_with_credentials(
    const uint8_t salt[VAULT_SALT_LEN], uint32_t kdf_mem, uint32_t kdf_iter,
    uint32_t kdf_parallel, const uint8_t wrapped_mk[WRAPPED_MK_SIZE]) {
  if (g_vault.container_format != VAULT_CONTAINER_LOG ||
      g_vault.commit_sequence == UINT64_MAX) {
    return VAULT_ERR_CORRUPTED;
  }

  int result = VAULT_OK;
  int fd = -1;
  uint8_t *index_record = NULL;
  size_t index_record_len = 0;
  uint8_t index_key[VAULT_KEY_LEN] = {0};
  uint8_t wrapped_index_key[WRAPPED_INDEX_KEY_SIZE] = {0};
  uint64_t sequence = g_vault.commit_sequence + 1;

  vault_random_bytes(index_key, sizeof(index_key));
  result = log_wrap_index_key(g_vault.master_key, g_vault.vault_id, sequence,
                              index_key, wrapped_index_key);
  if (result != VAULT_OK)
    goto cleanup;
  result = build_log_index_record(
      g_vault.entries, g_vault.entry_count, index_key, g_vault.vault_id,
      sequence, &index_record, &index_record_len);
  if (result != VAULT_OK)
    goto cleanup;

  fd = open(g_vault.path, O_RDWR);
  if (fd < 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  if (ftruncate(fd, (off_t)g_vault.committed_size) != 0 ||
      lseek(fd, (off_t)g_vault.committed_size, SEEK_SET) < 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  uint64_t index_offset = g_vault.committed_size;
  result = write_all(fd, index_record, index_record_len);
  if (result != VAULT_OK || fsync(fd) != 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  uint64_t committed_size = index_offset + index_record_len;
  uint32_t next_slot = (g_vault.active_root_slot + 1) % VAULT_LOG_SLOT_COUNT;
  vault_log_slot_t root;
  result = log_fill_slot(&root, sequence, g_vault.vault_id, salt, kdf_mem,
                         kdf_iter, kdf_parallel, wrapped_mk,
                         wrapped_index_key, index_offset, index_record_len,
                         committed_size,
                         g_vault.master_key);
  if (result != VAULT_OK)
    goto cleanup;
  result = log_write_slot(fd, next_slot, &root);
  if (result != VAULT_OK || fsync(fd) != 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  // The new root is already durable. Mirror it over the previous slot so old
  // credentials and old per-commit index keys are not retained in the live
  // container. A failed mirror is healed on the next authenticated open.
  int mirror_result = log_write_slot(fd, g_vault.active_root_slot, &root);
  if (mirror_result != VAULT_OK || fsync(fd) != 0) {
    LOGE("log_commit_index: failed to mirror committed root slot");
  }

  memcpy(g_vault.salt, salt, VAULT_SALT_LEN);
  memcpy(g_vault.wrapped_mk, wrapped_mk, WRAPPED_MK_SIZE);
  g_vault.wrapped_mk_len = WRAPPED_MK_SIZE;
  g_vault.kdf_mem = kdf_mem;
  g_vault.kdf_iter = kdf_iter;
  g_vault.kdf_parallel = kdf_parallel;
  g_vault.commit_sequence = sequence;
  g_vault.committed_size = committed_size;
  g_vault.index_offset = index_offset;
  g_vault.index_length = index_record_len;
  g_vault.active_root_slot = next_slot;
  log_refresh_metrics();

cleanup:
  if (fd >= 0)
    close(fd);
  if (index_record) {
    vault_zeroize(index_record, index_record_len);
    free(index_record);
  }
  vault_zeroize(index_key, sizeof(index_key));
  vault_zeroize(wrapped_index_key, sizeof(wrapped_index_key));
  return result;
}

int vault_verify_password(const uint8_t *passphrase, size_t pass_len) {
  if (!passphrase || pass_len == 0) {
    return VAULT_ERR_INVALID_PARAM;
  }
  if (!g_vault.is_open) {
    return VAULT_ERR_NOT_OPEN;
  }

  uint8_t kek[VAULT_KEY_LEN];
  uint8_t candidate_mk[VAULT_KEY_LEN];
  size_t candidate_len = 0;
  int result = vault_kdf_derive_with_params(
      passphrase, pass_len, g_vault.salt, g_vault.kdf_mem,
      g_vault.kdf_iter, kek);
  if (result == VAULT_OK) {
    result = vault_aead_decrypt(
        kek, g_vault.wrapped_mk, g_vault.vault_id, VAULT_ID_LEN,
        g_vault.wrapped_mk + VAULT_NONCE_LEN,
        VAULT_KEY_LEN + VAULT_TAG_LEN, candidate_mk, &candidate_len);
    if (result != VAULT_OK || candidate_len != VAULT_KEY_LEN) {
      result = VAULT_ERR_AUTH_FAIL;
    }
  }
  vault_zeroize(kek, sizeof(kek));
  vault_zeroize(candidate_mk, sizeof(candidate_mk));
  return result;
}

int vault_change_password(const uint8_t *old_passphrase, size_t old_pass_len,
                          const uint8_t *new_passphrase, size_t new_pass_len) {
  if (!old_passphrase || !new_passphrase) {
    return VAULT_ERR_INVALID_PARAM;
  }

  if (old_pass_len < VAULT_MIN_PASSPHRASE_LEN ||
      new_pass_len < VAULT_MIN_PASSPHRASE_LEN) {
    return VAULT_ERR_PASSPHRASE_TOO_SHORT;
  }

  if (!g_vault.is_open || !g_vault.path) {
    LOGE("vault_change_password: Vault not open");
    return VAULT_ERR_NOT_OPEN;
  }

  int result = VAULT_OK;
  int fd_in = -1;
  int fd_out = -1;
  char *temp_path = NULL;
  uint8_t old_kek[VAULT_KEY_LEN];
  uint8_t new_kek[VAULT_KEY_LEN];
  uint8_t new_salt[VAULT_SALT_LEN];
  uint8_t new_wrapped_mk[WRAPPED_MK_SIZE];
  uint8_t nonce[VAULT_NONCE_LEN];
  uint8_t decrypted_mk[VAULT_KEY_LEN];
  uint32_t kdf_mem = g_vault.kdf_mem;
  uint32_t kdf_iter = g_vault.kdf_iter;
  uint32_t kdf_parallel = g_vault.kdf_parallel;

  LOGI("vault_change_password: Verifying old password...");

  if (kdf_mem == 0 || kdf_iter == 0) {
    size_t mem_tmp;
    uint32_t iter_tmp, parallel_tmp;
    vault_get_kdf_params(&mem_tmp, &iter_tmp, &parallel_tmp);
    kdf_mem = (uint32_t)mem_tmp;
    kdf_iter = iter_tmp;
    kdf_parallel = parallel_tmp;
  }

  // Step 1: Verify old password by deriving KEK and decrypting wrapped MK
  result = vault_kdf_derive_with_params(
      old_passphrase, old_pass_len, g_vault.salt, kdf_mem, kdf_iter, old_kek);
  if (result != VAULT_OK) {
    LOGE("vault_change_password: Failed to derive old KEK");
    goto cleanup;
  }

  // Decrypt wrapped MK to verify old password
  // wrapped_mk = nonce (24) || ciphertext (32 + 16 tag)
  size_t decrypted_len;
  result = vault_aead_decrypt(old_kek,
                              g_vault.wrapped_mk, // nonce is first 24 bytes
                              g_vault.vault_id, VAULT_ID_LEN, // AAD
                              g_vault.wrapped_mk + VAULT_NONCE_LEN,
                              VAULT_KEY_LEN + VAULT_TAG_LEN, // ciphertext
                              decrypted_mk, &decrypted_len);

  if (result != VAULT_OK) {
    LOGE("vault_change_password: Old password verification failed");
    result = VAULT_ERR_AUTH_FAIL;
    goto cleanup;
  }

  // Verify decrypted MK matches current MK in memory
  if (sodium_memcmp(decrypted_mk, g_vault.master_key, VAULT_KEY_LEN) != 0) {
    LOGE("vault_change_password: Decrypted MK doesn't match");
    result = VAULT_ERR_AUTH_FAIL;
    goto cleanup;
  }

  LOGI("vault_change_password: Old password verified, generating new "
       "credentials...");

  // Step 2: Generate new salt
  vault_random_bytes(new_salt, VAULT_SALT_LEN);

  // Step 3: Derive new KEK from new password
  result = vault_kdf_derive_with_params(new_passphrase, new_pass_len, new_salt,
                                        kdf_mem, kdf_iter, new_kek);
  if (result != VAULT_OK) {
    LOGE("vault_change_password: Failed to derive new KEK");
    goto cleanup;
  }

  // Step 4: Wrap MK with new KEK
  vault_random_bytes(nonce, VAULT_NONCE_LEN);
  memcpy(new_wrapped_mk, nonce, VAULT_NONCE_LEN);

  result =
      vault_aead_encrypt(new_kek, nonce, g_vault.vault_id, VAULT_ID_LEN, // AAD
                         g_vault.master_key, VAULT_KEY_LEN,
                         new_wrapped_mk + VAULT_NONCE_LEN, nonce);
  if (result != VAULT_OK) {
    LOGE("vault_change_password: Failed to wrap MK with new KEK");
    goto cleanup;
  }

  LOGI("vault_change_password: Rewriting vault header...");

  if (g_vault.container_format == VAULT_CONTAINER_LOG) {
    result = log_commit_index_with_credentials(
        new_salt, kdf_mem, kdf_iter, kdf_parallel, new_wrapped_mk);
    if (result == VAULT_OK)
      LOGI("vault_change_password: Password changed successfully");
    goto cleanup;
  }

  // Step 5: Stream-rewrite vault header and rehash without loading full file
  fd_in = open(g_vault.path, O_RDONLY);
  if (fd_in < 0) {
    LOGE("vault_change_password: Failed to open vault for reading");
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  struct stat st;
  if (fstat(fd_in, &st) != 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  uint64_t file_size = (uint64_t)st.st_size;
  uint64_t content_size =
      (file_size > VAULT_HASH_LEN) ? file_size - VAULT_HASH_LEN : file_size;

  vault_header_t header;
  memset(&header, 0, sizeof(header));
  memcpy(header.magic, VAULT_MAGIC, VAULT_MAGIC_LEN);
  header.version = VAULT_VERSION;
  memcpy(header.vault_id, g_vault.vault_id, VAULT_ID_LEN);
  memcpy(header.kdf_salt, new_salt, VAULT_SALT_LEN);
  header.kdf_mem = kdf_mem;
  header.kdf_iter = kdf_iter;
  header.kdf_parallel = kdf_parallel;
  header.wrapped_mk_len = WRAPPED_MK_SIZE;

  size_t header_size = header_total_size(&header);
  if (content_size < header_size) {
    result = VAULT_ERR_CORRUPTED;
    goto cleanup;
  }

  // Step 6: Write to temp file and atomic rename
  size_t path_len = strlen(g_vault.path);
  temp_path = malloc(path_len + 5);
  if (!temp_path) {
    result = VAULT_ERR_MEMORY;
    goto cleanup;
  }
  snprintf(temp_path, path_len + 5, "%s.tmp", g_vault.path);

  fd_out = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd_out < 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  // Write header + wrapped MK + CRC
  if (write(fd_out, &header, sizeof(header)) != sizeof(header)) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  if (write(fd_out, new_wrapped_mk, WRAPPED_MK_SIZE) != WRAPPED_MK_SIZE) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  uint32_t new_crc = calculate_crc32((uint8_t *)&header, sizeof(header));
  if (write(fd_out, &new_crc, sizeof(new_crc)) != sizeof(new_crc)) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  // Compute new SHA256 hash and append (streaming)
  {
    crypto_hash_sha256_state hash_state;
    crypto_hash_sha256_init(&hash_state);
    crypto_hash_sha256_update(&hash_state, (uint8_t *)&header, sizeof(header));
    crypto_hash_sha256_update(&hash_state, new_wrapped_mk, WRAPPED_MK_SIZE);
    crypto_hash_sha256_update(&hash_state, (uint8_t *)&new_crc,
                              sizeof(new_crc));

    if (lseek(fd_in, header_size, SEEK_SET) < 0) {
      result = VAULT_ERR_IO;
      goto cleanup;
    }

    uint64_t remaining = content_size - header_size;
    uint8_t buffer[64 * 1024];
    while (remaining > 0) {
      size_t to_read =
          remaining > sizeof(buffer) ? sizeof(buffer) : (size_t)remaining;
      ssize_t read_len = read(fd_in, buffer, to_read);
      if (read_len <= 0) {
        result = VAULT_ERR_IO;
        goto cleanup;
      }
      if (write(fd_out, buffer, read_len) != read_len) {
        result = VAULT_ERR_IO;
        goto cleanup;
      }
      crypto_hash_sha256_update(&hash_state, buffer, read_len);
      remaining -= read_len;
    }

    uint8_t new_file_hash[VAULT_HASH_LEN];
    crypto_hash_sha256_final(&hash_state, new_file_hash);

    if (write(fd_out, new_file_hash, VAULT_HASH_LEN) != VAULT_HASH_LEN) {
      result = VAULT_ERR_IO;
      goto cleanup;
    }
    LOGI("vault_change_password: Integrity hash updated");
  }

  fsync(fd_out);
  close(fd_out);
  fd_out = -1;
  close(fd_in);
  fd_in = -1;

  if (rename(temp_path, g_vault.path) != 0) {
    LOGE("vault_change_password: Failed to rename temp file");
    unlink(temp_path);
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  fsync_parent_dir(g_vault.path);

  // Step 8: Update in-memory state
  memcpy(g_vault.salt, new_salt, VAULT_SALT_LEN);
  memcpy(g_vault.wrapped_mk, new_wrapped_mk, WRAPPED_MK_SIZE);
  g_vault.wrapped_mk_len = WRAPPED_MK_SIZE;
  g_vault.kdf_mem = kdf_mem;
  g_vault.kdf_iter = kdf_iter;
  g_vault.kdf_parallel = kdf_parallel;

  LOGI("vault_change_password: Password changed successfully");
  result = VAULT_OK;

cleanup:
  vault_zeroize(old_kek, VAULT_KEY_LEN);
  vault_zeroize(new_kek, VAULT_KEY_LEN);
  vault_zeroize(decrypted_mk, VAULT_KEY_LEN);
  vault_zeroize(new_wrapped_mk, WRAPPED_MK_SIZE);

  if (fd_in >= 0) {
    close(fd_in);
  }
  if (fd_out >= 0) {
    close(fd_out);
  }
  if (temp_path) {
    unlink(temp_path);
    free(temp_path);
  }

  return result;
}

static int log_commit_current_index(void) {
  return log_commit_index_with_credentials(
      g_vault.salt, g_vault.kdf_mem, g_vault.kdf_iter,
      g_vault.kdf_parallel, g_vault.wrapped_mk);
}

// ============================================================================
// Index-only operations
// ============================================================================

/**
 * Save only the index section without touching data blobs.
 * PERFORMANCE: Uses in-place update when possible, avoiding O(n) data copy.
 * SECURITY: AEAD encryption provides integrity - hash is optional.
 */
int vault_save_index_only(void) {
  if (!g_vault.is_open || !g_vault.path) {
    LOGE("vault_save_index_only: vault not open");
    return VAULT_ERR_NOT_OPEN;
  }

  if (g_vault.container_format == VAULT_CONTAINER_LOG)
    return log_commit_current_index();

  int result = VAULT_OK;
  int fd = -1;
  uint8_t *index_pt = NULL;
  uint8_t *index_ct = NULL;
  size_t pt_len = 0;
  size_t ct_len = 0;
  uint8_t index_nonce[VAULT_NONCE_LEN];
  vault_entry_t *entries_copy = NULL;

  LOGI("vault_save_index_only: starting for %u entries", g_vault.entry_count);

  result = clone_entries(g_vault.entries, g_vault.entry_count, &entries_copy);
  if (result != VAULT_OK)
    return result;

  // Serialize new index
  result = serialize_index(entries_copy, g_vault.entry_count, &index_pt,
                           &pt_len);
  if (result != VAULT_OK) {
    goto cleanup;
  }

  ct_len = pt_len + VAULT_TAG_LEN;
  index_ct = malloc(ct_len);
  if (!index_ct) {
    result = VAULT_ERR_MEMORY;
    goto cleanup;
  }

  result = vault_aead_encrypt(g_vault.master_key, NULL, NULL, 0, index_pt,
                              pt_len, index_ct, index_nonce);
  vault_zeroize(index_pt, pt_len);
  free(index_pt);
  index_pt = NULL;

  if (result != VAULT_OK) {
    goto cleanup;
  }

  // Open file for read+write
  fd = open(g_vault.path, O_RDWR);
  if (fd < 0) {
    LOGE("vault_save_index_only: failed to open vault for write");
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  struct stat st;
  if (fstat(fd, &st) != 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  // Calculate header size
  vault_header_t header;
  memset(&header, 0, sizeof(header));
  header.wrapped_mk_len = (uint32_t)g_vault.wrapped_mk_len;
  size_t header_size = header_total_size(&header);

  // Read old index section size
  lseek(fd, header_size, SEEK_SET);
  uint8_t old_idx_nonce[VAULT_NONCE_LEN];
  uint64_t old_idx_ct_len;
  if (read(fd, old_idx_nonce, VAULT_NONCE_LEN) != VAULT_NONCE_LEN ||
      read(fd, &old_idx_ct_len, sizeof(old_idx_ct_len)) !=
          sizeof(old_idx_ct_len)) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  size_t old_index_section_size =
      VAULT_NONCE_LEN + sizeof(uint64_t) + old_idx_ct_len;
  size_t new_index_section_size = VAULT_NONCE_LEN + sizeof(uint64_t) + ct_len;

  // SLOW PATH: Index size changed - need to adjust offsets
  // But still avoid copying data by using file truncation + append
  LOGI("vault_save_index_only: SLOW PATH - index size changed (%zu -> %zu)",
       old_index_section_size, new_index_section_size);

  int64_t offset_delta =
      (int64_t)new_index_section_size - (int64_t)old_index_section_size;

  // Adjust entry offsets
  for (uint32_t i = 0; i < g_vault.entry_count; i++) {
    vault_entry_t *entry = &entries_copy[i];
    if (entry->chunk_count > 0) {
      for (uint32_t c = 0; c < entry->chunk_count; c++) {
        int64_t adjusted = (int64_t)entry->chunks[c].offset + offset_delta;
        if (adjusted < 0) {
          result = VAULT_ERR_CORRUPTED;
          goto cleanup;
        }
        entry->chunks[c].offset = (uint64_t)adjusted;
      }
    } else {
      int64_t adjusted = (int64_t)entry->data_offset + offset_delta;
      if (adjusted < 0) {
        result = VAULT_ERR_CORRUPTED;
        goto cleanup;
      }
      entry->data_offset = (uint64_t)adjusted;
    }
  }

  // Re-serialize with adjusted offsets
  vault_zeroize(index_ct, ct_len);
  free(index_ct);
  index_ct = NULL;

  result = serialize_index(entries_copy, g_vault.entry_count, &index_pt,
                           &pt_len);
  if (result != VAULT_OK) {
    goto cleanup;
  }

  ct_len = pt_len + VAULT_TAG_LEN;
  index_ct = malloc(ct_len);
  if (!index_ct) {
    result = VAULT_ERR_MEMORY;
    goto cleanup;
  }

  result = vault_aead_encrypt(g_vault.master_key, NULL, NULL, 0, index_pt,
                              pt_len, index_ct, index_nonce);
  vault_zeroize(index_pt, pt_len);
  free(index_pt);
  index_pt = NULL;

  if (result != VAULT_OK) {
    goto cleanup;
  }

  // Unfortunately for size change, we need temp file approach
  // because we can't shift data blobs in place efficiently
  uint64_t file_size = (uint64_t)st.st_size;
  uint64_t content_size =
      (file_size > VAULT_HASH_LEN) ? file_size - VAULT_HASH_LEN : file_size;
  uint64_t data_start = header_size + old_index_section_size;
  uint64_t data_size =
      (content_size > data_start) ? content_size - data_start : 0;

  // Create temp file
  size_t path_len = strlen(g_vault.path);
  char *temp_path = malloc(path_len + 5);
  if (!temp_path) {
    result = VAULT_ERR_MEMORY;
    goto cleanup;
  }
  snprintf(temp_path, path_len + 5, "%s.tmp", g_vault.path);

  int fd_out = open(temp_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (fd_out < 0) {
    free(temp_path);
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  // Write header
  memcpy(header.magic, VAULT_MAGIC, VAULT_MAGIC_LEN);
  header.version = VAULT_VERSION;
  memcpy(header.vault_id, g_vault.vault_id, VAULT_ID_LEN);
  memcpy(header.kdf_salt, g_vault.salt, VAULT_SALT_LEN);
  header.kdf_mem = g_vault.kdf_mem;
  header.kdf_iter = g_vault.kdf_iter;
  header.kdf_parallel = g_vault.kdf_parallel;

  if (write(fd_out, &header, sizeof(header)) != sizeof(header) ||
      write(fd_out, g_vault.wrapped_mk, g_vault.wrapped_mk_len) !=
          (ssize_t)g_vault.wrapped_mk_len) {
    close(fd_out);
    unlink(temp_path);
    free(temp_path);
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  uint32_t crc = calculate_crc32((uint8_t *)&header, sizeof(header));
  write(fd_out, &crc, sizeof(crc));

  // Write index
  uint64_t ct_len_u64 = ct_len;
  if (write(fd_out, index_nonce, VAULT_NONCE_LEN) != VAULT_NONCE_LEN ||
      write(fd_out, &ct_len_u64, sizeof(ct_len_u64)) != sizeof(ct_len_u64) ||
      write(fd_out, index_ct, ct_len) != (ssize_t)ct_len) {
    close(fd_out);
    unlink(temp_path);
    free(temp_path);
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  // Copy data with 256KB buffer for speed
  if (data_size > 0) {
    lseek(fd, data_start, SEEK_SET);
    uint8_t buffer[256 * 1024]; // 256KB buffer for faster copy
    uint64_t remaining = data_size;
    while (remaining > 0) {
      size_t to_read =
          remaining > sizeof(buffer) ? sizeof(buffer) : (size_t)remaining;
      ssize_t read_len = read(fd, buffer, to_read);
      if (read_len <= 0) {
        close(fd_out);
        unlink(temp_path);
        free(temp_path);
        result = VAULT_ERR_IO;
        goto cleanup;
      }
      if (write(fd_out, buffer, read_len) != read_len) {
        close(fd_out);
        unlink(temp_path);
        free(temp_path);
        result = VAULT_ERR_IO;
        goto cleanup;
      }
      remaining -= read_len;
    }
  }

  result = append_integrity_hash(fd_out);
  if (result != VAULT_OK) {
    close(fd_out);
    unlink(temp_path);
    free(temp_path);
    goto cleanup;
  }

  fsync(fd_out);
  close(fd_out);

  // Atomic rename
  if (rename(temp_path, g_vault.path) != 0) {
    unlink(temp_path);
    free(temp_path);
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  fsync_parent_dir(g_vault.path);
  free(temp_path);

  free_entries_array(g_vault.entries, g_vault.entry_count);
  g_vault.entries = entries_copy;
  entries_copy = NULL;

  LOGI("vault_save_index_only: SLOW PATH complete");
  result = VAULT_OK;

cleanup:
  if (fd >= 0)
    close(fd);
  if (index_ct) {
    vault_zeroize(index_ct, ct_len);
    free(index_ct);
  }
  if (index_pt) {
    vault_zeroize(index_pt, pt_len);
    free(index_pt);
  }
  if (entries_copy) {
    free_entries_array(entries_copy, g_vault.entry_count);
  }

  return result;
}

static int log_append_entry(const vault_entry_t *new_entry,
                            const vault_payload_t *payload,
                            const char *chunk_dir) {
  int result = VAULT_OK;
  int fd = -1;
  uint8_t *index_record = NULL;
  size_t index_record_len = 0;
  uint8_t index_key[VAULT_KEY_LEN] = {0};
  uint8_t wrapped_index_key[WRAPPED_INDEX_KEY_SIZE] = {0};
  uint8_t *copy_buffer = NULL;
  vault_entry_t *entries = NULL;
  vault_entry_t *entry_copy = NULL;
  uint32_t new_count = g_vault.entry_count + 1;
  uint32_t entries_count = g_vault.entry_count;

  if (g_vault.commit_sequence == UINT64_MAX || new_count == 0)
    return VAULT_ERR_CORRUPTED;

  result = clone_entries(g_vault.entries, g_vault.entry_count, &entries);
  if (result != VAULT_OK)
    goto cleanup;
  vault_entry_t *resized =
      realloc(entries, new_count * sizeof(vault_entry_t));
  if (!resized) {
    result = VAULT_ERR_MEMORY;
    goto cleanup;
  }
  entries = resized;
  memset(&entries[g_vault.entry_count], 0, sizeof(vault_entry_t));
  entries_count = new_count;

  result = clone_entries(new_entry, 1, &entry_copy);
  if (result != VAULT_OK)
    goto cleanup;
  entries[g_vault.entry_count] = entry_copy[0];
  free(entry_copy);
  entry_copy = NULL;
  vault_entry_t *destination = &entries[g_vault.entry_count];

  fd = open(g_vault.path, O_RDWR);
  if (fd < 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  if (ftruncate(fd, (off_t)g_vault.committed_size) != 0 ||
      lseek(fd, (off_t)g_vault.committed_size, SEEK_SET) < 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  uint64_t output_offset = g_vault.committed_size;
  if (new_entry->chunk_count > 0) {
    if (chunk_dir) {
      copy_buffer = malloc(1024 * 1024);
      if (!copy_buffer) {
        result = VAULT_ERR_MEMORY;
        goto cleanup;
      }
    }
    for (uint32_t c = 0; c < new_entry->chunk_count; c++) {
      destination->chunks[c].offset = output_offset;
      if (payload) {
        size_t length = payload->chunk_lens[c];
        if (length > UINT32_MAX) {
          result = VAULT_ERR_INVALID_PARAM;
          goto cleanup;
        }
        destination->chunks[c].length = (uint32_t)length;
        result = write_all(fd, payload->chunks[c], length);
        if (result != VAULT_OK)
          goto cleanup;
        output_offset += length;
        continue;
      }

      size_t chunk_path_len = strlen(chunk_dir) + 32;
      char *chunk_path = malloc(chunk_path_len);
      if (!chunk_path) {
        result = VAULT_ERR_MEMORY;
        goto cleanup;
      }
      snprintf(chunk_path, chunk_path_len, "%s/chunk_%08u.enc", chunk_dir, c);
      int chunk_fd = open(chunk_path, O_RDONLY);
      free(chunk_path);
      if (chunk_fd < 0) {
        result = VAULT_ERR_IO;
        goto cleanup;
      }

      uint8_t nonce[VAULT_NONCE_LEN];
      result = read_all_at(chunk_fd, nonce, sizeof(nonce), 0);
      uint64_t length = new_entry->chunks[c].length;
      if (result == VAULT_OK &&
          sodium_memcmp(nonce, new_entry->chunks[c].nonce, sizeof(nonce)) != 0)
        result = VAULT_ERR_CORRUPTED;
      if (result == VAULT_OK)
        result = copy_ciphertext_range(chunk_fd, VAULT_NONCE_LEN, length, fd,
                                       copy_buffer, 1024 * 1024);
      close(chunk_fd);
      if (result != VAULT_OK)
        goto cleanup;
      destination->chunks[c].length = (uint32_t)length;
      output_offset += length;
    }
  } else {
    destination->data_offset = output_offset;
    destination->data_length = payload->data_len;
    result = write_all(fd, payload->data, payload->data_len);
    if (result != VAULT_OK)
      goto cleanup;
    output_offset += payload->data_len;
  }

  uint64_t sequence = g_vault.commit_sequence + 1;
  vault_random_bytes(index_key, sizeof(index_key));
  result = log_wrap_index_key(g_vault.master_key, g_vault.vault_id, sequence,
                              index_key, wrapped_index_key);
  if (result != VAULT_OK)
    goto cleanup;
  result = build_log_index_record(
      entries, new_count, index_key, g_vault.vault_id, sequence,
      &index_record, &index_record_len);
  if (result != VAULT_OK)
    goto cleanup;
  uint64_t index_offset = output_offset;
  result = write_all(fd, index_record, index_record_len);
  if (result != VAULT_OK || fsync(fd) != 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  uint64_t committed_size = index_offset + index_record_len;
  uint32_t next_slot = (g_vault.active_root_slot + 1) % VAULT_LOG_SLOT_COUNT;
  vault_log_slot_t root;
  result = log_fill_slot(
      &root, sequence, g_vault.vault_id, g_vault.salt, g_vault.kdf_mem,
      g_vault.kdf_iter, g_vault.kdf_parallel, g_vault.wrapped_mk,
      wrapped_index_key, index_offset, index_record_len, committed_size,
      g_vault.master_key);
  if (result != VAULT_OK)
    goto cleanup;
  result = log_write_slot(fd, next_slot, &root);
  if (result != VAULT_OK || fsync(fd) != 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  int mirror_result = log_write_slot(fd, g_vault.active_root_slot, &root);
  if (mirror_result != VAULT_OK || fsync(fd) != 0)
    LOGE("log_append_entry: failed to mirror committed root slot");

  free_entries_array(g_vault.entries, g_vault.entry_count);
  g_vault.entries = entries;
  g_vault.entry_count = new_count;
  entries = NULL;
  g_vault.commit_sequence = sequence;
  g_vault.committed_size = committed_size;
  g_vault.index_offset = index_offset;
  g_vault.index_length = index_record_len;
  g_vault.active_root_slot = next_slot;
  log_refresh_metrics();

cleanup:
  if (fd >= 0)
    close(fd);
  if (index_record) {
    vault_zeroize(index_record, index_record_len);
    free(index_record);
  }
  vault_zeroize(index_key, sizeof(index_key));
  vault_zeroize(wrapped_index_key, sizeof(wrapped_index_key));
  free(copy_buffer);
  if (entry_copy)
    free_entries_array(entry_copy, 1);
  if (entries)
    free_entries_array(entries, entries_count);
  return result;
}

/**
 * Append a new entry to the vault without rebuilding entire container.
 * Appends encrypted payload at end of file and updates index only.
 *
 * SECURITY:
 * - New payload is encrypted before write
 * - Existing data blobs remain untouched
 * - A fresh per-commit key authenticates the encrypted index
 * - The durable root-slot switch makes the append crash-safe
 *
 * @param new_entry Entry metadata (will be copied, caller retains ownership)
 * @param payload Encrypted payload data to append
 * @return VAULT_OK on success
 */
static int vault_append_entry_internal(const vault_entry_t *new_entry,
                                       const vault_payload_t *payload,
                                       const char *chunk_dir) {
  if (!g_vault.is_open || !g_vault.path) {
    LOGE("vault_append_entry: vault not open");
    return VAULT_ERR_NOT_OPEN;
  }
  if (!new_entry || (!payload && !chunk_dir) ||
      (chunk_dir && new_entry->chunk_count == 0) ||
      (payload && new_entry->chunk_count > 0 &&
       payload->chunk_count != new_entry->chunk_count)) {
    return VAULT_ERR_INVALID_PARAM;
  }

  if (g_vault.container_format == VAULT_CONTAINER_LOG)
    return log_append_entry(new_entry, payload, chunk_dir);

  int result = VAULT_OK;
  int fd_in = -1;
  int fd_out = -1;
  char *temp_path = NULL;
  uint8_t *index_pt = NULL;
  uint8_t *index_ct = NULL;
  size_t pt_len = 0;
  size_t ct_len = 0;
  uint8_t index_nonce[VAULT_NONCE_LEN];
  vault_entry_t *new_entries = NULL;

  LOGI("vault_append_entry: starting, current entries=%u", g_vault.entry_count);

  // Open original file
  fd_in = open(g_vault.path, O_RDONLY);
  if (fd_in < 0) {
    LOGE("vault_append_entry: failed to open vault");
    return VAULT_ERR_IO;
  }

  struct stat st;
  if (fstat(fd_in, &st) != 0) {
    close(fd_in);
    return VAULT_ERR_IO;
  }
  uint64_t file_size = (uint64_t)st.st_size;
  uint64_t content_size =
      (file_size > VAULT_HASH_LEN) ? file_size - VAULT_HASH_LEN : file_size;

  // Read header to get header size
  vault_header_t header;
  if (read(fd_in, &header, sizeof(header)) != sizeof(header)) {
    close(fd_in);
    return VAULT_ERR_IO;
  }
  size_t header_size = header_total_size(&header);

  // Read old index section size
  lseek(fd_in, header_size, SEEK_SET);
  uint8_t old_idx_nonce[VAULT_NONCE_LEN];
  uint64_t old_idx_ct_len;
  if (read(fd_in, old_idx_nonce, VAULT_NONCE_LEN) != VAULT_NONCE_LEN ||
      read(fd_in, &old_idx_ct_len, sizeof(old_idx_ct_len)) !=
          sizeof(old_idx_ct_len)) {
    close(fd_in);
    return VAULT_ERR_IO;
  }

  size_t old_index_section_size =
      VAULT_NONCE_LEN + sizeof(uint64_t) + old_idx_ct_len;
  uint64_t old_data_start = header_size + old_index_section_size;
  uint64_t old_data_size =
      (content_size > old_data_start) ? content_size - old_data_start : 0;

  // Calculate where new data will be appended (after current data)
  uint64_t new_data_offset = old_data_start + old_data_size;

  // Allocate new entries array (existing + 1 new)
  uint32_t new_count = g_vault.entry_count + 1;
  result = clone_entries(g_vault.entries, g_vault.entry_count, &new_entries);
  if (result != VAULT_OK)
    goto cleanup;
  vault_entry_t *resized =
      realloc(new_entries, new_count * sizeof(vault_entry_t));
  if (!resized) {
    free_entries_array(new_entries, g_vault.entry_count);
    new_entries = NULL;
    result = VAULT_ERR_MEMORY;
    goto cleanup;
  }
  new_entries = resized;
  memset(&new_entries[g_vault.entry_count], 0, sizeof(vault_entry_t));

  // Deep copy new entry
  {
    vault_entry_t *dst = &new_entries[g_vault.entry_count];
    memcpy(dst->file_id, new_entry->file_id, VAULT_ID_LEN);
    dst->type = new_entry->type;
    dst->created_at = new_entry->created_at;
    dst->name = new_entry->name ? strdup(new_entry->name) : NULL;
    dst->mime = new_entry->mime ? strdup(new_entry->mime) : NULL;
    dst->size = new_entry->size;
    dst->wrapped_dek_len = new_entry->wrapped_dek_len;
    if (new_entry->wrapped_dek && new_entry->wrapped_dek_len > 0) {
      dst->wrapped_dek = malloc(new_entry->wrapped_dek_len);
      if (!dst->wrapped_dek) {
        result = VAULT_ERR_MEMORY;
        goto cleanup;
      }
      memcpy(dst->wrapped_dek, new_entry->wrapped_dek,
             new_entry->wrapped_dek_len);
    }
    if (!dst->name || !dst->mime) {
      result = VAULT_ERR_MEMORY;
      goto cleanup;
    }
    dst->chunk_count = new_entry->chunk_count;

    // Set offsets for new entry's data
    if (new_entry->chunk_count > 0) {
      dst->chunks = malloc(new_entry->chunk_count * sizeof(dst->chunks[0]));
      if (!dst->chunks) {
        result = VAULT_ERR_MEMORY;
        goto cleanup;
      }
      for (uint32_t c = 0; c < new_entry->chunk_count; c++) {
        dst->chunks[c].offset = new_data_offset;
        dst->chunks[c].length =
            payload ? payload->chunk_lens[c] : new_entry->chunks[c].length;
        memcpy(dst->chunks[c].nonce, new_entry->chunks[c].nonce,
               VAULT_NONCE_LEN);
        new_data_offset += dst->chunks[c].length;
      }
    } else {
      dst->data_offset = new_data_offset;
      dst->data_length = payload->data_len;
      new_data_offset += payload->data_len;
    }
  }

  // Serialize new index
  result = serialize_index(new_entries, new_count, &index_pt, &pt_len);
  if (result != VAULT_OK) {
    goto cleanup;
  }

  ct_len = pt_len + VAULT_TAG_LEN;
  size_t new_index_section_size = VAULT_NONCE_LEN + sizeof(uint64_t) + ct_len;

  // Calculate offset delta
  int64_t offset_delta =
      (int64_t)new_index_section_size - (int64_t)old_index_section_size;

  // Adjust all entry offsets
  for (uint32_t i = 0; i < new_count; i++) {
    vault_entry_t *entry = &new_entries[i];
    if (entry->chunk_count > 0) {
      for (uint32_t c = 0; c < entry->chunk_count; c++) {
        int64_t adjusted = (int64_t)entry->chunks[c].offset + offset_delta;
        if (adjusted < 0) {
          result = VAULT_ERR_CORRUPTED;
          goto cleanup;
        }
        entry->chunks[c].offset = (uint64_t)adjusted;
      }
    } else {
      int64_t adjusted = (int64_t)entry->data_offset + offset_delta;
      if (adjusted < 0) {
        result = VAULT_ERR_CORRUPTED;
        goto cleanup;
      }
      entry->data_offset = (uint64_t)adjusted;
    }
  }

  // Re-serialize with adjusted offsets
  vault_zeroize(index_pt, pt_len);
  free(index_pt);
  index_pt = NULL;

  result = serialize_index(new_entries, new_count, &index_pt, &pt_len);
  if (result != VAULT_OK) {
    goto cleanup;
  }

  ct_len = pt_len + VAULT_TAG_LEN;
  index_ct = malloc(ct_len);
  if (!index_ct) {
    result = VAULT_ERR_MEMORY;
    goto cleanup;
  }

  result = vault_aead_encrypt(g_vault.master_key, NULL, NULL, 0, index_pt,
                              pt_len, index_ct, index_nonce);
  vault_zeroize(index_pt, pt_len);
  free(index_pt);
  index_pt = NULL;

  if (result != VAULT_OK) {
    goto cleanup;
  }

  // Create temp file
  // ponytail: atomic commit needs free space for current vault + new payload;
  // switch to a journaled in-place append only if storage becomes the bottleneck.
  size_t path_len = strlen(g_vault.path);
  temp_path = malloc(path_len + 5);
  if (!temp_path) {
    result = VAULT_ERR_MEMORY;
    goto cleanup;
  }
  snprintf(temp_path, path_len + 5, "%s.tmp", g_vault.path);

  fd_out = open(temp_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (fd_out < 0) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  // Write header
  memset(&header, 0, sizeof(header));
  memcpy(header.magic, VAULT_MAGIC, VAULT_MAGIC_LEN);
  header.version = VAULT_VERSION;
  memcpy(header.vault_id, g_vault.vault_id, VAULT_ID_LEN);
  memcpy(header.kdf_salt, g_vault.salt, VAULT_SALT_LEN);
  header.kdf_mem = g_vault.kdf_mem;
  header.kdf_iter = g_vault.kdf_iter;
  header.kdf_parallel = g_vault.kdf_parallel;
  header.wrapped_mk_len = (uint32_t)g_vault.wrapped_mk_len;

  if (write(fd_out, &header, sizeof(header)) != sizeof(header)) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  if (write(fd_out, g_vault.wrapped_mk, g_vault.wrapped_mk_len) !=
      (ssize_t)g_vault.wrapped_mk_len) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  uint32_t crc = calculate_crc32((uint8_t *)&header, sizeof(header));
  if (write(fd_out, &crc, sizeof(crc)) != sizeof(crc)) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  // Write new index section
  uint64_t ct_len_u64 = ct_len;
  if (write(fd_out, index_nonce, VAULT_NONCE_LEN) != VAULT_NONCE_LEN) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  if (write(fd_out, &ct_len_u64, sizeof(ct_len_u64)) != sizeof(ct_len_u64)) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  if (write(fd_out, index_ct, ct_len) != (ssize_t)ct_len) {
    result = VAULT_ERR_IO;
    goto cleanup;
  }

  // Copy existing data blobs with 256KB buffer for speed
  if (old_data_size > 0) {
    lseek(fd_in, old_data_start, SEEK_SET);

    uint8_t buffer[256 * 1024]; // 256KB for faster copy
    uint64_t remaining = old_data_size;
    while (remaining > 0) {
      size_t to_read =
          remaining > sizeof(buffer) ? sizeof(buffer) : (size_t)remaining;
      ssize_t read_len = read(fd_in, buffer, to_read);
      if (read_len <= 0) {
        result = VAULT_ERR_IO;
        goto cleanup;
      }
      if (write(fd_out, buffer, read_len) != read_len) {
        result = VAULT_ERR_IO;
        goto cleanup;
      }
      remaining -= read_len;
    }
  }

  close(fd_in);
  fd_in = -1;

  // Write new payload
  if (new_entry->chunk_count > 0) {
    for (uint32_t c = 0; c < new_entry->chunk_count; c++) {
      if (payload) {
        if (write(fd_out, payload->chunks[c], payload->chunk_lens[c]) !=
            (ssize_t)payload->chunk_lens[c]) {
          result = VAULT_ERR_IO;
          goto cleanup;
        }
        continue;
      }

      size_t chunk_path_len = strlen(chunk_dir) + 32;
      char *chunk_path = malloc(chunk_path_len);
      if (!chunk_path) {
        result = VAULT_ERR_MEMORY;
        goto cleanup;
      }
      snprintf(chunk_path, chunk_path_len, "%s/chunk_%08u.enc", chunk_dir, c);
      int chunk_fd = open(chunk_path, O_RDONLY);
      free(chunk_path);
      if (chunk_fd < 0) {
        result = VAULT_ERR_IO;
        goto cleanup;
      }

      uint8_t nonce[VAULT_NONCE_LEN];
      if (read(chunk_fd, nonce, sizeof(nonce)) != sizeof(nonce) ||
          sodium_memcmp(nonce, new_entry->chunks[c].nonce, sizeof(nonce)) != 0) {
        close(chunk_fd);
        result = VAULT_ERR_CORRUPTED;
        goto cleanup;
      }

      uint64_t remaining = new_entry->chunks[c].length;
      uint8_t buffer[256 * 1024];
      while (remaining > 0) {
        size_t to_read =
            remaining > sizeof(buffer) ? sizeof(buffer) : (size_t)remaining;
        ssize_t read_len = read(chunk_fd, buffer, to_read);
        if (read_len <= 0 || write(fd_out, buffer, read_len) != read_len) {
          close(chunk_fd);
          result = VAULT_ERR_IO;
          goto cleanup;
        }
        remaining -= (uint64_t)read_len;
      }
      close(chunk_fd);
    }
  } else {
    if (write(fd_out, payload->data, payload->data_len) !=
        (ssize_t)payload->data_len) {
      result = VAULT_ERR_IO;
      goto cleanup;
    }
  }

  result = append_integrity_hash(fd_out);
  if (result != VAULT_OK) {
    goto cleanup;
  }

  fsync(fd_out);
  close(fd_out);
  fd_out = -1;

  // Atomic rename
  if (rename(temp_path, g_vault.path) != 0) {
    unlink(temp_path);
    result = VAULT_ERR_IO;
    goto cleanup;
  }
  fsync_parent_dir(g_vault.path);

  // Update in-memory state: free old entries, use new ones
  if (g_vault.entries) {
    free_entries_array(g_vault.entries, g_vault.entry_count);
  }
  g_vault.entries = new_entries;
  g_vault.entry_count = new_count;
  new_entries = NULL; // Ownership transferred

  LOGI("vault_append_entry: completed successfully, new count=%u",
       g_vault.entry_count);
  result = VAULT_OK;

cleanup:
  if (fd_in >= 0)
    close(fd_in);
  if (fd_out >= 0) {
    close(fd_out);
    if (temp_path)
      unlink(temp_path);
  }
  if (new_entries) {
    free_entries_array(new_entries, new_count);
  }
  if (index_pt) {
    vault_zeroize(index_pt, pt_len);
    free(index_pt);
  }
  if (index_ct) {
    vault_zeroize(index_ct, ct_len);
    free(index_ct);
  }
  if (temp_path)
    free(temp_path);

  return result;
}

int vault_append_entry(const vault_entry_t *new_entry,
                       const vault_payload_t *payload) {
  return vault_append_entry_internal(new_entry, payload, NULL);
}

int vault_append_entry_from_chunk_dir(const vault_entry_t *new_entry,
                                      const char *chunk_dir) {
  return vault_append_entry_internal(new_entry, NULL, chunk_dir);
}
