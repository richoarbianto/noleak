#include "vault_streaming.h"
#include <assert.h>

int main(void) {
  size_t len = 0;
  const uint64_t fifty_gb = 50ULL * 1024 * 1024 * 1024;

  assert(streaming_chunk_plaintext_len(fifty_gb, STREAMING_CHUNK_SIZE, 12799,
                                       &len));
  assert(len == STREAMING_CHUNK_SIZE);
  assert(!streaming_chunk_plaintext_len(fifty_gb, STREAMING_CHUNK_SIZE, 12800,
                                        &len));
  assert(streaming_chunk_plaintext_len(fifty_gb - 1, STREAMING_CHUNK_SIZE,
                                       12799, &len));
  assert(len == STREAMING_CHUNK_SIZE - 1);
  assert(!streaming_chunk_plaintext_len(0, STREAMING_CHUNK_SIZE, 0, &len));
  return 0;
}
