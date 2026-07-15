#include "vault_engine.h"
#include <assert.h>

int main(void) {
  assert(vault_select_kdf_profile(2048, 1500, 0, 1) == KDF_PROFILE_LOW);
  assert(vault_select_kdf_profile(8192, 4000, 1, 1) == KDF_PROFILE_LOW);
  assert(vault_select_kdf_profile(8192, 4000, 0, 0) == KDF_PROFILE_LOW);
  assert(vault_select_kdf_profile(4096, 1500, 0, 1) == KDF_PROFILE_MEDIUM);
  assert(vault_select_kdf_profile(8192, 700, 0, 1) == KDF_PROFILE_MEDIUM);
  assert(vault_select_kdf_profile(8192, 2000, 0, 1) == KDF_PROFILE_HIGH);
  assert(vault_kdf_params_valid(32 * 1024 * 1024, 3, 1));
  assert(vault_kdf_params_valid(128 * 1024 * 1024, 10, 1));
  assert(vault_kdf_params_valid(256 * 1024 * 1024, 12, 1));
  assert(vault_kdf_params_valid(256 * 1024 * 1024, 12, 2));
  assert(!vault_kdf_params_valid(16 * 1024 * 1024, 3, 1));
  assert(!vault_kdf_params_valid(256 * 1024 * 1024, 3, 0));
  assert(!vault_kdf_params_valid(256 * 1024 * 1024, 3, 3));
  return 0;
}
