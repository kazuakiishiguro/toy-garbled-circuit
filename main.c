#include <string.h>
#include <openssl/evp.h>

/**
 * Key derivation function.
 * Concatenates two 160byte keys and generates a new 16-byte key using SHAKE128.
 * @param key1 First 16-byte key.
 * @param key2 Second 16-byte key.
 * @param result Output 16-byte derived key.
 */
void key_derivation(const unsigned char key1[16], const unsigned char key2[16], unsigned char result[16]) {
  unsigned char concatenated_keys[32];
  memcpy(concatenated_keys, key1, 16);
  memcpy(concatenated_keys + 16, key2, 16);

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) {
    fprintf(stderr, "Error initializing EVP_MD_CTX\n");
    exit(EXIT_FAILURE);
  }

  if (EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL) != 1 ||
      EVP_DigestUpdate(mdctx, concatenated_keys, 32) != 1 ||
      EVP_DigestFinalXOF(mdctx, result, 16) != 1) {
    fprintf(stderr, "Error during SHAKE128 hasing\n");
    EVP_MD_CTX_free(mdctx);
    exit(EXIT_FAILURE);
  }

  EVP_MD_CTX_free(mdctx);
}
