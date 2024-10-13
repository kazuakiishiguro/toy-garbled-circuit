#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

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

/**
 * Padding function.
 * Pads a single bit into a 16-byte block.
 * @param bit The bit to pad (0 or 1).
 * @param result Output 16-byte padded block.
 */
void pad(uint8_t bit, unsigned char result[16]) {
  result[0] = bit;
  memset(result + 1, 0x0F, 15);
}

/**
 * Unpad function.
 * Checks if the padded block is valid and returns the bit.
 * @param padded_bit The 16-byte padded block.
 * @return The original bit (0 or 1) if valie, -1 otherwise.
 */
int unpad(const unsigned char padded_bit[16]) {
  for (int i = 1; i < 16; ++i) {
    if (padded_bit[i] != 0x0F)
      return -1;
  }
  return padded_bit[0];
}

/* TODO: Implement Encryption and Decryption functions */

/**
 * Hash function.
 * Hashes a big number using SHAEK128 to produce a 16-byte output.
 * @param message The big number to hash.
 * @param result Output 16-byte hash.
 */
void hash_message(const BIGNUM *message, unsigned char result[16]) {
  int message_len = BN_num_bytes(message);
  unsigned char *message_bytes = malloc(message_len);
  if (message_bytes == NULL) {
    fprintf(stderr, "Memory allocation error\n");
    exit(EXIT_FAILURE);
  }

  BN_bn2bin(message, message_bytes);

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) {
    fprintf(stderr, "Error initializing EVP_MD_CTX\n");
    free(message_bytes);
    exit(EXIT_FAILURE);
  }

  if (EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL) != 1 ||
      EVP_DigestUpdate(mdctx, message_bytes, message_len) != 1 ||
      EVP_DigestFinalXOF(mdctx, result, 16) != 1) {
    fprintf(stderr, "Error during SHAKE128 hasing\n");
    EVP_MD_CTX_free(mdctx);
    free(message_bytes);
    exit(EXIT_FAILURE);
  }

  EVP_MD_CTX_free(mdctx);
  free(message_bytes);
}

/**
 * Generates the truth table for a given gate.
 * @param gate The logic gate ("AND" or "XOR").
 * @param table Output 4x3 truth table.
 */
void truth_table(const char *gate, uint8_t table[4][3]) {
  if (strcmp(gate, "AND") == 0) {
    uint8_t temp_table[4][3] = {
      {0, 0, 0},
      {0, 1, 0},
      {1, 0, 0},
      {1, 1, 1},
    };
    memcpy(table, temp_table, sizeof(temp_table));
  } else if (strcmp(gate, "XOR") == 0) {
    uint8_t temp_table[4][3] = {
      {0, 0, 0},
      {0, 1, 1},
      {1, 0, 1},
      {1, 1, 0},
    };
    memcpy(table, temp_table, sizeof(temp_table));
  } else {
    fprintf(stderr, "Invalid gate type\n");
    exit(EXIT_FAILURE);
  }
}

/**
 * Generates random keys.
 * @param keys Output 2x2 array of 16-byte keys.
 */
void generate_random_keys(unsigned char keys[2][2][16]) {
  for (int i = 0; i < 2; ++i) {
    for (int j = 0; j < 2; ++j) {
      if (RAND_bytes(keys[i][j], 16) != 1) {
        fprintf(stderr, "Error generating random bytes\n");
        exit(EXIT_FAILURE);
      }
    }
  }
}
