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

/**
 * Oblivious transfer.
 * Implements the OT protocol from https://eprint.iacr.org/2015/267.pdf.
 * @param keys Array of two 16-byte keys.
 * @param bit The selector bit (0 or 1).
 * @param result Output 16-byte selected key.
 */
void oblivious_transfer(const unsigned char keys[2][16], uint8_t bit, unsigned char result[16]) {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *p = BN_new();
  BIGNUM *g = BN_new();
  BIGNUM *a_priv = BN_new();
  BIGNUM *b_priv = BN_new();
  BIGNUM *bit_bn = BN_new();
  BIGNUM *a_pub = BN_new();
  BIGNUM *b_pub = BN_new();
  BIGNUM *a_pub_inverse = BN_new();
  BIGNUM *tmp = BN_new();

  // Initialize p and g
  BN_dec2bn(&p, "8232614617976856279072317982427644624595758235537723089819576056282601872542631717078779952011141109568991428115823956738415293901639693425529719101034229");
  BN_set_word(g, 2);

  // Generate random a_priv and b_priv
  BN_rand(a_priv, 512, -1, 0);
  BN_rand(b_priv, 512, -1, 0);
  BN_set_word(bit_bn, bit);

  // Compute a_pub = g^a_priv mod p
  BN_mod_exp(a_pub, g, a_priv, p, ctx);

  // Compute b_pub = g^b_priv * a_pub^bit mod p
  BIGNUM *a_pub_pow_bit = BN_new();
  BN_mod_exp(a_pub_pow_bit, a_pub, bit_bn, p, ctx);

  BN_mod_exp(tmp, g, b_priv, p, ctx);
  BN_mod_mul(b_pub, tmp, a_pub_pow_bit, p, ctx);

  // Compute a_pub_inverse = a_pub^{-1} mod p
  BN_mod_inverse(a_pub_inverse, a_pub, p, ctx);

  // Compute keyr = hash_message(a_pub^{b_priv} mod p)
  BN_mod_exp(tmp, a_pub, b_priv, p, ctx);
  unsigned char keyr[16];
  hash_message(tmp, keyr);

  // Compute hashkey[0] and hashkey[1]
  unsigned char hashkey[2][16];

  // hashkey[0] = hash_message(b_pub^{a_priv} mod p)
  BN_mod_exp(tmp, b_pub, a_priv, p, ctx);
  hash_message(tmp, hashkey[0]);

  // hashkey[1] = hash_message((b_pub^{a_priv} * a_pub^{-a_priv}) mod p)
  BIGNUM *b_pub_a_priv = BN_new();
  BN_mod_exp(b_pub_a_priv, b_pub, a_priv, p, ctx);

  BIGNUM *a_pub_inv_a_priv = BN_new();
  BN_mod_exp(a_pub_inv_a_priv, a_pub_inverse, a_priv, p, ctx);

  BN_mod_mul(tmp, b_pub_a_priv, a_pub_inv_a_priv, p, ctx);
  hash_message(tmp, hashkey[1]);

  // Encrypt keys[0] and keys[1]
  unsigned char e[2][16];
  encryption(hashkey[0], keys[0], e[0]);
  encryption(hashkey[1], keys[1], e[1]);

  // Decrypt e[bit] with keyr
  decryption(keyr, e[bit], result);

  // Clean up
  BN_free(p);
  BN_free(g);
  BN_free(a_priv);
  BN_free(b_priv);
  BN_free(bit_bn);
  BN_free(a_pub);
  BN_free(b_pub);
  BN_free(a_pub_inverse);
  BN_free(tmp);
  BN_free(a_pub_pow_bit);
  BN_free(b_pub_a_priv);
  BN_free(a_pub_inv_a_priv);
  BN_CTX_free(ctx);
}

/**
 * Generates a garbled circuit for the given gate using provided keys.
 * @param keys 2x2 array of 16-byte keys.
 * @param gate The logic gate ("AND" or "XOR").
 * @param garbled_values Output array of 4 encrypted 16-byte blocks.
 */
void garbled_circuit(const unsigned char keys[2][2][16], const char *gate, unsigned char garbled_values[4][16]) {
    uint8_t table[4][3];
    truth_table(gate, table);

    // Generate encrypted values
    for (int i = 0; i < 4; ++i) {
        unsigned char encryption_key[16];
        key_derivation(keys[0][i >> 1], keys[1][i & 1], encryption_key);

        unsigned char padded_bit[16];
        pad(table[i][2], padded_bit);

        encryption(encryption_key, padded_bit, garbled_values[i]);
    }

    // Shuffle garbled_values
    for (int i = 3; i > 0; --i) {
        int j = rand() % (i + 1);
        unsigned char temp[16];
        memcpy(temp, garbled_values[i], 16);
        memcpy(garbled_values[i], garbled_values[j], 16);
        memcpy(garbled_values[j], temp, 16);
    }
}

/**
 * Main function implementing the garbled circuit protocol.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Exit status.
 */
int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s garbler|evaluator <bit> <gate>\n", argv[0]);
        return EXIT_FAILURE;
    }

    uint8_t garbler_bit;
    uint8_t evaluator_bit;
    unsigned char keys[2][2][16];
    unsigned char evaluator_key[16];
    unsigned char garbled_values[4][16];
    char *gate = argv[3];

    if (strcmp(argv[1], "garbler") == 0) {
        // Garbler mode
        garbler_bit = (uint8_t)atoi(argv[2]);

        // Read four 16-byte keys from user input
        printf("Enter four 32-digit hexadecimal keys (each key is 16 bytes in hex):\n");
        for (int i = 0; i < 4; ++i) {
            char hexkey[33];
            if (scanf("%32s", hexkey) != 1) {
                fprintf(stderr, "Error reading key\n");
                return EXIT_FAILURE;
            }
            for (int j = 0; j < 16; ++j) {
                sscanf(&hexkey[j * 2], "%2hhx", &keys[i >> 1][i & 1][j]);
            }
        }

        // Randomly generate evaluator's bit
        evaluator_bit = rand() % 2;
    } else {
        // Evaluator mode
        evaluator_bit = (uint8_t)atoi(argv[2]);

        // Generate random keys
        generate_random_keys(keys);

        // Randomly generate garbler's bit
        garbler_bit = rand() % 2;
    }

    // Generate garbled circuit
    garbled_circuit(keys, gate, garbled_values);

    // Evaluator obtains key via oblivious transfer
    oblivious_transfer(keys[1], evaluator_bit, evaluator_key);

    // Derive encryption key
    unsigned char encryption_key[16];
    key_derivation(keys[0][garbler_bit], evaluator_key, encryption_key);

    // Evaluator decrypts garbled values
    for (int i = 0; i < 4; ++i) {
        unsigned char decrypted_value[16];
        decryption(encryption_key, garbled_values[i], decrypted_value);
        int value = unpad(decrypted_value);
        if (value != -1) {
            printf("Result: %d\n", value);
            break;
        }
    }

    return EXIT_SUCCESS;
}
