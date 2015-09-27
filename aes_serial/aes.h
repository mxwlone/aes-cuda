#include <stdint.h>
#include <time.h>

// blocksize in bytes
#define BLOCKSIZE 16
// The number of columns comprising a state in AES.
#define LANESIZE 4
// The number of 32 bit words in a key.
#define KEYWORDS 4
// Key length in bytes [128 bit]
#define KEYLENGTH 16
// The number of rounds in AES Cipher.
#define ROUNDS 10

void KeyExpansion(uint8_t* roundKey, uint8_t* key);

void AES128_ECB_encrypt(uint8_t* input, const uint8_t* key, uint8_t *output);