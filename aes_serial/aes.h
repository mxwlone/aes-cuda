#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

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




// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES128 encryption in CBC-mode of operation and handles 0-padding.
// ECB enables the basic ECB 16-byte block algorithm. Both can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef CBC
#define CBC 1
#endif

#ifndef ECB
#define ECB 1
#endif


void KeyExpansion(uint8_t* roundKey, uint8_t* key);

#if defined(ECB) && ECB

void AES128_ECB_encrypt(uint8_t* input, const uint8_t* key, uint8_t *output);
void AES128_ECB_decrypt(uint8_t* input, const uint8_t* key, uint8_t *output);

#endif // #if defined(ECB) && ECB




#endif //_AES_H_