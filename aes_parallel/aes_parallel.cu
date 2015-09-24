#define DEBUG 0

#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "aes.h"

static int encrypt_file(char* outfile, char* infile);
static void phex(uint8_t* str);

// The array that stores the round keys.
static uint8_t roundKey[176];
// The array that holds the plaintext for the current block.
uint8_t plaintext_block[BLOCKSIZE];
// The array that stores the ciphertext for the current block.
uint8_t ciphertext_block[BLOCKSIZE];

// 128bit key
uint8_t key[16] = { (uint8_t)0x2b, (uint8_t)0x7e, (uint8_t)0x15, (uint8_t)0x16,
					(uint8_t)0x28, (uint8_t)0xae, (uint8_t)0xd2, (uint8_t)0xa6,
					(uint8_t)0xab, (uint8_t)0xf7, (uint8_t)0x15, (uint8_t)0x88,
					(uint8_t)0x09, (uint8_t)0xcf, (uint8_t)0x4f, (uint8_t)0x3c };

char* INPUT_FILE = "../testdata/plaintext";
char* OUTPUT_FILE = "../testdata/ciphertext";

int main() {
	return encrypt_file(OUTPUT_FILE, INPUT_FILE);
}

int encrypt_file(char* outfile, char* infile) {
	uint64_t number_of_blocks = 0;
	size_t current_blocksize = 0;
	FILE *fp_in;
	FILE *fp_out;

	fp_in = fopen(infile, "rb");
	if (fp_in == NULL) {
		fprintf(stderr, "Can't open input file %s!\n", infile);
		return 1;
	}
	fp_out = fopen(outfile, "wb+");
	if (fp_out == NULL) {
		fprintf(stderr, "Can't open output file %s!\n", outfile);
		return 1;
	}

	//KeyExpansion(roundKey, key);

	fseek(fp_in, 0, SEEK_END);
	uint64_t size = ftell(fp_in);
	rewind(fp_in);
	uint8_t* plaintext = (uint8_t*)malloc(size);
	uint64_t bytes_read = fread(plaintext, sizeof(uint8_t), size, fp_in);
	number_of_blocks = bytes_read / BLOCKSIZE; // TODO take care of input that does not fit the blocksize

	printf("file size: %llu bytes\n", size);
	printf("bytes_read: %llu bytes\n", bytes_read);
	printf("Number of 16 byte blocks: %llu\n", number_of_blocks);

#if defined(DEBUG) && DEBUG
	printf("Plaintext:\n");
	uint8_t i;
	for (i = 0; i < number_of_blocks; i++) {
		phex(plaintext + (i * BLOCKSIZE));
	}
#endif
	

	//	do {
//		current_blocksize = read_plaintext_block(fp_in);
//		if (current_blocksize == 0)
//			break;
//
//		number_of_blocks++;
//
//#if defined(DEBUG) && DEBUG
//		uint8_t print_plaintext_block[16];
//
//		if (current_blocksize > 0) {
//			memcpy(print_plaintext_block, plaintext_block, 16);
//			printf("plaintext block %d:\n", number_of_blocks);
//			phex(print_plaintext_block);
//		}
//#endif
//
//		// encrypt plaintext block
//		//AES128_ECB_encrypt(plaintext_block, roundKey, ciphertext_block);
//
//		// write ciphertext block to output file
//		//fwrite(ciphertext_block, sizeof(uint8_t), BLOCKSIZE, fp_out);
//
//#if defined(DEBUG) && DEBUG
//		printf("chipertext block %d:\n", number_of_blocks);
//		phex(ciphertext_block);
//		printf("\n");
//#endif
//
//	} while (current_blocksize >= BLOCKSIZE);
//
	fclose(fp_in);
	fclose(fp_out);

	printf("\nEncryption of %llu 128-bit plaintext blocks successful!\n", number_of_blocks);
	return 0;
}

// prints string as hex
static void phex(uint8_t* str)
{
	unsigned char i;
	for (i = 0; i < 16; ++i)
		printf("%.2x", str[i]);
	printf("\n");
}