#define DEBUG 0
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <Windows.h>

#include "aes.h"

static double encrypt_file(char* outfile, char* infile);
static size_t read_plaintext_block();
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

boolean silent = 0;

int main(int argc, char *argv[]) {
	if (argc < 3 || argc > 4) {
		printf("Usage: aes_serial.exe <input file> <output file> [--silent]\n", argv[0]);
		return 1;
	}

	if (argc == 4)
		if (!strcmp(argv[3], "--silent"))
			silent = 1;


	double cpu_time_used;
	cpu_time_used = encrypt_file(argv[1], argv[2]);
	printf("Execution time: %6.9f seconds\n", cpu_time_used);

	return 0;
}

double encrypt_file(char* infile, char* outfile) {
	FILE *fp_in;
	FILE *fp_out;

	fp_in = fopen(infile, "rb");
	if (fp_in == NULL && !silent) {
		fprintf(stderr, "Can't open input file %s!\n", infile);
		exit(1);
	}
	fp_out = fopen(outfile, "wb+");
	if (fp_out == NULL && !silent) {
		fprintf(stderr, "Can't open output file %s!\n", outfile);
		exit(1);
	}

	KeyExpansion(roundKey, key);

#if defined(DEBUG) && DEBUG
	printf("Round Keys:\n");
	uint8_t i;
	for (i = 0; i < ROUNDS + 1; i++) {
		phex(roundKey + (i * ROUNDS));
	}
#endif

	// determine size of file, read file into plaintext and determine number of plaintext blocks
	fseek(fp_in, 0, SEEK_END);
	uintmax_t plaintext_size = ftell(fp_in);
	rewind(fp_in);
	uint8_t* plaintext = (uint8_t*)malloc(plaintext_size);
	uintmax_t bytes_read = fread(plaintext, sizeof(uint8_t), plaintext_size, fp_in);
	assert(bytes_read == plaintext_size);
	uintmax_t plaintext_blocks = (bytes_read + BLOCKSIZE - 1) / BLOCKSIZE;
	uint8_t* ciphertext = (uint8_t*)malloc(plaintext_blocks*BLOCKSIZE);

	if (!silent) {
		printf("File size: %llu bytes\n", plaintext_size);
		printf("Number of plaintext blocks: %llu (blocksize: %d bytes)\n", plaintext_blocks, BLOCKSIZE);
	}

#if defined(DEBUG) && DEBUG
	printf("Plaintext:\n");
	for (i = 0; i < plaintext_blocks; i++) {
		phex(plaintext + (i * BLOCKSIZE));
	}
#endif

	// measure time
	double cpu_time_used;
	LARGE_INTEGER frequency;
	LARGE_INTEGER start, end;
	QueryPerformanceFrequency(&frequency);

	// start timer
	QueryPerformanceCounter(&start);

	uintmax_t j;
	for (j = 0; j < plaintext_blocks; j++) {

		// encrypt plaintext block
		AES128_ECB_encrypt(plaintext + j*BLOCKSIZE, roundKey, ciphertext_block);

		// write ciphertext block to output file
		memcpy(ciphertext + j*BLOCKSIZE, ciphertext_block, sizeof(uint8_t)*BLOCKSIZE);
	}

	// stop timer
	QueryPerformanceCounter(&end);
	cpu_time_used = ((double)(end.QuadPart - start.QuadPart)) / ((double)frequency.QuadPart);

	// write ciphertext to output file
	fwrite(ciphertext, sizeof(uint8_t), BLOCKSIZE * plaintext_blocks, fp_out);
	
#if defined(DEBUG) && DEBUG
	printf("Ciphertext:\n");
	for (i = 0; i < plaintext_blocks; i++) {
		phex(ciphertext + (i * BLOCKSIZE));
	}
#endif

	fclose(fp_in);
	fclose(fp_out);

	if (!silent)
		printf("Encryption of %llu plaintext blocks successful!\n", plaintext_blocks);
	
	return cpu_time_used;
}

// Reads one block of plaintext of size BLOCKSIZE bytes from the file pointed to by the pointer fp.
// If the last block does not match BLOCKSIZE bytes, the block is padded with zero bytes.
static size_t read_plaintext_block(FILE *fp) {
	size_t current_blocksize = fread(plaintext_block, sizeof(uint8_t), BLOCKSIZE, fp);

#if defined(DEBUG) && DEBUG
	if (feof(fp))
		printf("End-of-File reached.\n");
	if (ferror(fp))
		printf("An error occurred while accessing the file.\n");
	if (current_blocksize == 0) return 0;
	//printf("current_blocksize: %d\n", current_blocksize);
#endif

	if (current_blocksize == 0) return 0;

	// pad last block with zeroes if it does not match BLOCKSIZE
	if (current_blocksize < BLOCKSIZE) {
		uint8_t i;
		for (i = 0; current_blocksize + i < BLOCKSIZE; ++i) {
			plaintext_block[current_blocksize + i] = '0';
		}
	}

	return current_blocksize;
}

// prints string as hex
static void phex(uint8_t* str) {
    unsigned char i;
    for(i = 0; i < 16; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}