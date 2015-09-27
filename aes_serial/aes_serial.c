#define DEBUG 0
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "aes.h"

static int encrypt_file(char* outfile, char* infile);
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

// unused: file names are provided as parameters
char* INPUT_FILE = "../testdata/test_10mb.bin";
char* OUTPUT_FILE = "../testdata/ciphertext_10mb_serial";

int main(int argc, char *argv[]) {
	if (argc < 3) {
		printf("Usage: aes_serial.exe <input file> <output file>\n", argv[0]);
		return 1;
	}
	clock_t start, end;
	double cpu_time_used;
	uint8_t return_value;
	start = clock();

	return_value = encrypt_file(argv[1], argv[2]);
	if (return_value != 0)
		return 1;

	end = clock();
	cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
	printf("Execution time: %f seconds\n", cpu_time_used);

	return return_value;
}

int encrypt_file(char* infile, char* outfile) {
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

	KeyExpansion(roundKey, key);

#if defined(DEBUG) && DEBUG
	printf("Round Keys:\n");
	uint8_t i;
	for (i = 0; i < ROUNDS + 1; i++) {
		phex(roundKey + (i * ROUNDS));
	}
#endif

	printf("Encrypting file \"%s\"\n", infile);
	
	do {
		current_blocksize = read_plaintext_block(fp_in);
		if (current_blocksize == 0)
			break;

		number_of_blocks++;

#if defined(DEBUG) && DEBUG
		char print_plaintext_block[16];

		if (current_blocksize > 0) {
			strncpy(print_plaintext_block, plaintext_block, 16);
			printf("plaintext block %d:\n", number_of_blocks);
			phex(print_plaintext_block);
		}
#endif

		// encrypt plaintext block
		AES128_ECB_encrypt(plaintext_block, roundKey, ciphertext_block);

		// write ciphertext block to output file
		fwrite(ciphertext_block, sizeof(uint8_t), BLOCKSIZE, fp_out);
		
#if defined(DEBUG) && DEBUG
		printf("chipertext block %d:\n", number_of_blocks);
		phex(ciphertext_block);
		printf("\n");
#endif

	} while (current_blocksize >= BLOCKSIZE);
	
	fclose(fp_in);
	fclose(fp_out);

	printf("\nEncryption of %llu plaintext blocks successful!\n", number_of_blocks);
	return 0;
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