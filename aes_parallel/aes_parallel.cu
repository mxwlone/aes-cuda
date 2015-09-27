#define DEBUG 0

#include "aes.h"

static void encrypt_file(char* outfile, char* infile, uint8_t* key);
static void __host__ phex(uint8_t* str);

// The array that stores the round keys.
uint8_t h_roundKey[176];

char* INPUT_FILE = "../testdata/test_10k.bin";
char* OUTPUT_FILE = "../testdata/ciphertext_10k_parallel";

int main() {
	uint8_t key[16] = { (uint8_t)0x2b, (uint8_t)0x7e, (uint8_t)0x15, (uint8_t)0x16,
						(uint8_t)0x28, (uint8_t)0xae, (uint8_t)0xd2, (uint8_t)0xa6,
						(uint8_t)0xab, (uint8_t)0xf7, (uint8_t)0x15, (uint8_t)0x88,
						(uint8_t)0x09, (uint8_t)0xcf, (uint8_t)0x4f, (uint8_t)0x3c };

	encrypt_file(OUTPUT_FILE, INPUT_FILE, key);

	return 0;
}

void encrypt_file(char* outfile, char* infile, uint8_t* key) {
	uintmax_t plaintext_blocks = 0;
	FILE *fp_in;
	FILE *fp_out;
	cudaError_t cudaStatus;

#if defined(DEBUG) && DEBUG
	uint8_t i;
#endif

	fp_in = fopen(infile, "rb");
	if (fp_in == NULL) {
		fprintf(stderr, "Can't open input file %s!\n", infile);
		exit(1);
	}
	fp_out = fopen(outfile, "wb+");
	if (fp_out == NULL) {
		fprintf(stderr, "Can't open output file %s!\n", outfile);
		exit(1);
	}

	KeyExpansion(key);
	
#if defined(DEBUG) && DEBUG
	printf("Round Keys:\n");
	for (i = 0; i < ROUNDS + 1; i++) {
		phex(h_roundKey + (i * BLOCKSIZE));
	}
#endif

	// determine size of file, read file into h_plaintext and determine number of plaintext blocks
	fseek(fp_in, 0, SEEK_END);
	uintmax_t plaintext_size = ftell(fp_in);
	rewind(fp_in);
	uint8_t* h_plaintext = (uint8_t*)malloc(plaintext_size);
	uintmax_t bytes_read = fread(h_plaintext, sizeof(uint8_t), plaintext_size, fp_in);
	assert(bytes_read == plaintext_size);
	plaintext_blocks = (bytes_read + BLOCKSIZE - 1) / BLOCKSIZE;
	uint8_t* h_ciphertext = (uint8_t*)malloc(plaintext_blocks*BLOCKSIZE);

	printf("Encrypting file \"%s\"\n", infile);
	printf("File size: %llu bytes\n", plaintext_size);
	printf("Number of plaintext chunks: %llu (blocksize: %d bytes)\n", plaintext_blocks, BLOCKSIZE);

#if defined(DEBUG) && DEBUG
	printf("Plaintext:\n");
	for (i = 0; i < plaintext_blocks; i++) {
		phex(h_plaintext + (i * BLOCKSIZE));
	}
#endif

	// copy h_plaintext and h_roundKey into global device memory
	uint8_t* d_plaintext;
	cudaStatus = cudaMalloc((void**)&d_plaintext, sizeof(uint8_t) * (plaintext_blocks * BLOCKSIZE)); // TODO if last block is smaller than BLOCKSIZE, the block maybe needs to be initialized with zero bits, test if this has to be done
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMalloc failed!");
		goto Error;
	}

	// make sure the last block is padded with zero bytes by initializing the full array with zero bytes
	cudaStatus = cudaMemset(d_plaintext, 0, sizeof(uint8_t) * (plaintext_blocks * BLOCKSIZE));
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMemset failed!");
		goto Error;
	}

	cudaStatus = cudaMemcpy(d_plaintext, h_plaintext, sizeof(uint8_t)*plaintext_size, cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMemcpy failed!");
		goto Error;
	}

	uint8_t* d_roundKey;
	cudaMalloc((void**)&d_roundKey, sizeof(uint8_t)*BLOCKSIZE*(ROUNDS+1));
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMalloc failed!");
		goto Error;
	}

	cudaMemcpy(d_roundKey, h_roundKey, sizeof(uint8_t)*BLOCKSIZE*(ROUNDS + 1), cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMemcpy failed!");
		goto Error;
	}

	// allocate space for the ciphertext on the device
	uint8_t* d_ciphertext;
	cudaStatus = cudaMalloc((void**)&d_ciphertext, sizeof(uint8_t) * (plaintext_blocks * BLOCKSIZE));
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMalloc failed!");
		goto Error;
	}

	// initialize the ciphertext with all zero // this is not necessary, it seems
	//cudaStatus = cudaMemset(d_ciphertext, 0, sizeof(uint8_t) * (plaintext_blocks * BLOCKSIZE));
	//if (cudaStatus != cudaSuccess) {
	//	fprintf(stderr, "cudaMemset failed!");
	//	goto Error;
	//}

	uintmax_t threads_per_block = THREADS_PER_BLOCK;
	uintmax_t number_of_blocks = (plaintext_blocks + threads_per_block - 1) / threads_per_block;
	//uintmax_t shared_memory_size = (BLOCKSIZE * THREADS_PER_BLOCK);

	printf("Launching kernel with configuration:\n");
	printf("Threads per block: %lld\n", threads_per_block);
	printf("Number of blocks: %lld\n", number_of_blocks);
	//printf("Shared memory size: %lld\n", shared_memory_size);

	// reset last error
	cudaGetLastError();
	cuda_encrypt_block<<<number_of_blocks, threads_per_block/*,shared_memory_size*/>>>(d_ciphertext, d_plaintext, d_roundKey, plaintext_blocks);

	cudaStatus = cudaGetLastError();
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "Kernel launch failed: %s\n", cudaGetErrorString(cudaStatus));
		goto Error;
	}

	cudaStatus = cudaDeviceSynchronize();
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaDeviceSynchronize failed: %s\n", cudaGetErrorString(cudaStatus));
		goto Error;
	}

	// Copy ciphertext array from device memory to host memory.
	cudaStatus = cudaMemcpy(h_ciphertext, d_ciphertext, sizeof(uint8_t) * (plaintext_blocks * BLOCKSIZE), cudaMemcpyDeviceToHost);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMemcpy failed!");
		goto Error;
	}
	
#if defined(DEBUG) && DEBUG
	printf("Ciphertext after kernel returned:\n");
	for (i = 0; i < plaintext_blocks; i++) {
		phex(h_ciphertext + (i * BLOCKSIZE));
	}
#endif

	// write ciphertext to output file
	fwrite(h_ciphertext, sizeof(uint8_t), BLOCKSIZE * plaintext_blocks, fp_out);

//	// Copy roundkey array from device memory to host memory to check if it is correct
//	cudaStatus = cudaMemcpy(h_roundKey, d_roundKey, sizeof(uint8_t) * (BLOCKSIZE * (ROUNDS+1)), cudaMemcpyDeviceToHost);
//	if (cudaStatus != cudaSuccess) {
//		fprintf(stderr, "cudaMemcpy failed!");
//		goto Error;
//	}
//
//#if defined(DEBUG) && DEBUG
//	printf("Round Keys:\n");
//	for (i = 0; i < ROUNDS + 1; i++) {
//		phex(h_roundKey + (i * ROUNDS));
//	}
//#endif

//	// Copy plaintext array from device memory to host memory. // just to be able to print it
//	cudaStatus = cudaMemcpy(h_plaintext, d_plaintext, sizeof(uint8_t) * (plaintext_blocks * BLOCKSIZE), cudaMemcpyDeviceToHost);
//	if (cudaStatus != cudaSuccess) {
//		fprintf(stderr, "cudaMemcpy failed!");
//		goto Error;
//	}
//
//#if defined(DEBUG) && DEBUG
//	printf("Plaintext on device:\n");
//	for (i = 0; i < plaintext_blocks; i++) {
//		phex(h_plaintext + (i * BLOCKSIZE));
//	}
//#endif

	printf("\nEncryption of %llu 128-bit plaintext blocks successful!\n", plaintext_blocks);
	return;

Error:
	free(h_plaintext);
	free(h_ciphertext);
	free(h_roundKey);

	cudaFree(d_plaintext);
	cudaFree(d_ciphertext);
	cudaFree(d_roundKey);
	
	fclose(fp_in);
	fclose(fp_out);
	exit(1);	
}


// This function produces LANESIZE * (ROUNDS+1) round keys. The round keys are used in each round to decrypt the states. 
void KeyExpansion(uint8_t* key)
{
	uint32_t i, j, k;
	uint8_t tempa[4]; // Used for the column/row operations

	// The first round key is the key
	for (i = 0; i < KEYWORDS; ++i)
	{
		h_roundKey[(i * 4) + 0] = key[(i * 4) + 0];
		h_roundKey[(i * 4) + 1] = key[(i * 4) + 1];
		h_roundKey[(i * 4) + 2] = key[(i * 4) + 2];
		h_roundKey[(i * 4) + 3] = key[(i * 4) + 3];
	}

	// All other round keys are found from the previous round keys.
	for (; (i < (LANESIZE * (ROUNDS + 1))); ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			tempa[j] = h_roundKey[(i - 1) * 4 + j];
		}
		if (i % KEYWORDS == 0)
		{
			// This function rotates the 4 bytes in a word to the left once.
			// [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

			// Function RotWord()
			{
				k = tempa[0];
				tempa[0] = tempa[1];
				tempa[1] = tempa[2];
				tempa[2] = tempa[3];
				tempa[3] = k;
			}

			// SubWord() is a function that takes a four-byte input word and 
			// applies the S-box to each of the four bytes to produce an output word.

			// Function Subword()
	  {
		  tempa[0] = sbox[tempa[0]];
		  tempa[1] = sbox[tempa[1]];
		  tempa[2] = sbox[tempa[2]];
		  tempa[3] = sbox[tempa[3]];
	  }

			tempa[0] = tempa[0] ^ Rcon[i / KEYWORDS];
		}
		else if (KEYWORDS > 6 && i % KEYWORDS == 4)
		{
			// Function Subword()
			{
				tempa[0] = sbox[tempa[0]];
				tempa[1] = sbox[tempa[1]];
				tempa[2] = sbox[tempa[2]];
				tempa[3] = sbox[tempa[3]];
			}
		}
		h_roundKey[i * 4 + 0] = h_roundKey[(i - KEYWORDS) * 4 + 0] ^ tempa[0];
		h_roundKey[i * 4 + 1] = h_roundKey[(i - KEYWORDS) * 4 + 1] ^ tempa[1];
		h_roundKey[i * 4 + 2] = h_roundKey[(i - KEYWORDS) * 4 + 2] ^ tempa[2];
		h_roundKey[i * 4 + 3] = h_roundKey[(i - KEYWORDS) * 4 + 3] ^ tempa[3];
	}
}


// prints string as hex
static void phex(uint8_t* str)
{
	unsigned char i;
	for (i = 0; i < 16; ++i)
		printf("%.2x", str[i]);
	printf("\n");
}