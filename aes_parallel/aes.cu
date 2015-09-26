#include "aes.h"

// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];

// The array that stores the round keys.
//__device__ static const uint8_t* RoundKey;

__device__ uintmax_t get_global_index(void)
{
	return blockIdx.x * blockDim.x + threadIdx.x;
}

// prints string as hex
__device__ static void phex(uint8_t* str) {
	unsigned char i;
	for (i = 0; i < 16; ++i)
		printf("%.2x", str[i]);
	printf("\n");
}

__device__ static void print_state(state_t* state, char message[]) {
	uintmax_t idx = get_global_index();
	uint8_t i, j;
	
	//for (i = 0; i < 4; i++) 
	printf("[thread %lld] state %s\n%.2x %.2x %.2x %.2x\n%.2x %.2x %.2x %.2x\n%.2x %.2x %.2x %.2x\n%.2x %.2x %.2x %.2x\n", idx, message, 
		(*state)[0][0], (*state)[0][1], (*state)[0][2], (*state)[0][3],
		(*state)[1][0], (*state)[1][1], (*state)[1][2], (*state)[1][3],
		(*state)[2][0], (*state)[2][1], (*state)[2][2], (*state)[2][3],
		(*state)[3][0], (*state)[3][1], (*state)[3][2], (*state)[3][3]);
}


//
//__device__ static void printKey() {
//	printf("RoundKey:\n");
//	unsigned char i, j;
//	for (j = 0; j < ROUNDS + 1; ++j) {
//		for (i = 0; i < KEYLENGTH; ++i)
//			printf("%.2x", RoundKey[(j*KEYLENGTH) + i]);
//		printf("\n");
//	}
//}

// Lookup-tables
__device__ __constant__ uint8_t d_sbox[256] = {
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

// XOR the round key on state.
__device__ void AddRoundKey(state_t* state, uint8_t* roundKey, uint8_t round) {
	uintmax_t idx = get_global_index();

	//printf("[Thread %lld] roundKey: %.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x\n", idx,
	//	roundKey[round*BLOCKSIZE + 0], roundKey[round*BLOCKSIZE + 1], roundKey[round*BLOCKSIZE + 2], roundKey[round*BLOCKSIZE + 3], 
	//	roundKey[round*BLOCKSIZE + 4], roundKey[round*BLOCKSIZE + 5], roundKey[round*BLOCKSIZE + 6], roundKey[round*BLOCKSIZE + 7], 
	//	roundKey[round*BLOCKSIZE + 8], roundKey[round*BLOCKSIZE + 9], roundKey[round*BLOCKSIZE + 10], roundKey[round*BLOCKSIZE + 11], 
	//	roundKey[round*BLOCKSIZE + 12], roundKey[round*BLOCKSIZE + 13], roundKey[round*BLOCKSIZE + 14], roundKey[round*BLOCKSIZE + 15]);

	uint8_t i, j;
	for (i = 0; i<4; ++i) {
		for (j = 0; j < 4; ++j) {
			//printf("[Thread %lld] (*state)[%d][%d] before: %.2x\n", idx, i, j, (*state)[i][j]);
			(*state)[i][j] ^= roundKey[round * LANESIZE * 4 + i * LANESIZE + j];
			//printf("[Thread %lld] (*state)[%d][%d] after: %.2x\n", idx, i, j, (*state)[i][j]);
		}
	}
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
__device__ void SubBytes(state_t* state)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[j][i] = d_sbox[(*state)[j][i]];
		}
	}
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
__device__ void ShiftRows(state_t* state)
{
	uint8_t temp;

	// Rotate first row 1 columns to left  
	temp = (*state)[0][1];
	(*state)[0][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[3][1];
	(*state)[3][1] = temp;

	// Rotate second row 2 columns to left  
	temp = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;

	temp = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;

	// Rotate third row 3 columns to left
	temp = (*state)[0][3];
	(*state)[0][3] = (*state)[3][3];
	(*state)[3][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[1][3];
	(*state)[1][3] = temp;
}

__device__ uint8_t xtime(uint8_t x)
{
	return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
__device__ void MixColumns(state_t* state)
{
	uint8_t i;
	uint8_t Tmp, Tm, t;
	for (i = 0; i < 4; ++i)
	{
		t = (*state)[i][0];
		Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
		Tm = (*state)[i][0] ^ (*state)[i][1]; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp;
		Tm = (*state)[i][1] ^ (*state)[i][2]; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp;
		Tm = (*state)[i][2] ^ (*state)[i][3]; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp;
		Tm = (*state)[i][3] ^ t;        Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp;
	}
}

// Cipher is the main function that encrypts the PlainText.
__device__ void Cipher(state_t* state, uint8_t* roundKey)
{
	uint8_t round = 0;

	// Add the First round key to the state before starting the rounds.
	AddRoundKey(state, roundKey, round);

	//print_state(state, "after first round key added");

	// There will be ROUNDS rounds.
	// The first ROUNDS-1 rounds are identical.
	// These ROUNDS-1 rounds are executed in the loop below.
	for (round = 1; round < ROUNDS; ++round)
	{
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, roundKey, round);
		//print_state(state, "after round key added");
	}

	// The last round is given below.
	// The MixColumns function is not here in the last round.
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, roundKey, ROUNDS);

	//print_state(state, "after last round key added");
}

__device__ void AES128_ECB_encrypt(uint8_t* ciphertext_block, uint8_t* roundKey) {
	state_t* state = (state_t*)ciphertext_block;
	//print_state(state, "after init");

	// The next function call encrypts the PlainText with the Key using AES algorithm.
	Cipher(state, roundKey);
}

__global__ void cuda_encrypt_block(uint8_t* d_ciphertext, uint8_t* d_plaintext, uint8_t* d_roundKey, uintmax_t plaintext_blocks) {
	uintmax_t idx = blockIdx.x * blockDim.x + threadIdx.x;
	__shared__ uint8_t s_roundKey[BLOCKSIZE * (ROUNDS + 1)];
	__shared__ uint8_t s_ciphertext[BLOCKSIZE * THREADS_PER_BLOCK];

	// first thraed of a block copies round key into shared memory
	if (idx % THREADS_PER_BLOCK == 0) {

		// TODO allocate shared round key by ROUNDS+1 threads in parallel. In this case, we must assure the kernel is launched with at least ROUNDS+1 threads per block.
		uint8_t j;
		for (j = 0; j < BLOCKSIZE*(ROUNDS + 1); j++) {
			//printf("s_roundkey[%d] = d_roundKey[%d] = %.2x\n", j, j, d_roundKey[j]);
			s_roundKey[j] = d_roundKey[j];
		}

	}

	__syncthreads();

	if (idx < plaintext_blocks) {
		uint64_t offset = idx*BLOCKSIZE;
		
		// copy plaintext block to be encrypted by this thread into shared ciphertext array
		uint8_t i;

		/*for (i = 0; i < BLOCKSIZE; i++) {
			s_ciphertext[offset + i] = d_plaintext[offset + i];
		}*/
		
		// test kernel function by just copying the plaintext on the device to the ciphertext on the device
		memcpy(d_ciphertext + offset, d_plaintext + offset, BLOCKSIZE);

		// each plaintext block is encrypted by an individual thread
		AES128_ECB_encrypt(d_ciphertext + offset, s_roundKey);
		//memcpy(d_ciphertext + offset, s_ciphertext + offset, sizeof(uint8_t)*BLOCKSIZE);
	}
}