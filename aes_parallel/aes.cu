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
//
//static uint8_t getSBoxValue(uint8_t num) {
//	return sbox[num];
//}
//
// XOR the round key on state.
__device__ void AddRoundKey(state_t* state, uint8_t* roundKey, uint8_t round) {
	uintmax_t idx = get_global_index();

	//printf("[Thread %lld] roundKey: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n", idx,
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
//
//// The SubBytes Function Substitutes the values in the
//// state matrix with values in an S-box.
//static void SubBytes(void)
//{
//	uint8_t i, j;
//	for (i = 0; i < 4; ++i)
//	{
//		for (j = 0; j < 4; ++j)
//		{
//			(*state)[j][i] = getSBoxValue((*state)[j][i]);
//		}
//	}
//}
//
//// The ShiftRows() function shifts the rows in the state to the left.
//// Each row is shifted with different offset.
//// Offset = Row number. So the first row is not shifted.
//static void ShiftRows(void)
//{
//	uint8_t temp;
//
//	// Rotate first row 1 columns to left  
//	temp = (*state)[0][1];
//	(*state)[0][1] = (*state)[1][1];
//	(*state)[1][1] = (*state)[2][1];
//	(*state)[2][1] = (*state)[3][1];
//	(*state)[3][1] = temp;
//
//	// Rotate second row 2 columns to left  
//	temp = (*state)[0][2];
//	(*state)[0][2] = (*state)[2][2];
//	(*state)[2][2] = temp;
//
//	temp = (*state)[1][2];
//	(*state)[1][2] = (*state)[3][2];
//	(*state)[3][2] = temp;
//
//	// Rotate third row 3 columns to left
//	temp = (*state)[0][3];
//	(*state)[0][3] = (*state)[3][3];
//	(*state)[3][3] = (*state)[2][3];
//	(*state)[2][3] = (*state)[1][3];
//	(*state)[1][3] = temp;
//}
//
//static uint8_t xtime(uint8_t x)
//{
//	return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
//}
//
//// MixColumns function mixes the columns of the state matrix
//static void MixColumns(void)
//{
//	uint8_t i;
//	uint8_t Tmp, Tm, t;
//	for (i = 0; i < 4; ++i)
//	{
//		t = (*state)[i][0];
//		Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
//		Tm = (*state)[i][0] ^ (*state)[i][1]; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp;
//		Tm = (*state)[i][1] ^ (*state)[i][2]; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp;
//		Tm = (*state)[i][2] ^ (*state)[i][3]; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp;
//		Tm = (*state)[i][3] ^ t;        Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp;
//	}
//}
//
//static uint8_t Multiply(uint8_t x, uint8_t y)
//{
//	return (((y & 1) * x) ^
//		((y >> 1 & 1) * xtime(x)) ^
//		((y >> 2 & 1) * xtime(xtime(x))) ^
//		((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
//		((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
//}
//
// Cipher is the main function that encrypts the PlainText.
__device__ void Cipher(state_t* state, uint8_t* roundKey)
{
	uint8_t round = 0;

	// Add the First round key to the state before starting the rounds.
	AddRoundKey(state, roundKey, round);

	print_state(state, "after first round key added");

	// There will be ROUNDS rounds.
	// The first ROUNDS-1 rounds are identical.
	// These ROUNDS-1 rounds are executed in the loop below.
	for (round = 1; round < ROUNDS; ++round)
	{
		//SubBytes();
		//ShiftRows();
		//MixColumns();
		AddRoundKey(state, roundKey, round);
		print_state(state, "after round key added");
	}

	//// The last round is given below.
	//// The MixColumns function is not here in the last round.
	//SubBytes();
	//ShiftRows();
	AddRoundKey(state, roundKey, ROUNDS);

	print_state(state, "after last round key added");
}

__device__ void AES128_ECB_encrypt(uint8_t* ciphertext_block, uint8_t* roundKey) {
	state_t* state = (state_t*)ciphertext_block;
	print_state(state, "after init");

	// The next function call encrypts the PlainText with the Key using AES algorithm.
	Cipher(state, roundKey);
}

__global__ void cuda_encrypt_block(uint8_t* d_ciphertext, uint8_t* d_plaintext, uint8_t* d_roundKey, uintmax_t plaintext_blocks) {
	uintmax_t idx = blockIdx.x * blockDim.x + threadIdx.x;

	if (idx == 0) {

		printf("[Thread %lld] roundKey: %.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x\n%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x\n", idx,
			d_roundKey[0], d_roundKey[1], d_roundKey[2], d_roundKey[3],
			d_roundKey[4], d_roundKey[5], d_roundKey[6], d_roundKey[7],
			d_roundKey[8], d_roundKey[9], d_roundKey[10], d_roundKey[11],
			d_roundKey[12], d_roundKey[13], d_roundKey[14], d_roundKey[15],
			d_roundKey[16], d_roundKey[17], d_roundKey[18], d_roundKey[19],
			d_roundKey[20], d_roundKey[21], d_roundKey[22], d_roundKey[23],
			d_roundKey[24], d_roundKey[25], d_roundKey[26], d_roundKey[27],
			d_roundKey[28], d_roundKey[29], d_roundKey[30], d_roundKey[31]);
	}

	if (idx < plaintext_blocks) {
		uint64_t offset = idx*BLOCKSIZE;
		
		// test kernel function by just copying the plaintext on the device to the ciphertext on the device
		memcpy(d_ciphertext + offset, d_plaintext + offset, BLOCKSIZE);

		// each plaintext block is encrypted by an individual thread
		AES128_ECB_encrypt(d_ciphertext + offset, d_roundKey);
	}
}