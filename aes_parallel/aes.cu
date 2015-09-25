#include "aes.h"

// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];
__device__ static state_t* state;

// The array that stores the round keys.
//__device__ static const uint8_t* RoundKey;

// prints string as hex
__device__ static void phex(uint8_t* str) {
	unsigned char i;
	for (i = 0; i < 16; ++i)
		printf("%.2x", str[i]);
	printf("\n");
}

__device__ static void print_state() {
	uint8_t i, j;
	printf("state:\n");
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++)
			printf("%.2x", (*state)[i][j]);
		printf("\n");
	}
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
//// This function produces LANESIZE * (ROUNDS+1) round keys. The round keys are used in each round to decrypt the states. 
//void KeyExpansion(uint8_t* roundKey, uint8_t* key)
//{
//	uint32_t i, j, k;
//	uint8_t tempa[4]; // Used for the column/row operations
//
//	// The first round key is the key
//	for (i = 0; i < KEYWORDS; ++i)
//	{
//		roundKey[(i * 4) + 0] = key[(i * 4) + 0];
//		roundKey[(i * 4) + 1] = key[(i * 4) + 1];
//		roundKey[(i * 4) + 2] = key[(i * 4) + 2];
//		roundKey[(i * 4) + 3] = key[(i * 4) + 3];
//	}
//
//	// All other round keys are found from the previous round keys.
//	for (; (i < (LANESIZE * (ROUNDS + 1))); ++i)
//	{
//		for (j = 0; j < 4; ++j)
//		{
//			tempa[j] = roundKey[(i - 1) * 4 + j];
//		}
//		if (i % KEYWORDS == 0)
//		{
//			// This function rotates the 4 bytes in a word to the left once.
//			// [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
//
//			// Function RotWord()
//			{
//				k = tempa[0];
//				tempa[0] = tempa[1];
//				tempa[1] = tempa[2];
//				tempa[2] = tempa[3];
//				tempa[3] = k;
//			}
//
//			// SubWord() is a function that takes a four-byte input word and 
//			// applies the S-box to each of the four bytes to produce an output word.
//
//			// Function Subword()
//	  {
//		  tempa[0] = getSBoxValue(tempa[0]);
//		  tempa[1] = getSBoxValue(tempa[1]);
//		  tempa[2] = getSBoxValue(tempa[2]);
//		  tempa[3] = getSBoxValue(tempa[3]);
//	  }
//
//			tempa[0] = tempa[0] ^ Rcon[i / KEYWORDS];
//		}
//		else if (KEYWORDS > 6 && i % KEYWORDS == 4)
//		{
//			// Function Subword()
//			{
//				tempa[0] = getSBoxValue(tempa[0]);
//				tempa[1] = getSBoxValue(tempa[1]);
//				tempa[2] = getSBoxValue(tempa[2]);
//				tempa[3] = getSBoxValue(tempa[3]);
//			}
//		}
//		roundKey[i * 4 + 0] = roundKey[(i - KEYWORDS) * 4 + 0] ^ tempa[0];
//		roundKey[i * 4 + 1] = roundKey[(i - KEYWORDS) * 4 + 1] ^ tempa[1];
//		roundKey[i * 4 + 2] = roundKey[(i - KEYWORDS) * 4 + 2] ^ tempa[2];
//		roundKey[i * 4 + 3] = roundKey[(i - KEYWORDS) * 4 + 3] ^ tempa[3];
//	}
//}
//
//
//// XOR the round key on state.
//static void AddRoundKey(uint8_t round) {
//	uint8_t i, j;
//	for (i = 0; i<4; ++i) {
//		for (j = 0; j < 4; ++j) {
//			(*state)[i][j] ^= RoundKey[round * LANESIZE * 4 + i * LANESIZE + j];
//		}
//	}
//}
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
//// Cipher is the main function that encrypts the PlainText.
//static void Cipher(void)
//{
//	uint8_t round = 0;
//
//	// Add the First round key to the state before starting the rounds.
//	AddRoundKey(0);
//
//	//print_state();
//
//	// There will be ROUNDS rounds.
//	// The first ROUNDS-1 rounds are identical.
//	// These ROUNDS-1 rounds are executed in the loop below.
//	for (round = 1; round < ROUNDS; ++round)
//	{
//		SubBytes();
//		ShiftRows();
//		MixColumns();
//		AddRoundKey(round);
//	}
//
//	// The last round is given below.
//	// The MixColumns function is not here in the last round.
//	SubBytes();
//	ShiftRows();
//	AddRoundKey(ROUNDS);
//}

__device__ void AES128_ECB_encrypt(uint8_t* ciphertext_block, uint8_t* roundKey)
{
	// Copy input to output, and work in-memory on output
	//BlockCopy(output, input);
	state = (state_t*)ciphertext_block;
	print_state();


	//RoundKey = roundKey;

	// The next function call encrypts the PlainText with the Key using AES algorithm.
	//Cipher();
}