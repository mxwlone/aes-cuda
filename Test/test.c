#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE

#include <Windows.h>

int launch_test(char* plaintext, char* ciphertext);

#define NUMBER_OF_FILES 7

const char* files[NUMBER_OF_FILES] = {
	" ..\\testdata\\test_10k.bin ", 
	" ..\\testdata\\test_100k.bin ", 
	" ..\\testdata\\test_500k.bin ", 
	" ..\\testdata\\test_1mb.bin ", 
	" ..\\testdata\\test_10mb.bin ", 
	" ..\\testdata\\test_20mb.bin ", 
	" ..\\testdata\\test_100mb.bin " };

const char* PATH_SERIAL = " ..\\Release\\aes_serial.exe ";
const char* PATH_PARALLEL = "..\\Release\\aes_parallel.exe ";

int main(void) {

	char* ciphertext = " ..\\testdata\\ciphertext ";
	
	int i;
	for (i = 0; i < NUMBER_OF_FILES; i++) {
		printf("> Test for file %s\n", files[i]);
		launch_test(files[i], ciphertext);
	}

	return 0;
}

int launch_test(char* plaintext, char* ciphertext) {
	char* command[200];

	// prepare command for serial
	strcpy(command, PATH_SERIAL);
	strcat(strcat(command, plaintext), ciphertext);

	// execute serial_aes
	printf("=================== AES Serial ===================\n");
	if (system(command))
		exit(1);

	// prepare command for parallel
	strcpy(command, PATH_PARALLEL);
	strcat(strcat(command, plaintext), ciphertext);
	//strcat(strcat(strcat(command, plaintext), ciphertext), " 10 ");

	// execute parallel_aes
	printf("\n================== AES Parallel ==================\n");
	if (system(command))
		exit(1);
	printf("==================================================\n\n\n");
}