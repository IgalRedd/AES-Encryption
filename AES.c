/*
 * Made by Igal Brener on May 29th, 2023
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define FILE_EXTENSION ".enc"
#define WORD_SIZE 4

// Function prototype
unsigned char multiply_bytes(unsigned char, unsigned char);

void printer(unsigned char*, int);

// The inner arrays are of the form:
// # of bytes, # of keys, the length for the 4 x length state array
int AES_consts[3][3] = 
{
	{16, 10, 4},
	{24, 12, 6},
	{32, 14, 8}
};

// The matrix used to mix columns
unsigned char mix_matrix[WORD_SIZE][WORD_SIZE] =
{
	{2, 3, 1, 1},
	{1, 2, 3, 1},
	{1, 1, 2, 3},
	{3, 1, 1, 2}
};

// Inverse matrix used to unmix columns
unsigned char unmix_matrix[WORD_SIZE][WORD_SIZE] =
{
	{14, 11, 13, 9},
	{9, 14, 11, 13},
	{13, 9, 14, 11},
	{11, 13, 9, 14}
};

typedef struct info_package {
	char *file_name;
	char *key;
	int decrypt_bool;
	int remove_bool;
	int type;
} info_package;

/*
 * Wraps the malloc call to easily error check
 */
void *Malloc(size_t size) {
	void *ptr = malloc(size);
	if (ptr == NULL) {
		fprintf(stderr, "Malloc failed...\n");
		exit(1);
	}
	return ptr;
}

/*
 * Given a dest array of bytes and a src 
 * array of bytes that are both at least size 
 * length. This will then transform the src array into the 
 * XOR'd version of the old src and dest
 */
void XOR_arr(const unsigned char *dest, unsigned char *src, int size) {
	for (int i = 0; i < size; i++) {
		src[i] = src[i] ^ dest[i];
	}
}

/*
 * The S-box in the AES encryption. We use the Rijndael S-box
 */
unsigned char Rijndael_S_Box(unsigned char byte) {
	unsigned char S_box[16][16] = 
	{
		{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, 
		{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, 
		{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, 
		{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, 
		{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, 
		{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, 
		{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, 
		{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}, 
		{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, 
		{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, 
		{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, 
		{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, 
		{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, 
		{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, 
		{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}, 
		{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
	};

	// Corresponds to 00001111
	unsigned char temp_byte = 15;
	// Performs & to find, given the byte was in hex form the first digit
	int column = temp_byte & byte;

	// Corresponds to 11110000
	temp_byte = temp_byte << 4;
	// Performs & to find, given the byte was in hex form the second digit
	int row = temp_byte & byte;
	// Shifts it back to make it a number between 0 - 15
	row = row >> 4;

	return S_box[row][column];
}

/*
 * Reverse S-box 
 */
unsigned char Reverse_Rijndael_S_box(unsigned char byte) {
	unsigned char Reverse_S_box[16][16] = 
	{
		{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb}, 
		{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb}, 
		{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e}, 
		{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25}, 
		{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92}, 
		{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84}, 
		{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06}, 
		{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b}, 
		{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73}, 
		{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e}, 
		{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b}, 
		{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4}, 
		{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f}, 
		{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef}, 
		{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61}, 
		{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
	};

	// Corresponds to 00001111
	unsigned char temp_byte = 15;
	// Performs & to find, given the byte was in hex form the first digit
	int column = temp_byte & byte;

	// Corresponds to 11110000
	temp_byte = temp_byte << 4;
	// Performs & to find, given the byte was in hex form the second digit
	int row = temp_byte & byte;
	// Shifts it back to make it a number between 0 - 15
	row = row >> 4;

	return Reverse_S_box[row][column];
}

/*
 * Processes the arguements passed and returns 
 * a dynamically allocated info_package
 */
info_package *process_args(int argc, char **argv) {
	info_package *info = Malloc(sizeof(info_package));

	// Initializes info
	info->key = NULL;
	info->file_name = NULL;
	info->decrypt_bool = 0;
	info->remove_bool = 0;
	info->type = 128;

	int i;

	for (i = 1; i < argc; i++) {
		// Checks if this is an decrypt arguement
		if (strcmp(argv[i], "-d") == 0) {
			info->decrypt_bool = 1;
		} else if (strcmp(argv[i], "-r") == 0) {
			info->remove_bool = 1;
		} else {
			// If there is a space included this must be either a key or type arguement
			char *space = strchr(argv[i], '=');
			if (space != NULL) {

				// Checks if this is the key arguement		
				if (strncmp(argv[i], "-k", space - argv[i]) == 0 || strncmp(argv[i], "-K", space - argv[i] == 0)) {
					char *key = space + sizeof(char);
					//  Copies over the key
					// Note that if the user didn't input a key then 
					// key is just pointing to a \0 and so we copy over just a null character
					info->key = Malloc((strlen(key) + 1) * sizeof(char));
					strcpy(info->key, key);
					
				}
				// Checks if this is a type
				else if (strncmp(argv[i], "-type", space - argv[i]) == 0) {
					// Gets the type of encryption and ensures it is a valid type
					int type = strtol(space + sizeof(char), NULL, 10);
					if (type != 128 && type != 192 && type != 256) {
						printf("Invalid type.\n");
						exit(1);
					}

					info->type = type;
				} else {
					// Assumes since this isn't an arguement its a file
					break;
				}
			} else {
				break;
			}
		}
	}

	// Assumes the next arguement after all the other ones is the file
	if (i < argc) {
		info->file_name = Malloc(sizeof(char) * (strlen(argv[i]) + 1));
		strcpy(info->file_name, argv[i]);
	}
	
	if (info->key == NULL) {
		printf("No key entered, try again.\n");
		exit(1);
	} else if (info->file_name == NULL) {
		printf("No file entered, try again.\n");
		exit(1);
	}

	return info;
}

/*
 * Returns a malloc'd array of unsigned char that represents a key
 * If the given key is too long it'll truncate it, if its too short it'll expand it (with 0s).
 * Assumes key != NULL and key is a string
 */
unsigned char *format_key(char *key, int key_size) {
	// Take the minimum, either loop exactly how long 
	// the key should be or its actual length if its smaller
	int loop_num = key_size; 
	if (strlen(key) < key_size) {
		loop_num = strlen(key);
	}

	unsigned char *new_key = Malloc(sizeof(unsigned char) * key_size);

	// Rewrite the already existing characters into the key
	for (int i = 0; i < loop_num; i++) {
		new_key[i] = (unsigned char)key[i];
	}

	// Pad out any extra unwritten space with 0s
	for (int i = loop_num; i < key_size; i++) {
		new_key[i] = 0;
	}

	return new_key;
}

/*
 * Given a dynamically allocated key
 * this function will transform the key into the next round key
 * Precondition: 0 <= round_const <= 13
 */
unsigned char *next_round_key(const unsigned char *key, int round, int const_pos) {
	// Predefined round_consts for key expansion
	unsigned char round_consts[14] = {1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77};

	unsigned char *new_key = Malloc(sizeof(unsigned char) * AES_consts[const_pos][0]);
	// Gets the first "word" of the new key
	// This is done by doing a one byte left shift on the first word
	// We also perform the substitution directly here
	for (int i = 0; i < WORD_SIZE - 1; i++) {
		new_key[i] = Rijndael_S_Box(key[i + 1]);
	}
	new_key[WORD_SIZE - 1] = Rijndael_S_Box(key[0]);

	// Performs an XOR of the first word with the round constants
	for (int i = 0; i < WORD_SIZE; i++) {
		new_key[i] = new_key[i] ^ round_consts[round];
	}

	// Finally to get all the other words in the key, we do XOR 
	// with the newest word we made and the new word we need

	// For each subsequent word we haven't finished yet
	for (int i = 1; i < AES_consts[const_pos][2]; i++) {
		// For each byte in the new word we XOR it with the previous new key and the old byte
		for (int j = 0; j < WORD_SIZE; j++) {
			new_key[WORD_SIZE * i + j] = new_key[WORD_SIZE * (i - 1) + j] ^ key[i * WORD_SIZE + j];
		}
	}

	return new_key;
}

/*
 * Pads the message by the pad amount (adds pad amount unsigned 
 * chars starting from the end), using the pad amount unsigned char
 * as the padding character. The message should be msg_length size array
 */
void pad_message(unsigned char *msg, unsigned char pad_amount, int msg_length) {
	// Start at the end and go until you've gone by pad amount
	for (int i = msg_length - 1; i >= msg_length - pad_amount; i--) {
		msg[i] = pad_amount;
	}
}

/*
 * Performs the shift rows operation in AES onto the message
 */
void shift_rows(unsigned char *data, int const_pos) {
	int length = AES_consts[const_pos][2];
	int modulo = AES_consts[const_pos][0];

	// Loop over each row starting from the 2nd row down (first has no shifts)
	for (int i = 1; i < WORD_SIZE; i++) {
		// Store the values in a temporary char array in the new order (shifted order)
		// then rewrite the data from the temporary array in the new order
		unsigned char temp[length];

		for (int j = 0; j < length; j++) {
			/*
			 * For each position in the temp array, finds out where the array 
			 * currently corresponds to (that is; for row i, index j in the array that would 
			 * corresponds to i + WORD_SIZE * j) then shifts it over by WORD_SIZE * i 
			 * which corresponds to shifting the row.
			 * Add the modulo so it loops back around to ensure no accesing of info outside of the array.
			 */
			temp[j] = data[((WORD_SIZE * (j + i) + i) % modulo)];
		}

		// Rewrites the data with the new order
		for (int j = 0; j < length; j++) {
			data[i + WORD_SIZE * j] = temp[j];
		}
	}
} 

/*
 * Reverse operation on shift_rows
 */
void unshift_rows(unsigned char *data, int const_pos) {
	int length = AES_consts[const_pos][2];
	int modulo = AES_consts[const_pos][0];

	// Loop over each row starting from 2nd row (first nothing happened)
	for (int i = 1; i < WORD_SIZE; i++) {
		// Store the values in a temporary char array in the new order (unshifted order)
		// then rewrite the data from the temporary array in the new order
		unsigned char temp[length];

		for (int j = 0; j < length; j++) {
			// Same idea as in the shift rows, but since each row i was shifted 
			// by i positions, we then shift it back again by the length - i 
			// meaning the total shift corresponds to a shift in length which 
			// corresponds to nothing
			temp[j] = data[((WORD_SIZE * (j + (length - i)) + i) % modulo)];
		}

		// Rewrites the data with the new order
		for (int j = 0; j < length; j++) {
			data[i + WORD_SIZE * j] = temp[j];
		}
	}
}

/*
 * Converts an int that might be more than 1 
 * byte in length to 1 byte using the specific Rijndael 
 * function. That is given the int in binary represents 
 * a function we mod it by x^4 + x^3 + x + 1 
 * (we have that x^8 = x^4 + x^3 + x + 1)
 */
unsigned char mod_rijndael(int byte) {
	// Gets the original byte value (eg: the value of the first 8 bits)
	// 255 = 11111111
	unsigned char value = (unsigned char)(byte & 255);

	// Right shifts 8 bits to see if any bits are left over 
	// (if not then the original value does not need to be modded)
	int leftover = byte >> 8;

	// Each value in the left over can be treated as x^8 * some 
	// number so we simply multiply and XOR it onto 
	// the value until no more bits are leftover

	// Counter of which value we are currently multiplying by
	int i = 0;
	while (leftover > 0) {
		// If the first byte is 1 then we need to multiply, if not do nothing
		if ((leftover & 1) > 0) {
			// 27 = 00011011 = x^4 + x^3 + x + 1
			// Gets the new value of the x^8 * x^i and then mods it again 
			// to ensure we it is 1 byte
			value = value ^ mod_rijndael(27 << i);
		}

		// Increments
		i++;
		leftover = leftover >> 1;
	}
	
	return value;
}

/*
 * Multiplies two bytes together according to the mix columns methods in AES
 * Note that bytes here correspond to polynomials in the Rijndael finite field
 * eg: 111 = x^2 + x + 1
 * and we are multiplying these polynomials in the field to get a new polynomial back
 */
unsigned char multiply_bytes(unsigned char byte0, unsigned char byte1) {
	unsigned char value = 0;

	// Counter of which value we are currently multiplying by
	int i = 0;
	while (byte0 > 0) {
		// If the first byte is 1 then we need to multiply, if not do nothing
		if ((byte0 & 1) > 0) {
			// Creates an int so we can overflow the value to more than 
			// 1 byte when we multiply temporarily
			int manipulated_byte = (int)byte1;

			// Multiplies it by the current value
			manipulated_byte = manipulated_byte << i;
			// Adds it to the value after modding it to ensure its 1 byte
			value = value ^ mod_rijndael(manipulated_byte);
		}

		// Increments
		i++;
		byte0 = byte0 >> 1;
	}

	return value;
}

/*
 * Multiplies columns of a data by the given matrix. 
 * Assumes the matrix is WORD_SIZE x WORD_SIZE unsigned chars. 
 * This is done so both mixing and unmixing could be done 
 * by switching matrixes inputted rather than copying the same function twice.
 */
void matrix_column_multiplication(unsigned char *data, int const_pos, unsigned char matrix[WORD_SIZE][WORD_SIZE]) {
	// Creates a temporary array to store the 
	// values so that our mixing doesn't affect
	// the matrix multiplication
	unsigned char temp_arr[WORD_SIZE];

	// Loops over each column and row in the data state matrix
	for (int col = 0; col < AES_consts[const_pos][2]; col++) {
		for (int row = 0; row < WORD_SIZE; row++) {
			// Calculates the new value by multiplying and XORing all the values of the matrixes
			unsigned char new_value = 0;
			for (int i = 0; i < WORD_SIZE; i++) {
				new_value = new_value ^ multiply_bytes(matrix[row][i], data[col * WORD_SIZE + i]);
			}

			temp_arr[row] = new_value;

		}

		// Finally we can assign the value since we won't be using this column again
		for (int row = 0; row < WORD_SIZE; row++) {
			data[col * WORD_SIZE + row] = temp_arr[row];
		}
	}
}

/*
 * Takes a msg of unsigned chars of size defined 
 * in the AES_consts for the current const_pos and 
 * an array of keys (also the same size as the data) 
 * containing AES_consts keys specified amount and 
 * performs the correct amount of rounds to encrypt the data.
 */
void encrypt_message(unsigned char *msg, unsigned char **keys, int const_pos) {
	// The -1 loops is because you don't mix the data at the end
	for (int i = 0; i < AES_consts[const_pos][1] - 1; i++) {
		XOR_arr(keys[i], msg, AES_consts[const_pos][0]);

		// This is the substitution stage
		for (int j = 0; j < AES_consts[const_pos][0]; j++) {
			msg[j] = Rijndael_S_Box(msg[j]);
		}

		shift_rows(msg, const_pos);
		matrix_column_multiplication(msg, const_pos, mix_matrix);
	}

	// Performs final round without mixing columns

	XOR_arr(keys[AES_consts[const_pos][1] - 1], msg, AES_consts[const_pos][0]);

	// This is the substitution stage
	for (int j = 0; j < AES_consts[const_pos][0]; j++) {
		msg[j] = Rijndael_S_Box(msg[j]);
	}

	shift_rows(msg, const_pos);
}

/*
 * Takes a msg of unsigned chars of size defined 
 * in the AES_consts for the current const_pos and 
 * an array of keys (also the same size as the data) 
 * containing AES_consts keys specified amount and 
 * performs the correct amount of rounds to decrypt the data.
 */
void decrypt_message(unsigned char *msg, unsigned char **keys, int const_pos) {
	// First round is special since in the last round no mixing of columns was used

	unshift_rows(msg, const_pos);

	// This is the reverse substitution stage
	for (int j = 0; j < AES_consts[const_pos][0]; j++) {
		msg[j] = Reverse_Rijndael_S_box(msg[j]);
	}

	XOR_arr(keys[AES_consts[const_pos][1] - 1], msg, AES_consts[const_pos][0]);

	// The -2 is because we used the first key already
	for (int i = AES_consts[const_pos][1] - 2; i >= 0; i--) {
		matrix_column_multiplication(msg, const_pos, unmix_matrix);
		unshift_rows(msg, const_pos);

		// This is the reverse substitution stage
		for (int j = 0; j < AES_consts[const_pos][0]; j++) {
			msg[j] = Reverse_Rijndael_S_box(msg[j]);
		}

		XOR_arr(keys[i], msg, AES_consts[const_pos][0]);
	}
}

int main(int argc, char **argv) {
	// Ensures all arguements passed in are proper arguements
	if (argc < 3) {
		printf("Incorrect usage. Proper usage is:\n./AES [args including: -d, -type=128/196/256, -r] -k=key filename\n");
		return 1;
	}
	info_package *package = process_args(argc, argv);

	// Depending on which type of encryption we choose the constant from AES_consts
	int const_pos;
	switch(package->type) {
		case 128:
			const_pos = 0;
			break;
		case 192:
			const_pos = 1;
			break;
		case 256:
			const_pos = 2;
			break;
	}

	// Ensures the file passed in exists
	struct stat st;
	if (stat(package->file_name, &st) == -1) {
		printf("File does not exist...\n");
		return 1;
	} else if (S_ISDIR(st.st_mode)) {
		printf("Only works on regular files, not directories...\n");
		return 1;
	}
	
	// Gets the key and properly formats it
	unsigned char *keys[AES_consts[const_pos][1]];
	keys[0] = format_key(package->key, AES_consts[const_pos][0]);

	free(package->key);

	// Generates all the keys
	for (int i = 1; i < AES_consts[const_pos][1]; i++) {
		keys[i] = next_round_key(keys[i - 1], i, const_pos);
	}

	FILE *read_file;
	FILE *write_file;
	unsigned char padding;
	unsigned char msg[AES_consts[const_pos][0]];
	int read_amount;

	if (package->decrypt_bool) {
		// The new file name is just the old file name as we are removing .enc
		// Finds where the .enc is
		char *extension = strstr(package->file_name, FILE_EXTENSION);
		// Finds how long the original message is
		int original_length = extension - package->file_name;

		// Gets the original file name
		char new_file_name[original_length + 1];
		strncpy(new_file_name, package->file_name, original_length);
		new_file_name[original_length] = '\0';


		read_file = fopen(package->file_name, "rb");
		if (read_file == NULL) {
			printf("Failed to open the file for reading.\n");
			return 1;
		}

		write_file = fopen(new_file_name, "wb");
		if (write_file == NULL) {
			printf("Failed to open the new file for writing.\n");
			return 1;
		}

		// Figures out how much the file was padded by
		fread(&padding, sizeof(unsigned char), 1, read_file);

		while (fread(msg, sizeof(unsigned char), AES_consts[const_pos][0], read_file) > 0) {
			decrypt_message(msg, keys, const_pos);

			int write_amount = AES_consts[const_pos][0];
			// Checks if this block was the final block to read
			// If so we shouldn't write the extra amount of
			// padding, just write the original message
			if (fgetc(read_file) != EOF) {
				fseek(read_file, -(sizeof(unsigned char)), SEEK_CUR);
			} else {
				write_amount = padding;
			}

			fwrite(msg, sizeof(unsigned char), write_amount, write_file);
		}

	} 
	else {
		// The new file name will be the old file name with an 
		// appended file extension + 1 for the null terminator
		char new_file_name[strlen(package->file_name) + strlen(FILE_EXTENSION) + 1];
		strcpy(new_file_name, package->file_name);
		strcat(new_file_name, FILE_EXTENSION);

		read_file = fopen(package->file_name, "rb");
		if (read_file == NULL) {
			printf("Failed to open the file for reading.\n");
			return 1;
		}

		write_file = fopen(new_file_name, "wb");
		if (write_file == NULL) {
			printf("Failed to open the new file for writing.\n");
			return 1;
		}

		// Figures out how much the file will be padded by
		padding = (unsigned char)(st.st_size % AES_consts[const_pos][0]);

		// Writes the padding byte
		fwrite(&padding, sizeof(unsigned char), 1, write_file);

		read_amount = fread(msg, sizeof(unsigned char), AES_consts[const_pos][0], read_file);
		while (read_amount > 0) {
			// Checks if we need to pad the message
			if (read_amount != AES_consts[const_pos][0]) {
				pad_message(msg, AES_consts[const_pos][0] - read_amount, AES_consts[const_pos][0]);
			}

			encrypt_message(msg, keys, const_pos);
			fwrite(msg, sizeof(unsigned char), AES_consts[const_pos][0], write_file);

			read_amount = fread(msg, sizeof(unsigned char), AES_consts[const_pos][0], read_file);
		}
	}

	fclose(write_file);
	fclose(read_file);

	// If the user requested it, removes the file
	if (package->remove_bool) {
		if (remove(package->file_name) != 0) {
			printf("Error removing file");
			return 1;
		}
	}

	return 0;
}