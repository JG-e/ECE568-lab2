#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include "lib/sha1.h"
#include "time.h"


// Function to convert a hexadecimal character to its binary equivalent
uint8_t hex_to_bin_digit(char hex_digit) {
    switch(hex_digit) {
        case '0': return 0b0000;
        case '1': return 0b0001;
        case '2': return 0b0010;
        case '3': return 0b0011;
        case '4': return 0b0100;
        case '5': return 0b0101;
        case '6': return 0b0110;
        case '7': return 0b0111;
        case '8': return 0b1000;
        case '9': return 0b1001;
        case 'A': return 0b1010;
        case 'B': return 0b1011;
        case 'C': return 0b1100;
        case 'D': return 0b1101;
        case 'E': return 0b1110;
        case 'F': return 0b1111;
        default:
            printf("Invalid hexadecimal digit: %c\n", hex_digit);
    }
}

// Function to convert a hexadecimal string to binary
char* hex_to_binary(const char* hex_string) {
    // Allocate memory for binary string (4 bits for each hex digit)
	// 8 bits = 1 byte, thus 2 hex digits = 1 byte, also +1 for null terminator
  char* binary_string = (char*)malloc(SHA1_BLOCKSIZE); 
	memset(binary_string, 0, SHA1_BLOCKSIZE);
    
	int bin_index = 0;
	for (int i = 0; i < strlen(hex_string); i+=2) {
		uint8_t upper = hex_to_bin_digit(hex_string[i]);
		uint8_t lower = hex_to_bin_digit(hex_string[i+1]);
		binary_string[bin_index++] = (upper << 4) | lower & 0xFF;
	}

  return binary_string;
}

int extractLast31Bits(int num) {
    // Define a bitmask with the last 31 bits set to 1
    int bitmask = 0x7FFFFFFF;

    // Perform bitwise AND to extract the last 31 bits
    int extractedBits = num & bitmask;

    return extractedBits;
}


char* IntToBinaryString(int num) {
    // Number of bits in an integer
    int num_bits = sizeof(int) * 8;
    char *binary_string = (char *)malloc(num_bits + 1); // +1 for null terminator
    if (binary_string == NULL) {
        printf("Memory allocation failed\n");
        exit(1);
    }

    // Start from the leftmost bit (most significant bit)
    for (int i = num_bits - 1; i >= 0; i--) {
        // Extract the i-th bit using bitwise AND
        int bit = (num >> i) & 1;
        // Convert the bit to a character and store it in the string
        binary_string[num_bits - 1 - i] = bit + '0';
    }
    // Null-terminate the string
    binary_string[num_bits] = '\0';

    return binary_string;
}


int DT(unsigned char* string) {
	// 31-bit string
	unsigned char res = (string[19] & 0x0f);
	int offset = res;
	int P = string[offset+3] | (string[offset+2] << 8) | (string[offset+1] << 16) | (string[offset] << 24);
	// binCode below is 31 digits in binary
	int binCode = extractLast31Bits(P);
	return binCode;
}

int truncateHMAC(unsigned char* hmac) {
	// truncate the hmac according to rfc4226

	// Step 6.2  Generate a 4-byte string Snum = StToNum(Sbits) (Dynamic Truncation)
	int Snum = DT(hmac);
	// Step 6.3  Generate a 6-digit number Snum = Snum % 10^6
	int totp = Snum % 1000000;
	return totp;
}

void HMAC(unsigned char* key, unsigned char* result) {

	int key_len = strlen(key);
	unsigned char k_ipad[SHA1_BLOCKSIZE]; 	/* inner padding -
								* key XORd with ipad
								*/	
	unsigned char k_opad[SHA1_BLOCKSIZE]; /* outer padding -
								* key XORd with opad
								*/
	/* start out by storing key in pads */
	bzero( k_ipad, sizeof k_ipad);
	bzero( k_opad, sizeof k_opad);
	bcopy( key, k_ipad, key_len);
	bcopy( key, k_opad, key_len);

	/* XOR key with ipad and opad values */
	for (int i=0; i<SHA1_BLOCKSIZE; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	// Step 2:  Calculate the 'message', aka the timestep from the unix time.
	// Need to calculate timesteps as the message
	time_t currentTime;

	// Get the current time
	time(&currentTime);
	// assume the above is in seconds
	long currStep = floor(currentTime / 30);

	// Calculate time current Unix time
	uint64_t time64 = (uint64_t)currStep;

	uint8_t time8[] = {(time64 >> 56) & 0xff,
						(time64 >> 48) & 0xff,
						(time64 >> 40) & 0xff,
						(time64 >> 32) & 0xff,
						(time64 >> 24) & 0xff,
						(time64 >> 16) & 0xff,
						(time64 >> 8) & 0xff,
						time64 & 0xff};

	uint8_t* stepsAsBytes = (uint8_t*) time8;

	// Now inner key and message have been calculated.  get the Inner hash:
	// Step 3: get the inner hash.
  // calculate the innerHash = Sha1(inner key | message)

	SHA1_INFO ctx1;

	// Perform the hashing according to rfc2104
	sha1_init(&ctx1);
	sha1_update(&ctx1, k_ipad, SHA1_BLOCKSIZE);
	sha1_update(&ctx1, stepsAsBytes, 8); // Time, as 8 bytes

	// keep calling sha1_update if you have more data to hash...
	sha1_final(&ctx1, result);
	// after final, sha array will be populated with the unsigned chars.  
	// Pass this to outer hash.

	// Step 4: calculate the outer key
	// Step 5:  calculate the result = Sha1(outer key | inner hash)

	sha1_init(&ctx1);
	sha1_update(&ctx1, k_opad, SHA1_BLOCKSIZE);
	sha1_update(&ctx1, result, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx1, result);
}


static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	// Step 1: Combine the key and innerpad to get the innerKey
	unsigned char* key = (unsigned char*) hex_to_binary(secret_hex);
	
	uint8_t hmac[SHA1_DIGEST_LENGTH]; // SHA1_DIGEST_LENGTH aka 20
	memset(hmac, 0, SHA1_DIGEST_LENGTH);
	// Step 6: truncate the hmac to 6 digits.
	// Step 6.1  Generate a 4-byte string Sbits = DT(HS) , return 31-bit string.
	HMAC(key, hmac);
	int totp = truncateHMAC(hmac);
	int givenTotp = atoi(TOTP_string);

	// Step 7: return whether the given string is equal to the truncated hmac as integer values
	return totp == givenTotp;
}


int
main(int argc, char * argv[])
{
	if ( argc != 3 ) {
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	TOTP_value = argv[2];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
