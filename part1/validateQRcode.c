#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include "lib/sha1.h"
#include "time.h"


/**
Converts the input hex string to an array of bytes as unsigned chars.  Every two hex
digits of the string will be interpretted as an int and then put into the unsigned char 
array.
*/
void convertHexStringToCharArray(char *hex, unsigned char *padded) {

	// use strtol to convert the hex byte to a decimal
	// loop over 4 bytes backwards, copying in 1 bit starting from 31 -> 24
	
	char * endPtr;
	char buf[3]; // holds current two bytes of hex input as a small string

	// Copy hex into two string parts
	int i;
	
	for (i = 0 ; i < 10 ; i++) {
		buf[0] = hex[2 * i];
		buf[1] = hex[(2 * i) + 1];
		buf[3] = '\0';

		// convert hex string to long int
		long int hexByte = strtol(buf, &endPtr, 16);

		padded[i] = (unsigned char) hexByte;
		// printf("padded[%d]: %hhu", i, padded[i]);
	}
	printf("\n");
	for (i = 10 ; i < 64 ; i++) {
		padded[i] = 0;
	}
}

/**
Converts the input integer to an array of bytes as unsigned chars.  Every byte of the
integer will be interpretted as an individual unsigned char and then put into the unsigned char 
array.
*/
void convertIntegerToCharArray(unsigned int steps, unsigned char *asChar) {
	// Dont know if Little endian matters here ??  Try big endian first.

	asChar[3] = steps & 0xFF;
	asChar[2] = (steps >> 8) & 0xFF;
	asChar[1] = (steps >> 16) & 0xFF;
	asChar[0] = (steps >> 24) & 0xFF;
	// ie: [most sig byte, 2nd, 3rd, least sig byte] of 'steps' int
}


void calculateKey(unsigned char *key_64, unsigned char *resultKey, int num) {
	if (num == 0) {
		// inner key, use 0x36
		for (int i = 0 ; i < 64 ; i++) {
				// printf("%hhu  ", key_64[i]);
				resultKey[i] = key_64[i] ^ 0x36;
				// printf("and I ran: ");
				// printf("%hhu\n", resultKey[i]);
				// printf("in func addr: %p\n", &resultKey[i]);
		}
	} else {
		// outer pad, use 0x5c
		for (int i = 0 ; i < 64 ; i++) {
			// printf("me too: ");
			resultKey[i] = key_64[i] ^ 0x5c;
			// printf("%hhu\n", resultKey[i]);
			// printf("in func addr: %p\n", &resultKey[i]);
		}
	}
}

int extractLast31Bits(int num) {
    // Define a bitmask with the last 31 bits set to 1
    unsigned int bitmask = (1 << 31) - 1;

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


int StToNum(unsigned char* s) {
    int result = 0;

    // Start from the leftmost character
    for (int i = 0; i < strlen(s); i++) {
        // Shift the result to the left to make space for the new bit
        result = result << 1;

        // If the current character is '1', set the rightmost bit to 1
        if (s[i] == '1') {
            result = result | 1;
        } else if (s[i] != '0') {
            // If the character is not '0' or '1', it's an invalid binary string
            printf("Invalid binary string!\n");
            return -1;
        }
    }
    return result;
}


int DT(unsigned char* string) {
	// 31-bit string
	unsigned char* s;
	int res = (string[19] & 0x0f);
	s = IntToBinaryString(res);
	int offset = StToNum(s);
	int P = string[offset] | (string[offset+1] << 8) | (string[offset+2] << 16) | (string[offset+3] << 24);
	// binCode below is 31 digits in binary
	int binCode = extractLast31Bits(P);
	return binCode;
}


static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	// Step 1: Combine the key and innerpad to get the innerKey
	unsigned char* key = secret_hex;
	int key_len = strlen(secret_hex);
	unsigned char k_ipad[65]; 	/* inner padding -
								* key XORd with ipad
								*/	
	unsigned char k_opad[65]; /* outer padding -
								* key XORd with opad
								*/
	/* start out by storing key in pads */
	bzero( k_ipad, sizeof k_ipad);
	bzero( k_opad, sizeof k_opad);
	bcopy( key, k_ipad, key_len);
	bcopy( key, k_opad, key_len);

	/* XOR key with ipad and opad values */
	for (int i=0; i<64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	// Step 2:  Calculate the 'message', aka the timestep from the unix time.
	// Need to calculate timesteps as the message
	time_t currentTime;

	// Get the current time
	time(&currentTime);
	// assume the above is in seconds
	unsigned int currStep = floor(currentTime / 30);
	// printf("Sizeof unsigned int: %d\n", sizeof(unsigned int));  // = 4
	// Print the current Unix time - debug
	// printf("Current Unix Time: %ld\n", currentTime); 
	printf("Current timestep: %d\n", floor(currentTime / 30)); // debug
	unsigned char* stepsAsBytes = (unsigned char*) &currStep;
	for (int i = 0 ; i < 4 ; i++) {
		printf("stepAsBytes[%d]: %hhu\n", i, stepsAsBytes[i]); // debug
	}

	// Now inner key and message have been calculated.  get the Inner hash:
	// Step 3: get the inner hash.
  // calculate the innerHash = Sha1(inner key | message)

	SHA1_INFO ctx1;
	uint8_t innerHash[SHA1_DIGEST_LENGTH]; // SHA1_DIGEST_LENGTH aka 20
	sha1_init(&ctx1);
	sha1_update(&ctx1, k_ipad, 64);
	sha1_update(&ctx1, stepsAsBytes, 4); // message, as 4 bytes
	// // keep calling sha1_update if you have more data to hash...
	sha1_final(&ctx1, innerHash);
	// after final, sha array will be populated with the unsigned chars.  Pass this to outer hash.
	
	uint8_t hmac[SHA1_DIGEST_LENGTH]; // SHA1_DIGEST_LENGTH aka 20

	// Step 4: calculate the outer key
	// Step 5:  calculate the HMAC = Sha1(outer key | inner hash)

	sha1_init(&ctx1);
	sha1_update(&ctx1, k_opad, 64);
	sha1_update(&ctx1, innerHash, 20);
	sha1_final(&ctx1, hmac);

	for (int i = 0 ; i < 20 ; i++) {
		printf("hmac[%d]: %x\n", i, hmac[i]);
		printf("hmac[%d]: %d\n", i, hmac[i]);
	}

	// Step 6: truncate the hmac to 6 digits.
	// Step 6.1  Generate a 4-byte string Sbits = DT(HS) , return 31-bit string.
	printf("hmac[19]: %x\n", hmac[19]);
	printf("hmac[19] & 0xf: %x\n", hmac[19] & 0xf);

	int binCode = DT(hmac);

	// Step 6.2, modulo the binCode to be 6 digits:
	int totp = binCode % 1000000; // 10^6
	printf("Derived totp: %d\n", totp);
	int givenTotp = atoi(TOTP_string);
	printf("Given totp: %d\n", givenTotp);

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
