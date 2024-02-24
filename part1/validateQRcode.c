#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

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

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	// Step 1: Combine the key and innerpad to get the innerKey
	unsigned char paddedKey[64];
	// 1.1: prepare - pad the given secret_hex to 64 bytes.
	convertHexStringToCharArray(secret_hex, paddedKey); // now padded key contains key and a bunch of 0s.

	unsigned char innerKey[64];
	// printf("%p\n", &innerKey);
	// inner pad encapsulated
	calculateKey(paddedKey, innerKey, 0); // padded key xor'ed with 0x36, put in innerKey

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
	unsigned char stepsAsBytes[4];
	convertIntegerToCharArray(currStep, stepsAsBytes);
	for (int i = 0 ; i < 4 ; i++) {
		printf("stepAsBytes[%d]: %hhu\n", i, stepsAsBytes[i]); // debug
	}

	// Now inner key and message have been calculated.  get the Inner hash:
	// Step 3: get the inner hash.
  // calculate the innerHash = Sha1(inner key | message)

	SHA1_INFO ctx1;
	uint8_t innerHash[SHA1_DIGEST_LENGTH]; // SHA1_DIGEST_LENGTH aka 20
	sha1_init(&ctx1);
	sha1_update(&ctx1, innerKey, 64);
	sha1_update(&ctx1, stepsAsBytes, 4); // message, as 4 bytes
	// // keep calling sha1_update if you have more data to hash...
	sha1_final(&ctx1, innerHash);
	// printf("inner hash sha start (2/20): ");
	// for (int i = 0; i < 2 ; i++) {
	// 	printf("%hhu\n", innerHash[i]);
	// }
	// after final, sha array will be populated with the unsigned chars.  Pass this to outer hash.

	// Step 4: calculate the outer key
	unsigned char outerKey[64];
	calculateKey(paddedKey, outerKey, 1);
		// printf("%p\n", &outerKey);
	// for (int j = 0 ; j < 10 ; j++) {
	// 	// sanity check:
	// 	printf("Char:  %hhu\n", innerKey[j]);
	// 	printf("out of func addr: %p\n", &innerKey[j]);
	// }

	// Step 5:  calculate the HMAC = Sha1(outer key | inner hash)

	SHA1_INFO ctx2;
	uint8_t hmac[SHA1_DIGEST_LENGTH]; // SHA1_DIGEST_LENGTH aka 20
	sha1_init(&ctx2);
	sha1_update(&ctx2, outerKey, 64);
	sha1_update(&ctx2, innerHash, 20);
	sha1_final(&ctx2, hmac);
	for (int i = 0 ; i < 20 ; i++) {
		printf("hmac[%d]: %x\n", i, hmac[i]);
		printf("hmac[%d]: %d\n", i, hmac[i]);
	}


	// Step 6: truncate the hmac to 6 digits.
	// Step 6.1  Generate a 4-byte string Sbits = DT(HS) , return 31-bit string.
	printf("hmac[19]: %x\n", hmac[19]);
	printf("hmac[19] & 0xf: %x\n", hmac[19] & 0xf);
	int offset = hmac[19] & 0xf;
	// binCode below is 31 digits in binary
	int binCode = (hmac[offset]  & 0x7f) << 24  // the 0x7f handles the fact that final bit might cause sign issues
			| (hmac[offset+1] & 0xff) << 16
			| (hmac[offset+2] & 0xff) <<  8
			| (hmac[offset+3] & 0xff);

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
