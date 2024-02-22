#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

/**
Converts the input hex string to an array of bytes as unsigned chars.  Every two hex
digits of the string will be interpretted as an int and then put into the unsigned char 
array.
*/
void convertHexStringToCharArray(char *hex, unsigned char *asArray) {

	// use strtol to convert the hex byte to a decimal
	
	char * endPtr;
	char buf[3]; // holds current two digits of hex input as a small string

	// Copy hex into two string parts
	int i;
	
	for (i = 0 ; i < 10 ; i++) {
		buf[0] = hex[2 * i];
		buf[1] = hex[(2 * i) + 1];
		buf[3] = '\0';

		// convert hex string to long int
		long int hexByte = strtol(buf, &endPtr, 16);
		asArray[i] = (unsigned char) hexByte;
	}
}


int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	char uri[256];
	unsigned char converted[32];
	char outputBuffer[32]; // to hold 16 bytes of output

	strcpy(uri, "otpauth://totp/");
	strcat(uri, accountName);
	strcat(uri, "?issuer=");
	strcat(uri, issuer);
	strcat(uri, "&secret=");

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Dylan: otpauth://totp/ACCOUNTNAME?issuer=ISSUER&secret=SECRET&period=30
	// Dylan: name of the account (example: dylan123*), urlencode the special characters. use urlEncode() function.
	// Dylan: issuer: name of the service ie: facebook., urlEncode (including space characters)
	// Dylan: secret: 80-bit secret key value. encode in base32, using base32_encode() function
	// Dylan: all secrets WILL be provided to our app as (exactly) 20-char base-32 values, all upper case letters.

	//Dylan: a function exists to print a properly formatted barcode to the screen.

	convertHexStringToCharArray(secret_hex, converted);
	// for (int j = 0 ; j < strlen(secret_hex) / 2 ; j++) {		// debug
	// 	printf("Char: %hhu\n", converted[j]);
	// }

	base32_encode(converted, 10, outputBuffer, 32);
	// printf("Encoded string: %s\n", outputBuffer);  // debug
	strcat(uri, outputBuffer);
	strcat(uri, "&period=30");

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	displayQRcode(uri);

	return (0);
}
