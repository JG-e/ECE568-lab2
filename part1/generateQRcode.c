#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"


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
    char* binary_string = (char*)malloc(10 ); 
    
	int bin_index = 0;
	for (int i = 0; i < strlen(hex_string); i+=2) {
		uint8_t upper = hex_to_bin_digit(hex_string[i]);
		uint8_t lower = hex_to_bin_digit(hex_string[i+1]);
		binary_string[bin_index++] = (upper << 4) | lower & 0xFF;
	}

    return binary_string;
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
	strcat(uri, urlEncode(accountName));
	strcat(uri, "?issuer=");
	strcat(uri, urlEncode(issuer));
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

	char* bin_secret = hex_to_binary(secret_hex);

	base32_encode(bin_secret, 10, outputBuffer, 32);
	
	strcat(uri, outputBuffer);
	strcat(uri, "&period=30");

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	displayQRcode(uri);

	return (0);
}
