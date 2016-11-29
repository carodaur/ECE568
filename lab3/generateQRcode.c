#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include "lib/encoding.h"
#define SECRET_KEY_SIZE 80
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
	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	// Secret hex is a 80 bit key value,which is a 80/4 = 20 digit value. It will generate a 16 char Base-32 encoding 
	int secret_hex_len = strlen(secret_hex);
	uint8_t secret_hex_unit8[(SECRET_KEY_SIZE/8)];
	int secret_hex_int[secret_hex_len];
	char * str_hex_conv_ref = "0123456789ABCDEF";
	int i, j;
	
	if (secret_hex_len < (SECRET_KEY_SIZE/4)){
		// Pad leading 0s
		int padding_size = SECRET_KEY_SIZE/4 - secret_hex_len;
		for(i = 0; i < padding_size; i ++){
			secret_hex_int[i] = 0;
		}
		//Convert secret hex from str to int in array format after the leading 0s
		for(i = padding_size; i < (SECRET_KEY_SIZE/4) ; i ++){
			char digit_char = secret_hex[i-padding_size];
			secret_hex_int[i] = -1;
			for(j = 0; j < 16; j ++){
				if(toupper(digit_char) == str_hex_conv_ref[j]){
					secret_hex_int[i] = j;
					break;
				}
			}
		}
		secret_hex_len = SECRET_KEY_SIZE/4;
	}else{
		//Convert secret hex from str to int in array format
		for(i = 0; i < secret_hex_len; i ++){
			char digit_char = secret_hex[i];
			secret_hex_int[i] = -1;
			for(j = 0; j < 16; j ++){
				if(toupper(digit_char) == str_hex_conv_ref[j]){
					secret_hex_int[i] = j;
					break;
				}
			}
		}
	}
	for (i = 0; i < secret_hex_len; i ++){
		assert(secret_hex_int[i] >= 0);
	}

	// Write the secret int to unit8 array
	j = 0;
	for(i = 0; i < secret_hex_len; i= i+2){
		if((i+2)%2 == 0){
			secret_hex_unit8[j] = (((secret_hex_int[i]<<4)&0x0f0) + (secret_hex_int[i+1]&0x0f))&0x0ff;
			j ++;
		}
	}

	uint8_t *base32_result = (uint8_t*) malloc(sizeof(uint8_t)*(SECRET_KEY_SIZE/5));
	base32_encode(secret_hex_unit8, secret_hex_len, base32_result, (SECRET_KEY_SIZE/5));
	const char * issuer_encode = urlEncode(issuer);
	const char * accountName_encode = urlEncode(accountName);

	int qr_str_len = SECRET_KEY_SIZE/5 + strlen(issuer_encode) + strlen(accountName_encode) + 128;
	char hotp_qr_str[qr_str_len];
	char totp_qr_str[qr_str_len];
	sprintf(hotp_qr_str, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", accountName_encode, issuer_encode, base32_result);
	sprintf(totp_qr_str, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accountName_encode, issuer_encode, base32_result);


	displayQRcode(hotp_qr_str);
	displayQRcode(totp_qr_str);

	return (0);
}
