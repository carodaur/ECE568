#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"
#define HASH_BLOCK_SIZE 512
#define SECRET_KEY_SIZE 80
#define SHA_DIGEST_LENGTH 160

void HMAC(char * secret_hex, uint8_t *message, uint8_t *sha){
	
	int i, j;
	/**********************************************************
	 * Prepare opad and ipad value
	 **********************************************************/
	uint8_t opad= 0x5c;
	uint8_t ipad=0x36;
	
	/**********************************************************
	 * Prepare secret key in binary format
	 **********************************************************/
	int secret_hex_len = strlen(secret_hex);
	uint8_t secret_hex_unit8[(SECRET_KEY_SIZE/8)];
	int secret_hex_int[secret_hex_len];
	char * str_hex_conv_ref = "0123456789ABCDEF";	
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

	/**********************************************************
	 * Pad binary secret to length 
	 **********************************************************/
	uint8_t secret_hex_unit8_padded[HASH_BLOCK_SIZE/8];
	for (i = 0; i < (HASH_BLOCK_SIZE/8); i ++){
		secret_hex_unit8_padded[i] = 0;
		if(i < (SECRET_KEY_SIZE/8)){
			secret_hex_unit8_padded[i] = secret_hex_unit8[i];
		}
	}
	/**********************************************************
	 * Compute hash data 
	 **********************************************************/
	SHA1_INFO ctx1, ctx2;
	uint8_t sha2[SHA_DIGEST_LENGTH/8];
	sha1_init(&ctx1);
	sha1_init(&ctx2);

	uint8_t secret_hex_unit8_padded_opad[HASH_BLOCK_SIZE/8];
	uint8_t secret_hex_unit8_padded_ipad[HASH_BLOCK_SIZE/8];

	for (i = 0; i < (HASH_BLOCK_SIZE/8); i++){
		secret_hex_unit8_padded_ipad[i] = (secret_hex_unit8_padded[i] ^ ipad);
	}
	sha1_update(&ctx2, secret_hex_unit8_padded_ipad, (HASH_BLOCK_SIZE/8));
	sha1_update(&ctx2, message, 8);
	sha1_final(&ctx2, sha2);

	for (i = 0; i < (HASH_BLOCK_SIZE/8); i++){
		secret_hex_unit8_padded_opad[i] = (secret_hex_unit8_padded[i] ^ opad);
	}
	sha1_update(&ctx1, secret_hex_unit8_padded_opad, (HASH_BLOCK_SIZE/8));
	sha1_update(&ctx1, sha2, (SHA_DIGEST_LENGTH/8));
	sha1_final(&ctx1, sha);
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	uint8_t *sha = (uint8_t *)malloc(sizeof(uint8_t)*(SHA_DIGEST_LENGTH/8));
	uint8_t message[8];
	int i;
	for(i=0; i<8; i++){
		message[i]=0;
	}
	message[7] =1;
	HMAC(secret_hex, message, sha);
	int t;
	int offset = sha[19] & 0xf ;
	int bin_code = (sha[offset] & 0x7f) << 24 | (sha[offset+1] & 0xff) << 16 | (sha[offset+2] & 0xff) << 8 | (sha[offset+3] & 0xff) ;
	int hotp_int = bin_code %1000000;
	char hotp_str_expected[7];
	sprintf(hotp_str_expected, "%d", hotp_int);
	//printf("HOTP expected %s\n", hotp_str_expected);
	if(!strcmp(HOTP_string, hotp_str_expected)){
		return(1);
	}else{
		return (0);
	}
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	uint8_t *sha = (uint8_t *)malloc(sizeof(uint8_t)*(SHA_DIGEST_LENGTH/8));
	int T;
	int T0 = 0;
	int X = 30;
	time_t seconds = time(NULL);
	T = ((int)seconds - T0) / X;
	uint8_t message[8];
	int i;
	for(i=0; i<8; i++){
		message[i]=0;
	}
	message[7] =T&0x0ff;
	message[6] =(T>>8)&0x0ff;
	message[5] =(T>>16)&0x0ff;
	message[4] =(T>>24)&0x0ff;
	HMAC(secret_hex, message, sha);
	int t;
	int offset = sha[19] & 0xf ;
	int bin_code = (sha[offset] & 0x7f) << 24 | (sha[offset+1] & 0xff) << 16 | (sha[offset+2] & 0xff) << 8 | (sha[offset+3] & 0xff) ;
	int totp_int = bin_code %1000000;
	char totp_str_expected[7];
	sprintf(totp_str_expected, "%d", totp_int);
	//printf("TOTP expected %s\n", totp_str_expected);
	if(!strcmp(TOTP_string, totp_str_expected)){
		return(1);
	}else{
		return (0);
	}
}


int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	HOTP_value = argv[2];
	char *	TOTP_value = argv[3];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(HOTP_value) == 6);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
