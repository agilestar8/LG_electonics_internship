#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "aes_cbc.h"

int main(){

	U8 enc[128];
	U8 dec[128];

	aes_encrypt(cipher_key, enc, sizeof(cipher_key));
	printf("\n");
	printBytes(enc,strlen(enc));

	print("%d", );
	return 0;
}
