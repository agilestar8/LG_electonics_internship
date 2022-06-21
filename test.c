#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/aes.h>
#include<openssl/des.h>
#include<openssl/cmac.h>
#define KEY_BIT 128
#define KEYSIZE 64
#define MACSIZE 16

//typedef uint8_t U8;
typedef unsigned char U8;

// AES_CBC Encrypt
int aes_encrypt( U8 *p_in, U8 *p_out, int size, U8 *key)
{
	AES_KEY aes_key;            // aes_key structure 
	U8 iv_aes[AES_BLOCK_SIZE];      // initialize vectore
	bzero(iv_aes, sizeof(iv_aes));  // insert 0 to iv_array
 
    AES_set_encrypt_key(key, KEY_BIT, &aes_key);                  // set cipher key
	AES_cbc_encrypt( p_in, p_out, size, &aes_key , iv_aes, AES_ENCRYPT); // encrypting

	return 0;
}

// AES_CBC Decrypt
int aes_decrypt( U8 *p_in, U8 *p_out, int size, U8 *key)
{
	AES_KEY dec_key;
	U8 iv_aes[AES_BLOCK_SIZE];
	bzero(iv_aes, sizeof(iv_aes));

	AES_set_decrypt_key(key, KEY_BIT, &dec_key);
	AES_cbc_encrypt( p_in, p_out, size, &dec_key , iv_aes, AES_DECRYPT);

	return 0;
}

// Print Array
void printBytes(U8 *arr, size_t len){
	for (int i=0;i<len;i++){
		printf("0x%02x ", arr[i]);
	}
	printf("\n");
}


int ascii_to_hex(char c){
	int num = (int) c;
	if(num<58 && num >47){
		return num-48;
	}
	if(num<103 && num>96){
		return num-87;
	}
	return num;
}


int main(){
	
	// Cipher Key
	static U8 cipher_key[] = 
							{0x00,0x01, 
							 0x00,0x10, 
							 0xAA,0xAA,0xAA,0xAA,
							 0xAA,0xAA,0xAA,0xAA,
							 0xAA,0xAA,0xAA,0xAA,
							 0xAA,0xAA,0xAA,0xAA,
							 0x00,0x02,
							 0x00,0x10,
							 0xBB,0xBB,0xBB,0xBB,
							 0xBB,0xBB,0xBB,0xBB,
							 0xBB,0xBB,0xBB,0xBB,
							 0xBB,0xBB,0xBB,0xBB,
							 0x00,0x03,
							 0x00,0x10,
							 0xCC,0xCC,0xCC,0xCC,
							 0xCC,0xCC,0xCC,0xCC,
							 0xCC,0xCC,0xCC,0xCC,
							 0xCC,0xCC,0xCC,0xCC};


	// Mac Key
	static const U8 mac_key[] = {0x2b,0x7e,0x15,0x16, 
							 	 0x28,0xae,0xd2,0xa6,
								 0xab,0xf7,0x15,0x88,
								 0x09,0xcf,0x4f,0x3c};

	U8 PSS_KEY[16];
	for(int i=4;i<20;i++){
		PSS_KEY[i-4] = cipher_key[i];
	}
	//printBytes(cipher_key, KEYSIZE);
	//printBytes(PSS_KEY,sizeof(PSS_KEY));
	printf("\n");

	int encrypt_size = ((sizeof(cipher_key) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	U8 p_encrypt[KEYSIZE];         
	U8 p_decrypt[KEYSIZE];         
	U8 p_temp[1024];

	// Decrypt
	memcpy(p_temp, p_encrypt, encrypt_size);    
	aes_decrypt(p_temp, p_decrypt, encrypt_size, PSS_KEY );   


	// key save and load
	
	FILE *fp = fopen("abc.txt","r");
	if (fp == NULL){
		printf("[SERER] don't have key, create key_file :\n");
		printBytes(p_decrypt, sizeof(p_decrypt));
		
		U8 key[KEYSIZE] = {0,};
		U8 *num;

		FILE *fp = fopen("abc.txt","w");
		for(int i=0;i<KEYSIZE;i++){
			num = (U8*)malloc(sizeof(U8) * KEYSIZE);
			fgets(num,KEYSIZE,fp);
			key[i] = num;
			printf("%02hhX ", num);
		}
		printf("\n");
		fclose(fp);
		return 0;
			
	}else{
		U8 key[KEYSIZE] = {0,};
		U8 buffer[64] = {0,};	
		fgets(buffer,sizeof(buffer),fp);
		
		printf("\nRead file : \n");
		for(int i=0;i<sizeof(
		

	}
	fclose(fp);


	// Encrypt
	aes_encrypt(cipher_key, p_encrypt, sizeof(cipher_key), PSS_KEY);
	printBytes(p_encrypt, sizeof(p_encrypt));




	

	return 0;
}
