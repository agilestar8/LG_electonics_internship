#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <mqueue.h>
#include <sys/stat.h>
#include <time.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/cmac.h>
#define KEY_BIT 128
#define KEYSIZE 64
#define MACSIZE 16
#define PSKSIZE 16

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

// MAC Verification
int verify_mac(U8 *mac1, U8 *mac2)
{
	if (memcmp(mac1, mac2, MACSIZE)==0 ) {
		printf("MAC Corrected\n");
	}else{
		printf("[WARNING] Incorrect MAC!\n");
		return 1;
	}
	return 0;

}

// Print Array
void printBytes(U8 *arr, size_t len){
	for (int i=0;i<len;i++){
		printf("0x%02x ", arr[i]);
	}
	printf("\n");
}



// server.c
int main(int argc, char *args[])
{
	printf("\nRun Server\n");

	printf("waiting...\n");
	// Message Queue Setting
    struct mq_attr attr;
    attr.mq_maxmsg = 10;
    attr.mq_msgsize = 128;
    U8 buf[KEYSIZE+MACSIZE] = {};
    mqd_t mq; 
 
	// MQ open
    mq = mq_open("/mq_buf", O_RDWR | O_CREAT, 0666, &attr);
    if (mq == -1){
		perror("message queue open error");
        exit(1);
     }
	
	// MQ receive
    if(mq_receive(mq, buf, attr.mq_msgsize,NULL) == -1){
        perror("mq_receive error");
		exit(-1);
    }

	printf("\n[SERVER] received MQ!\n");

	
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
	static const U8 mac_key[] = {   0x01,0x02,0x03,0x04, 
									0xaa,0xbb,0xcc,0xdd,
									0xaa,0xbb,0xcc,0xdd,
									0xaa,0xbb,0xcc,0xdd};


	// Decryption
	U8 s_encrypt[KEYSIZE];
	U8 s_decrypt[KEYSIZE];		
	U8 temp[1024];	
	int encrypt_size;	

	// Divide buffer to encrypted_key   CMAC
	U8 r_encrypt[KEYSIZE+MACSIZE];
	U8 r_mac[MACSIZE];	
	for(int i=0; i<KEYSIZE; i++){
		r_encrypt[i] = buf[i];
	}
	for(int i=KEYSIZE;i<KEYSIZE+MACSIZE;i++){
		r_mac[i-KEYSIZE] = buf[i];
	}

	// Set PSS KEY
	U8 PSS_KEY[PSKSIZE];
	for(int i=4;i<20;i++){
		PSS_KEY[i-4] = cipher_key[i];
	}
	printf("\n[SERVER] PSS KEY : \n");
	//printBytes(cipher_key, 20);
	printBytes(PSS_KEY,sizeof(PSS_KEY));

	encrypt_size = ((sizeof(r_encrypt) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	memcpy(temp, r_encrypt, encrypt_size);		
	aes_decrypt(temp, s_decrypt, encrypt_size, PSS_KEY);

/*
	U8 cipher_key[KEYSIZE] = {0,};

	FILE *file;
	file = fopen("cipher_key.txt", 'r');
	if (file == NULL){
		memcpy(cipher_key, s_decrypt, sizeof(buf));
		printf("Cipher_Key setting Complete!\n");
		printBytes(cipher_key, KEYSIZE);
	}
	else{
		for(int i=0;i<KEYSIZE;i++){
		read_key = (U8*)malloc(sizeof(U8)*KEYSIZE);
		fgets(read_key,KEYSIZE,file);
		memcpy(cipher_key, 
		}
	}
*/

	

	printf("\n[SERVER] Received buffer length : %ld\n", sizeof(buf));
	printf("[SERVER] Received buffer : \n");
	printBytes(buf,sizeof(buf));
	printf("\n");
	printf("[SERVER] Received Key: \n");
	printBytes(r_encrypt,KEYSIZE);
	printf("\n");	 
	printf("[SERVER] Decrypted Key : \n");
	printBytes(s_decrypt,sizeof(cipher_key));
	printf("\n");	

	// Re_Encrpyt by Cipher_key
	aes_encrypt(s_decrypt, s_encrypt, sizeof(s_decrypt), PSS_KEY);
	printf("[SERVER] Re Encrpyt : \n");
	printBytes(s_encrypt,KEYSIZE);
	printf("\n");


	// Crate CMAC 
	U8 server_mac[MACSIZE] = {0}; 
	size_t mactlen;

	CMAC_CTX *ctx = CMAC_CTX_new();
	CMAC_Init(ctx, mac_key, MACSIZE, EVP_aes_128_cbc(), NULL);
	CMAC_Update(ctx, r_encrypt, KEYSIZE);
	CMAC_Final(ctx, server_mac, &mactlen);
	CMAC_CTX_free(ctx);

	printf("[SERVER] CLIENT MAC: \n");
	printBytes(r_mac,MACSIZE);
	printf("\n");	 

	printf("[SERVER] SERVER MAC : \n");
	printBytes(server_mac, mactlen);	
	printf("\n");

	verify_mac(r_mac, server_mac);

/*
	FILE* fp = fopen("cipher_key.txt", "w");
	fputs(s_encrypt,fp);
	if(fp == NULL){
		printf("\nno file\n");
		return 0;
	}
	fclose(fp);
*/

	printf("[SERVER CLOSED]\n");

	return 0;
}
