#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <mqueue.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stdint.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/cmac.h>
#define KEY_BIT 128
#define KEYSIZE 64
#define MACSIZE 16
#define PSKSIZE 16
// SERVER.C

typedef uint8_t U8;
//typedef unsigned char U8;


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

typedef struct message{
	int cmd;
	char buffer[100];
	int ret;
}msg;



int main(int argc, char *args[])
{
	printf("\nRun Server\n");
	printf("waiting data...\n");
	// Message Queue Setting
    struct mq_attr attr;
    attr.mq_maxmsg = 10;
    attr.mq_msgsize = 128;
    U8 buf[KEYSIZE+MACSIZE] = {};
    mqd_t mq; 
	msg m;

	/* Receive First Key

	mq = mq_open("/mq_key", O_RDWR | O_CREAT, 0666, &attr);
    if(mq_receive(mq, buf, attr.mq_msgsize,NULL) == -1){
		print("error1");	
	}
	mq_close(mq);
	
	U8 s_encrypt[KEYSIZE]={0,};
	U8 s_decrypt[KEYSIZE]={0,;		
	U8 temp[1024]={0,};	
	int encrypt_size;		
	*/


	// key save and load	
/* save
	aes_encrypt(m.buffer, s_encrypt, sizeof(m.buffer), PSS_KEY);
	encrypt_size = ((sizeof(m.buffer) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	memcpy(temp, m.buffer, encrypt_size);		
	aes_decrypt(temp, s_decrypt, encrypt_size, PSS_KEY);
	
    int fd;
	fd = open("file.dlc",O_WRONLY|O_CREAT,0666);
	write(fd, s_decrypt, KEYSIZE);
	printf("[SERVER] don't have key, create key file \n");		
	close(fd);


*/	
	int fd;
	U8 cipher_key[KEYSIZE]={0,};
	umask(0);

	fd = open("file.dlc",O_RDONLY,0666);	
	read(fd, cipher_key, KEYSIZE);
	printf("[SERVER] Read File.dlc : \n");
	printBytes(cipher_key,KEYSIZE-4);
	printf("\n");
	close(fd);

	U8 s_encrypt[KEYSIZE]={0,};
	U8 s_decrypt[KEYSIZE]={0,};		
	U8 temp[1024]={0,};	
	int encrypt_size;	
	
	// Key Setting
	U8 PSS_KEY[16];
	U8 cmac_key[16];
	U8 hmac_key[16];

	// Set PSS KEY
	for(int i=4;i<20;i++){
		PSS_KEY[i-4] = cipher_key[i];
	}
	printf("[SERVER] PSS KEY : \n");
	printBytes(PSS_KEY,sizeof(PSS_KEY));

	// Set CMAC Key
	for(int i=24;i<40;i++){
		cmac_key[i-24] = cipher_key[i];
	}
	printf("[SERVER] CMAC KEY : \n");
	printBytes(cmac_key, sizeof(cmac_key));
	// Set HMAC Key	
	for(int i=44;i<60;i++){
		hmac_key[i-44] = cipher_key[i];
	}
	printf("[SERVER] HMAC KEY : \n");
	printBytes(hmac_key, sizeof(hmac_key));


	// Receive APP's data
	mq = mq_open("/mq_buf", O_RDWR | O_CREAT, 0666, &attr);
    if (mq == -1){
		perror("message queue open error");
        exit(1);
     }
	if ((mq_receive(mq, (char *) &m, sizeof(m)+128, NULL)) == -1){
		printf("error2");
	}
	printf("\n[SERVER] received !\n");	
	printf("[SERVER] cmd : %d\n", m.cmd);
	printf("[SERVER] text : ");
	printBytes(m.buffer,strlen(m.buffer));
	printf("[SERVER] ret : %d\n", m.ret);
	printf("\n");



	// command
	if (m.cmd == 1){
		aes_encrypt(m.buffer, s_encrypt, sizeof(m.buffer), PSS_KEY);
		printf("[SERVER] Encrpyt : ");
		printBytes(s_encrypt,strlen(s_encrypt));
		printf("\n");
	}

	else if(m.cmd == 2){
		encrypt_size = ((sizeof(m.buffer) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
		memcpy(temp, s_encrypt, encrypt_size);		
		aes_decrypt(temp, s_decrypt, encrypt_size, PSS_KEY);
		printf("[SERVER] Decrypt : ");
		printBytes(s_decrypt,strlen(m.buffer));
		printf("\n");
	}

	else if(m.cmd == 3){
		// Crate CMAC 
		U8 server_mac[MACSIZE] = {0}; 
		size_t mactlen;

		CMAC_CTX *ctx = CMAC_CTX_new();
		CMAC_Init(ctx, cmac_key, MACSIZE, EVP_aes_128_cbc(), NULL);
		CMAC_Update(ctx, m.buffer, sizeof(m.buffer));
		CMAC_Final(ctx, server_mac, &mactlen);
		CMAC_CTX_free(ctx);

		printf("[SERVER] Generated CMAC : \n");
		printBytes(server_mac, mactlen);	
		printf("\n");

		}

	else if(m.cmd == 4){
		// Create HMAC
		int hlen = sizeof(hmac_key);
		U8 hmac[1024];

		HMAC_CTX *ctx2 = HMAC_CTX_new();
		HMAC_CTX_reset(ctx2);
		HMAC_Init_ex(ctx2, hmac_key, MACSIZE, EVP_sha256(), NULL);
		HMAC_Update(ctx2, m.buffer, sizeof(m.buffer));
		HMAC_Final(ctx2, hmac, &hlen);
		printf("[SERVER] HMAC Digest : \n");
		printBytes(hmac,strlen(hmac));
		HMAC_CTX_free(ctx2);
	}

	/*
	// Divide buffer to encrypted_key   CMAC
	U8 r_encrypt[KEYSIZE+MACSIZE];
	U8 r_mac[MACSIZE];	
	for(int i=0; i<KEYSIZE; i++){
		r_encrypt[i] = buf[i];
	}
	for(int i=KEYSIZE;i<KEYSIZE+MACSIZE;i++){
		r_mac[i-KEYSIZE] = buf[i];
	}
	*/


	mq_close(mq);
	printf("[SERVER CLOSED]\n");
	return 0;
}

