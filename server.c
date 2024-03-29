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

// AES_CBC Encrypt
int aes_encrypt( U8 *p_in, U8 *p_out, int size, U8 *key)
{
	AES_KEY aes_key;				// aes_key structure 
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
    U8 buf[KEYSIZE+MACSIZE] = {0,};
    mqd_t mq; 
	msg m;


/*
	// Read File
	int fd;
	U8 cipher_key[KEYSIZE]={0,};
	umask(0);

	fd = open("file.dlc",O_RDONLY,0666);	
	if (fd == 0){

		int encrypt_size = ((strlen(key_buf) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
		memcpy(temp, key_buf, encrypt_size);		
		aes_decrypt(temp, k_decrypt, encrypt_size, PSS_KEY);
		
		read(fd, cipher_key, KEYSIZE);

		U8 k_decrypt[KEYSIZE]={0,};		
		U8 temp[1024]={0,};	
		int encrypt_size;		
		
	
		printf("[SERVER] Read Decrypted File.dlc : \n");
		printBytes(cipher_key,KEYSIZE-4);
		printf("\n");
	}
	close(fd);



	// Receive First Key
	if open("file.dlc", O_RDONLY);

	U8 key_Buf[KEYSIZE];
	mq = mq_open("/mq_key", O_RDONLY, 0666, &attr);
    if (mq == 0)

	if(mq_receive(mq, key_buf, attr.mq_msgsize,NULL) == -1){
		print("[SERVER] Key Receive Error");	
	}
	mq_close(mq);
	

*/

	// load	
/*
	aes_encrypt(m.buffer, s_encrypt, sizeof(m.buffer), PSS_KEY);
	encrypt_size = ((strlen(m.buffer) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	memcpy(temp, m.buffer, encrypt_size);		
	aes_decrypt(temp, s_decrypt, encrypt_size, PSS_KEY);
	
	// save
    int fd;
	fd = open("file.dlc",O_WRONLY|O_CREAT,0666);
	write(fd, s_encrypt, KEYSIZE);
	printf("[SERVER] don't have key, create key file \n");		
	close(fd);
*/	

	int fd;
	U8 cipher_key[KEYSIZE]={0,};
	umask(0);

	fd = open("file.dlc",O_RDONLY,0666);	
	read(fd, cipher_key, KEYSIZE);
	printf("[SERVER] Read Decrypted File.dlc : \n");
	printBytes(cipher_key,KEYSIZE-4);
	printf("\n");
	close(fd);

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

	while (1){
		// Receive APP's data
		mq = mq_open("/mq_buf", O_RDWR | O_CREAT, 0666, &attr);
		if (mq == -1){
			perror("message queue open error");
			exit(1);
		 }
		if ((mq_receive(mq, (char *) &m, sizeof(m)+128, NULL)) == -1){
			printf("[SERVER] receive error");
		}
		m.ret = 0;
		printf("\n[SERVER] received data\n");	
		printf("[SERVER] cmd : %d\n", m.cmd);
		//printf("[SERVER] text : %s\n", m.buffer);
		//printf("[SERVER] return : %d\n", m.ret);
		printf("\n");

		U8 s_encrypt[KEYSIZE]={0,};
		U8 s_decrypt[KEYSIZE]={0,};		
		U8 temp[1024]={0,};	
		int encrypt_size;	

		// command		
		if (m.cmd == 1){
			aes_encrypt(m.buffer, s_encrypt, strlen(m.buffer), PSS_KEY);
			printf("[SERVER] Encrpyt : ");
			printBytes(s_encrypt,strlen(s_encrypt));
			printf("\n");
			}
		
		else if(m.cmd == 2){
			aes_encrypt(m.buffer, s_encrypt, strlen(m.buffer), PSS_KEY);	
			encrypt_size = ((strlen(m.buffer) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
			memcpy(temp, s_encrypt, encrypt_size);		
			aes_decrypt(temp, s_decrypt, encrypt_size, PSS_KEY);
		
			printf("[SERVER] buffer : ");
			printBytes(s_encrypt,strlen(s_encrypt));
			printf("[SERVER] Decrypted Text : ");
			printf("%s\n", s_decrypt);
			printf("\n");
		}
		else if(m.cmd == 3){
			aes_encrypt(m.buffer, s_encrypt, strlen(m.buffer), PSS_KEY);
	
			// Crate CMAC 
			U8 server_mac[MACSIZE] = {0}; 
			size_t mactlen;

			CMAC_CTX *ctx = CMAC_CTX_new();
			CMAC_Init(ctx, cmac_key, MACSIZE, EVP_aes_128_cbc(), NULL);
			CMAC_Update(ctx, m.buffer, strlen(m.buffer));
			CMAC_Final(ctx, server_mac, &mactlen);
			CMAC_CTX_free(ctx);

			printf("[SERVER] Generated CMAC : \n");
			printBytes(server_mac, mactlen);

			U8 AE[100];
			memcpy(AE, s_encrypt, strlen(s_encrypt));
			for(int i=0;i<MACSIZE;i++){
				AE[i+strlen(s_encrypt)] = server_mac[i];
			}

			printf("[SERVER] AE : \n");
			printBytes(AE,strlen(AE));
			printf("\n");

			}

		else if(m.cmd == 4){
			// Create HMAC
			int hlen = sizeof(hmac_key);
			U8 hmac[1024];
			HMAC_CTX *ctx2 = HMAC_CTX_new();
			HMAC_CTX_reset(ctx2);
			HMAC_Init_ex(ctx2, hmac_key, MACSIZE, EVP_sha256(), NULL);
			HMAC_Update(ctx2, m.buffer, strlen(m.buffer));
			HMAC_Final(ctx2, hmac, &hlen);
			printf("[SERVER] HMAC Digest : \n");
			printBytes(hmac,strlen(hmac));
			HMAC_CTX_free(ctx2);

			aes_encrypt(m.buffer, s_encrypt, strlen(m.buffer), PSS_KEY);	
			U8 AE[128];
			memcpy(AE, s_encrypt, strlen(s_encrypt));
			for(int i=0;i<strlen(hmac);i++){
				AE[i+strlen(s_encrypt)] = hmac[i];
			}
			printf("[SERVER] AE : \n");
			printBytes(AE,strlen(AE));
			printf("\n");


		}
		else if(m.cmd == 5){
			mq_close(mq);
			printf("[SERVER] Close Server\n");
			return 0;
		}
		else if(m.cmd == 6){
			printf("미구현\n");

		}

		else{
			printf("Usage error");
			mq_close(mq);
			return 0;
		}



	mq_close(mq);
	}
	
	
	return 0;
}

