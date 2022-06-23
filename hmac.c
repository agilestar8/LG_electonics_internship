#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/hmac.h>
//#include<openssl/evp.h>

typedef unsigned char U8;


int main(){
	U8 key[10] = {1,2,3,4,5,6,7,8,9,10};
//	U8 data[16] = {1,2,3,4,5,6,7,8,9,10};
	char *data = "hello";

	// HMAC create
	int len = sizeof(key);
	U8 hmac[100];

	HMAC_CTX *ctx2 = HMAC_CTX_new();
	HMAC_CTX_reset(ctx2);

    HMAC_Init_ex(ctx2, key, sizeof(key), EVP_sha256(), NULL);
    HMAC_Update(ctx2, hmac, sizeof(data));
    HMAC_Final(ctx2, hmac, &len);

	printf("key : ");
	for(int i=0;i<strlen(hmac);i++){
		printf("%02x ", data[i]);
	}
	printf("\n %d ", sizeof(data));


	printf("HMAC Digest : \n");
	for(int i=0;i<strlen(hmac);i++){
		printf("%02x ", hmac[i]);
	}
	printf("\n %d", strlen(hmac));

	HMAC_CTX_free(ctx2);

	return 0;
}
