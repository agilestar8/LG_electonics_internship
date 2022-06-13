#include <stdio.h>
#include <openssl/cmac.h>
#include "aes_cbc.h"

void printBytes(unsigned char *buf, size_t len) {
  for(int i=0; i<len; i++) {
    printf("%02x ", buf[i]);
  }
  printf("\n");
}

int main(int argc, char *argv[])
{

  // Mac Key: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
  unsigned char key[] = { 0x2b,0x7e,0x15,0x16, 
                          0x28,0xae,0xd2,0xa6,
                          0xab,0xf7,0x15,0x88,
                          0x09,0xcf,0x4f,0x3c};
	

  // M: 6b c1 be e2 2e 40 9f 96 e9 3d 7e 11 73 93 17 2a   Mlen: 128
  unsigned char message[] = { 0x6b,0xc1,0xbe,0xe2, 
                              0x2e,0x40,0x9f,0x96, 
                              0xe9,0x3d,0x7e,0x11, 
                              0x73,0x93,0x17,0x2a };

  unsigned char mact[16] = {0}; 
  size_t mactlen;



  // CMAC create 

  CMAC_CTX *ctx = CMAC_CTX_new();
  CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL);
  printf("message length = %lu bytes (%lu bits)\n",sizeof(message), sizeof(message)*8);
 
  CMAC_Update(ctx, message, sizeof(message));
  CMAC_Final(ctx, mact, &mactlen);

  printBytes(mact, mactlen);
  /* expected result T = 070a16b4 6b4d4144 f79bdd9d d04a287c */

  CMAC_CTX_free(ctx);
  return 0;
}

