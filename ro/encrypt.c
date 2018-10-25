#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "encrypt.h"

int secretkey = 0xc007f00l;

int encrypt(const unsigned char* src, unsigned char** enc, unsigned int len){
  unsigned int i;

  *enc = malloc(len);

  srand(secretkey);
  for (i=0;i<len;i++) {
    memset(*enc+i, src[i] ^ (rand() % 256), 1);
  }

  return(len);
}

int decrypt(const unsigned char* src, unsigned char** dec, unsigned int len){
  unsigned int i;

  // +1 to get additional zero byte - just in case ;-)
  *dec = malloc(len+1);
  memset(*dec, 0x00, len+1);

  srand(secretkey);
  for (i=0;i<len;i++) {
    memset(*dec+i, src[i] ^ (rand() % 256), 1);
  }

  return(len);
}
