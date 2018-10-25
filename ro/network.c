#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "network.h"
#include "encrypt.h"

int senddata(const unsigned char *msg, int len) {
  unsigned int elen, slen;
  unsigned char *crypt;

  elen = encrypt(msg, &crypt, len);
  slen = htonl(elen);

  fwrite((char *)&slen, 1, sizeof(elen), stdout);
  fwrite(crypt, 1, elen, stdout);
  fflush(stdout);
  free(crypt);

  return(0);
}

int recvdata(unsigned char **buf) {
  unsigned int slen, plen, elen;
  unsigned char *crypt;
  int res;

  res = fread(&slen, 1, 4, stdin);
  if (res != 4) return(-1);

  elen = ntohl(slen);
  if (elen > 1024) {
    return(-1);
  }
  crypt = malloc(elen);

  res = fread(crypt, 1, elen, stdin);

  if (res != elen) {
    free(crypt);
    return(-1);
  }

  *buf = malloc(elen);
  plen = decrypt(crypt, buf, elen);
  free(crypt);

  return(plen);
}
