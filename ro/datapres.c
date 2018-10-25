#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <signal.h>

#include "encrypt.h"
#include "network.h"

#define URANDOM "/dev/urandom"
#define ADMIN_HASH "\x55\x50\xc2\xa7\xab\xfc\x21\x44\x2f\xce\x66\xf4\x2a\x2a\xdc\xe2"
#define DATA_DIR "./"

#define PROMPT "> "
#define WELCOMEMSG "Welcome to German Data Preservation Service (DPS)!\nThis is a high secure service - no data will be given to external people!\n"
#define UNKNOWNMSG "Unknown command.\n"
#define QUITMSG "Thanks for using our service!\n"
#define NOTFOUND "Record not found!\n"
#define NOPERM "Permission denied!\n"
#define INVALIDTOKEN "Invalid token!\n"

char admin_flag = 0;

struct data{
    unsigned char name[50];
    unsigned int src_ip;
    unsigned int dst_ip;
    time_t timestamp;
    unsigned char token[17];
    unsigned char comment[100];
};

long long random_value(){
    FILE *f = fopen(URANDOM, "r");
    unsigned long long ran;
    fread(&ran, 1, 8, f);

    fclose(f);

    return ran;
}

struct data load(char* token) {
    FILE *f;
    char *filename;

    filename = malloc(64);
    strcpy(filename, DATA_DIR);
    strcat(filename, token);

    f = fopen(filename, "r");
    struct data data;

    // todo: check ret value
    fread(&data, sizeof(struct data), 1, f);

    fclose(f);

    free(filename);

    return data;
}

void save(struct data data){
    unsigned char *filename;
    FILE *f;

    filename = malloc(64);
    strcpy(filename, DATA_DIR);
    strcat(filename, data.token);
    puts(filename);
    f = fopen(filename, "w+");
    fwrite(&data, sizeof(struct data), 1, f);
    fclose(f);

    free(filename);
}

void set(){
    struct in_addr inp;
    struct data data;

    unsigned char *tmp_ptr;
    int len;
    senddata("Name: ",6);
    recvdata(&tmp_ptr);
    strncpy(data.name, tmp_ptr, 50);
    free(tmp_ptr);

    senddata("Source IP: ", 11);
    recvdata(&tmp_ptr);
    inet_aton(tmp_ptr,&inp);
    data.src_ip = inp.s_addr;
    free(tmp_ptr);

    senddata("Destination IP: ", 16);
    recvdata(&tmp_ptr);
    memset(&inp, 0,sizeof(struct in_addr));
    inet_aton(tmp_ptr,&inp);
    data.dst_ip = inp.s_addr;
    free(tmp_ptr);

    senddata("Comment: ",9);
    recvdata(&tmp_ptr);
    strncpy(data.comment, tmp_ptr,100);
    data.comment[99] = '\0';
    free(tmp_ptr);

    unsigned long long token = random_value();
    snprintf(data.token, 17, "%.16llx", token);
    tmp_ptr = malloc(40);
    memset(tmp_ptr,0,40);

    data.timestamp = time(0);
    senddata(data.token,16);

    save(data);

    free(tmp_ptr);
}

void login(){
    int i = 0;
    unsigned int flag = 0;
    unsigned char password[40];
    unsigned char digest[16];

    unsigned char *pw;
    senddata("Password: ", 10);
    recvdata(&pw);
    for(i=0; i<40; i++){
      if(pw[i] == 0){
        break;
      }
      password[i] = pw[i];
    }

    MD5_CTX context;
    MD5_Init(&context);
    MD5_Update(&context, password, strlen(password));
    MD5_Final(digest, &context);

    if(strncmp(digest, ADMIN_HASH,16) == 0){
        senddata("Logged in\n", 9);
        memset(password,0,strlen(password));
        flag = 1;
    }
    else{
        senddata("Wrong password!\n", 16);
    }
    memset(password, 0, 40);
    admin_flag = flag;
    free(pw);
}

void logout(){
    admin_flag = 0;
    senddata("Logged out\n", 11);
}

void retrieve(){
    unsigned char *name;
    unsigned char *token;
    unsigned char* buf = malloc(100);
    struct in_addr inp;
    char *tmp;
    int i;

    senddata("Name: ", 6);
    recvdata(&name);

    senddata("Token: ", 7);
    recvdata(&token);

    // verify token user input
    for (i=0;i<strlen(token);i++) {
      if (!((token[i] >= 0x30 && token[i] <= 0x39) || (token[i] >= 0x61 && token[i] <= 0x7a))) {

        senddata(INVALIDTOKEN, strlen(INVALIDTOKEN));

        free(name);
        free(token);

        return;
      }
    }

    struct data data = load(token);
    if (strncmp(data.name, name, sizeof(data.name)) == 0) {
      memset(buf,0,100);
      snprintf(buf, sizeof(data.name), "Name: %s\n", data.name);
      senddata(buf, strlen(buf));

      memset(buf,0,100);
      inp.s_addr = data.src_ip;
      tmp = inet_ntoa(inp);
      snprintf(buf, 50, "Source IP: %s\n", tmp);
      senddata(buf, strlen(buf));

      memset(buf,0,100);
      inp.s_addr = data.dst_ip;
      tmp = inet_ntoa(inp);
      snprintf(buf, 50, "Destination IP: %s\n", tmp);
      senddata(buf, strlen(buf));

      memset(buf,0,100);
      snprintf(buf, sizeof(data.comment), "Comment: %s\n", data.comment);
      senddata(buf, strlen(buf));
    } else senddata(NOTFOUND, strlen(NOTFOUND));

    free(name);
    free(token);
}

void show_all(){
  if(!admin_flag){
    senddata(NOPERM, strlen(NOPERM));
    return;
  }
  struct data data;
  unsigned char* buf = malloc(100);
  unsigned char* tmp;
    struct in_addr inp;

  DIR *dp;
  struct dirent *ep;
  dp = opendir (DATA_DIR);

  if (dp != NULL)
  {
    while (ep = readdir (dp)){
      if(strlen(ep->d_name)==16){
        data = load(ep->d_name);
        memset(buf,0,100);
        snprintf(buf, sizeof(data.name), "Name: %s\n", data.name);
        senddata(buf, strlen(buf));

        memset(buf,0,100);
        inp.s_addr = data.src_ip;
        tmp = inet_ntoa(inp);
        snprintf(buf, 50, "Source IP: %s\n", tmp);
        senddata(buf, strlen(buf));

        memset(buf,0,100);
        inp.s_addr = data.dst_ip;
        tmp = inet_ntoa(inp);
        snprintf(buf, 50, "Destination IP: %s\n", tmp);
        senddata(buf, strlen(buf));

        memset(buf,0,100);
        snprintf(buf, sizeof(data.comment), "Comment: %s\n", data.comment);
        senddata(buf, strlen(buf));
      }
    }

    (void) closedir (dp);
  }
}

void help() {
  unsigned char *helpcmd;

  helpcmd = malloc(256);
  memset(helpcmd, 0, 256);

  strcpy(helpcmd, "Commands:\n");
  strcat(helpcmd, "r - retrieve\n");
  strcat(helpcmd, "s - set\n");
  if(admin_flag) strcat(helpcmd, "a - show all\n");
  else strcat(helpcmd, "l - login\n");
  strcat(helpcmd, "h - help\n");
  strcat(helpcmd, "q - quit\n");

  senddata(helpcmd, strlen(helpcmd));
}


int main(int argc, char const *argv[]) {
  int enable = 1;
  // WELCOME MESSAGE
  senddata(WELCOMEMSG, strlen(WELCOMEMSG));
  senddata(PROMPT, strlen(PROMPT));

  // READ CLIENT COMMAND
  unsigned char *data;
  int datalen = 1;
  char *pos;

  while (1) {
    datalen = recvdata(&data);

    if ((pos = strchr(data, '\n')) != NULL) *pos = 0x00;

    if (strcmp(data, "r") == 0) retrieve();
    else if (strcmp(data, "s") == 0) set();
    else if (strcmp(data, "l") == 0) login();
    else if (strcmp(data, "h") == 0) help();
    else if (strcmp(data, "a") == 0 && admin_flag) show_all();
    else if (strcmp(data, "q") == 0) {
      senddata(QUITMSG, strlen(QUITMSG));
      exit(0);
    }
    else senddata(UNKNOWNMSG, strlen(UNKNOWNMSG));
    senddata(PROMPT, strlen(PROMPT));

    free(data);
  }

  /* code */
  return(0);
}
