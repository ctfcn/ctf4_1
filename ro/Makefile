all: encrypt network
	gcc  -fno-stack-protector -O0 datapres.c encrypt.o network.o -o gdps -lcrypto

encrypt: encrypt.c
	gcc -c encrypt.c -o encrypt.o


network: network.c
	gcc -c network.c -o network.o

clean:
	rm -f *.o gdps
