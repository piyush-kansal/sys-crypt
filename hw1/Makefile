obj-y += sys_xcrypt.o

all:
	gcc -Wall -Werror xcipher.c -o xcipher -lssl -lcrypto

clean:
	rm -f *.o
	rm -f sys_xcrypt
	rm -f xcipher
	rm -f built*
	rm -f modules*
