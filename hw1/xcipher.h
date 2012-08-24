#include <stdio.h>
#include <malloc.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>

#define __NR_sys_xcrypt	349

void printMd5Sum( unsigned char* md, char* md5 );
