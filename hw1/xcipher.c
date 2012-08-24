#include "xcipher.h"

int main( int argc, char **argv ) {
	char *inFile = NULL, *opFile = NULL, *passwd = NULL, *updPass = NULL;
	char encryptedKey[ 2 * MD5_DIGEST_LENGTH + 1 ];
	unsigned char md5buff[ MD5_DIGEST_LENGTH ];

	int eFlag = 0, dFlag = 0, c, ret = 0;
	int validCharCnt = 0, i = 0;

	while( ( c = getopt( argc, argv, "edhp:" ) ) != -1 )
		switch( c ) {
			case 'e':
				eFlag = 1;
				break;

			case 'd':
				dFlag = 1;
				break;

			case 'p':
				passwd = optarg;
				break;

			case 'h':
				printf( "It is a program to encrypt/decrypt a file using AES algorithm in CBC mode\n" );
				printf ( "Usage: ./xcipher -p <password> -e infile outfile (for encryption)\n" );
				printf ( "Usage: ./xcipher -p <password> -d infile outfile (for decryption)\n" );
				return 0;				

			case '?':
				fprintf( stderr, "Unknown option \"%c\".\n", optopt );
				return -1;
		}

	// - Input values validation
	if( ( ( argc - optind ) > 2 ) || ( ( argc - optind ) < 2 ) || ( eFlag == dFlag ) ) {
		printf( "Wrong usage detected\n" );
		printf ( "Usage: ./xcipher -p <password> -e infile outfile (for encryption)\n" );
		printf ( "Usage: ./xcipher -p <password> -d infile outfile (for decryption)\n" );
		return -1;
	}

	inFile = argv[ optind ];
	opFile = argv[ optind + 1 ];

	// - Look for '\n' in user passsword
	while( passwd[i] ) {
		if( passwd[i] != '\n' )
			validCharCnt++;

		i++;
	}

	// - Remove '\n' from the i/p password to create a valid password
	updPass = (char *)malloc( ( validCharCnt + 1 ) * sizeof( char ) );
	if( !updPass ) {
		printf ( "Out of Memory!" );
		return -1;
	}

	i = 0;
	validCharCnt = 0;
	while ( passwd[i] ) {
		if( passwd[i] != '\n' ) {
			updPass[validCharCnt] = passwd[i];
			validCharCnt++;
		}

		i++;
	}

	updPass[validCharCnt] = '\0';

	// - Check for validity of the password length
	if( validCharCnt < 6 ) {
		printf( "Password length should be of minimum 6 characters\n" );
		return -1;
	}

	// - Generate MD5 Hash
	MD5( (unsigned char*)updPass, strlen( updPass ), md5buff );
	printMd5Sum( md5buff, encryptedKey );

	if( eFlag )
		ret = syscall( __NR_sys_xcrypt, inFile, opFile, encryptedKey, strlen( encryptedKey ), 1 );
	else if( dFlag )
		ret = syscall( __NR_sys_xcrypt, inFile, opFile, encryptedKey, strlen( encryptedKey ), 0 );

	if( ret < 0 )
		perror( "Error" );

	free( updPass );
	updPass = NULL;

	return ret;
}

void printMd5Sum( unsigned char* md, char* md5 ) {
	int i;

	for( i = 0 ; i < MD5_DIGEST_LENGTH; i++ ) {
		char temp[3];
		snprintf( temp, sizeof( temp ), "%02x", md[i] );

		if( i == 0 )
			strncpy( md5, temp, 3 );
		else
			strncat( md5, temp, MD5_DIGEST_LENGTH );
	}
}
