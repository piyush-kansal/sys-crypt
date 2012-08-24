/*	
 *	FILE:		sys_xcrypt.c
 *	AUTHOR:		Piyush Kansal
 *	DESCRIPTION:	Source file to implement file encryption/decryption using static linking
 */


#include "sys_xcrypt.h"


/*
 *	Function definition for FILL_SG.
 *	This function is used to fill up the scatter list structure
 */
void FILL_SG( struct scatterlist *sg, char *ptr, int len ) {
	#ifdef CONFIG_DEBUG_SG
		sg->sg_magic = SG_MAGIC;
	#endif

	sg->page_link = (unsigned long)virt_to_page( ptr );
	sg->offset = offset_in_page( ptr );
	sg->length = len;
}

/* 	
 *	Function definition for sys_xcrypt.
 *	This function encrypts/decrypts files using AES Block Cipher algorithm using CBC mode.
 */
asmlinkage int sys_xcrypt( const char * const infile, const char * const opfile, const char * const keybuf, const int keylen, const short int flags ) {
	const char algo[] = "cbc(aes)";
	char *ipBuf = NULL, *opBuf = NULL, *iv = NULL, *inFile = NULL, *opFile = NULL, *keyBuf = NULL;
	int errno = 0, ret = 0;
	int actReadLen = 0, actWriteLen = 0, padLen = 0, blkSiz = 0, ipFileLen = 0, opFileLen = 0, keyLen = 0;
	int delOpFile = 0, prmbLen = 0, idx = 0;
	unsigned int fileSize = 0, factor = 1;
	struct file *inFilePtr = NULL, *opFilePtr = NULL;
	struct crypto_blkcipher *tfm = NULL;
	struct blkcipher_desc desc;
	struct scatterlist sg[2];
	struct dentry *tmpDentry;
	struct inode *tmpInode = NULL;
	mm_segment_t oldfs;

	/* Check for NULL pointers or invalid values */
	if( ( NULL == infile ) || ( NULL == opfile ) || ( NULL == keybuf ) || ( ( _FLAG_ENCRYPT_ != flags ) && ( _FLAG_DECRYPT_ != flags ) ) ) {
		printk( KERN_ALERT "Invalid I/P" );
		errno = -EINVAL;
		goto OUT_OK;
	}

	/* Verify if all the pointers belong to the user's own address space */
	ret = access_ok( VERIFY_READ, infile, 0 );
	if( !ret ) {
		printk( KERN_ALERT "Invalid pointer to I/P file passed as argument" );
		errno = -EFAULT;
		goto OUT_OK;
	}

	ret = access_ok( VERIFY_READ, opfile, 0 );
	if( !ret ) {
		printk( KERN_ALERT "Invalid pointer to O/P file passed as argument" );
		errno = -EFAULT;
		goto OUT_OK;
	}

	ret = access_ok( VERIFY_READ, keybuf, 0 );
	if( !ret ) {
		printk( KERN_ALERT "Invalid pointer to Password passed as argument" );
		errno = -EFAULT;
		goto OUT_OK;
	}

	/* Find out the length of the i/p buffers */
	ipFileLen = strlen_user( infile );
	opFileLen = strlen_user( opfile );
	keyLen = strlen_user( keybuf );

	/* Allocate buffers to copy i/p arguments from user space to kernel space */
	inFile = kmalloc( ipFileLen, GFP_KERNEL );
	if( NULL == inFile ) {
		errno = -ENOMEM;
		goto OUT_OK;
	}
	else {
		ret = strncpy_from_user( inFile, infile, ipFileLen );
		if( ret < 0 ) {
			errno = ret;
			goto OUT_IP;
		}
	}
		
	opFile = kmalloc( opFileLen, GFP_KERNEL );
	if( NULL == opFile ) {
		errno = -ENOMEM;
		goto OUT_IP;
	}
	else {
		ret = strncpy_from_user( opFile, opfile, opFileLen );
		if( ret < 0 ) {
			errno = ret;
			goto OUT_IP;
		}
	}
		
	keyBuf = kmalloc( keyLen, GFP_KERNEL );
	if( NULL == keyBuf ) {
		errno = -ENOMEM;
		goto OUT_IP;
	}
	else {
		ret = strncpy_from_user( keyBuf, keybuf, keyLen );
		if( ret < 0 ) {
			errno = ret;
			goto OUT_IP;
		}
	}

	/* Open I/P file. It will report error in case of non-existing file and bad permissions but not bad owner */
	inFilePtr = filp_open( inFile, O_RDONLY, 0 );
	if ( !inFilePtr || IS_ERR( inFilePtr ) ) {
		errno = (int)PTR_ERR( inFilePtr );
		printk( KERN_ALERT "Error opening i/p file: %d\n", errno );
		inFilePtr = NULL;
		goto OUT_IP;
    	}

	/* Check if the file is a regular file or not */
	if( !S_ISREG( inFilePtr->f_path.dentry->d_inode->i_mode ) ) {
		printk( KERN_ALERT "Error as file is not a regular one" );
		errno = -EBADF;
		goto OUT_FILE;
	}

	/* Check if the I/p file and the process owner match */
	if( ( current->real_cred->uid != inFilePtr->f_path.dentry->d_inode->i_uid ) && ( current->real_cred->uid != 0 ) ) {
		printk( KERN_ALERT "Error as owner of file and process does not match" );
		errno = -EACCES;
		goto OUT_FILE;
	}

	/* Open O/P file with error handling */
	opFilePtr = filp_open( opFile, O_WRONLY | O_CREAT | O_EXCL, 0 );
	if ( !opFilePtr || IS_ERR( opFilePtr ) ) {
		errno = (int)PTR_ERR( opFilePtr );
		printk( KERN_ALERT "Error opening o/p file: %d\n", errno );
		opFilePtr = NULL;
		goto OUT_FILE;
	}

	/* 
	 * Check if the infile and opfile point to the same file
	 * If they reside on the different file partition and have same name then it should be allowed else not
	 */
	if( 	( inFilePtr->f_path.dentry->d_inode->i_sb == opFilePtr->f_path.dentry->d_inode->i_sb ) && 
		( inFilePtr->f_path.dentry->d_inode->i_ino ==  opFilePtr->f_path.dentry->d_inode->i_ino ) ) {
		printk( KERN_ALERT "I/p and O/p file cannot be same" );
		errno = -EINVAL;
		goto OUT_FILE;
	}

	/* Set the o/p file permission to i/p file */
	opFilePtr->f_path.dentry->d_inode->i_mode =  inFilePtr->f_path.dentry->d_inode->i_mode;
	
	/* Set the file position to the beginning of the file */
	inFilePtr->f_pos = 0;
	opFilePtr->f_pos = 0;

	/* Allocate buffer to read data into and to write data to. For performance reasons, set its size equal to PAGE_SIZE */
	ipBuf = kmalloc( PAGE_SIZE, GFP_KERNEL );
	if( NULL == ipBuf ) {
		errno = -ENOMEM;
		goto OUT_FILE;
	}
		
	memset( ipBuf, _NULL_CHAR_, PAGE_SIZE );

	opBuf = kmalloc( PAGE_SIZE, GFP_KERNEL );
	if( NULL == opBuf ) {
		errno = -ENOMEM;
		goto OUT_DATA_PAGE;
	}
		
	memset( opBuf, _NULL_CHAR_, PAGE_SIZE );

	/* Allocate tfm */
	tfm = crypto_alloc_blkcipher( algo, 0, CRYPTO_ALG_ASYNC );
	if ( NULL == tfm  ) {
		printk( KERN_ALERT "Failed to load transform for %s: %ld\n", algo, PTR_ERR( tfm ) );
		errno = -EINVAL;
		goto OUT_DATA_PAGE;
	}

	/* Initialize desc */
	desc.tfm = tfm;
	desc.flags = 0;

	ret = crypto_blkcipher_setkey( tfm, keybuf, keylen );
	if( ret ) {
		printk( "Setkey() failed. Flags=%x\n", crypto_blkcipher_get_flags( tfm ) );
		errno = -EINVAL;
		goto OUT_CIPHER;
	}

	/* Initialize sg structure */
	FILL_SG( &sg[0], ipBuf, PAGE_SIZE );
	FILL_SG( &sg[1], opBuf, PAGE_SIZE );

	/* Get the block size */
	blkSiz = ((tfm->base).__crt_alg)->cra_blocksize;

	/* Initialize IV */
	iv = kmalloc( blkSiz, GFP_KERNEL );
	if( NULL == iv ) {
		errno = -ENOMEM;
		goto OUT_CIPHER;
	}
		
	memset( iv, _NULL_CHAR_, blkSiz );
	crypto_blkcipher_set_iv( tfm, iv, crypto_blkcipher_ivsize( tfm ) );

	/* Store the key and file size in encrypted form in the preamble */
	switch( flags ) {
		case _FLAG_ENCRYPT_:
			memcpy( ipBuf, keybuf, keylen );
			prmbLen = keylen;
			fileSize = (unsigned int)inFilePtr->f_path.dentry->d_inode->i_size;

			while( fileSize ) {
				ipBuf[ prmbLen + idx ] = fileSize % 10;
				fileSize /= 10;
				++idx;
			}

			prmbLen += idx;

			#ifdef _DEBUG_
				printk( KERN_ALERT "idx=%d prmbLen=%d\n", idx, prmbLen );
			#endif

			memset( ipBuf + prmbLen, _ETX_, _UL_MAX_SIZE_ - idx );
			prmbLen += ( _UL_MAX_SIZE_ - idx );

			#ifdef _DEBUG_
				printk( KERN_ALERT "prmbLen=%d\n", prmbLen );
			#endif

			padLen = blkSiz - ( prmbLen % blkSiz );
			memset( ipBuf + prmbLen, _ETX_, padLen );
			prmbLen += padLen;
  
			#ifdef _DEBUG_
				printk( KERN_ALERT "padLen=%d prmbLen=%d\n", padLen, prmbLen );
			#endif

			ret = crypto_blkcipher_encrypt( &desc, &sg[1], &sg[0], prmbLen );
			if (ret) {
				printk( KERN_ALERT "Encryption failed. Flags=0x%x\n", tfm->base.crt_flags );
				delOpFile = 1;
				goto OUT_IV;
			}

			oldfs = get_fs();
			set_fs( KERNEL_DS );

			opFilePtr->f_op->write( opFilePtr, opBuf, prmbLen, &opFilePtr->f_pos );

			/* Reset the address space to user one */
			set_fs( oldfs );

			break;

		case _FLAG_DECRYPT_:
			/* Set the address space to kernel one */
			oldfs = get_fs();
			set_fs( KERNEL_DS );

			prmbLen = keylen + _UL_MAX_SIZE_;
			padLen = blkSiz - ( prmbLen % blkSiz );
			prmbLen += padLen;

			#ifdef _DEBUG_
				printk( KERN_ALERT "padLen=%d prmbLen=%d\n", padLen, prmbLen );
			#endif

			actReadLen = inFilePtr->f_op->read( inFilePtr, ipBuf, prmbLen, &inFilePtr->f_pos );
			if( actReadLen != prmbLen ) {
				printk( KERN_ALERT "Requested number of bytes for preamble are lesser" );
				delOpFile = 1;
				goto OUT_IV;
			}

			#ifdef _DEBUG_
				printk( KERN_ALERT "actReadLen=%d\n", actReadLen );
			#endif

			/* Reset the address space to user one */
			set_fs( oldfs );

			ret = crypto_blkcipher_decrypt( &desc, &sg[1], &sg[0], prmbLen );
			if (ret) {
				printk( KERN_ALERT "Decryption failed. Flags=0x%x\n", tfm->base.crt_flags );
				delOpFile = 1;
				goto OUT_IV;
			}

			ret = memcmp( keybuf, opBuf, keylen );
			if( ret ) {
				printk( "Wrong password entered." );
				errno = -EKEYREJECTED;
				goto OUT_IV;
			}

			idx = 0;
			fileSize = 0;

			while( opBuf[ keylen + idx ] != _ETX_ ) {
				fileSize += opBuf[ keylen + idx ] * factor;
				factor *= 10;
				++idx;
			}

			#ifdef _DEBUG_
				printk( KERN_ALERT "idx=%d fileSize=%u\n", idx, fileSize );
			#endif

			break;
	}

	/* Read file till the file pointer reaches to the EOF */
	while( inFilePtr->f_pos < inFilePtr->f_path.dentry->d_inode->i_size ) {
		/* Initialize it to NULL char */
		memset( ipBuf, _NULL_CHAR_, PAGE_SIZE );
		memset( opBuf, _NULL_CHAR_, PAGE_SIZE );

		/* Set the address space to kernel one */
		oldfs = get_fs();
		set_fs( KERNEL_DS );

		actReadLen = inFilePtr->f_op->read( inFilePtr, ipBuf, PAGE_SIZE, &inFilePtr->f_pos );

		/* Reset the address space to user one */
		set_fs( oldfs );

		/* As per the i/p flag, do encryption/decryption */
		switch( flags ) {
			case _FLAG_ENCRYPT_:
				/* For encryption ensure padding as per the block size */
				#ifdef _DEBUG_
					printk( KERN_ALERT "Bytes read from I/P file ::%d::\n", actReadLen );
				#endif

				if( actReadLen % blkSiz ) {
					padLen = blkSiz - ( actReadLen % blkSiz );
					memset( ipBuf + actReadLen, _ETX_, padLen );
					actReadLen += padLen;
				}

				#ifdef _DEBUG_
					printk( KERN_ALERT "Pad Length ::%d::\n", padLen );
					printk( KERN_ALERT "Data read from I/P file ::%s::\n", ipBuf );
				#endif

				/* Encrypt the data */
				ret = crypto_blkcipher_encrypt( &desc, &sg[1], &sg[0], PAGE_SIZE );
				if (ret) {
					printk( KERN_ALERT "Encryption failed. Flags=0x%x\n", tfm->base.crt_flags );
					delOpFile = 1;
					goto OUT_IV;
				}

				break;

			case _FLAG_DECRYPT_:
				/* Decrypt the data */
				ret = crypto_blkcipher_decrypt( &desc, &sg[1], &sg[0], PAGE_SIZE );
				if (ret) {
					printk( KERN_ALERT "Decryption failed. Flags=0x%x\n", tfm->base.crt_flags );
					delOpFile = 1;
					goto OUT_IV;
				}

				#ifdef _DEBUG_
					printk( KERN_ALERT "Bytes read from I/P file ::%d::\n", actReadLen );
				#endif

				while( _ETX_ == opBuf[ actReadLen - 1 ] ) {
					opBuf[ actReadLen - 1 ] = _NULL_CHAR_;
					--actReadLen;
				}

				#ifdef _DEBUG_
					printk( KERN_ALERT "Bytes read from I/P file ::%d::\n", actReadLen );
					printk( KERN_ALERT "Data read from I/P file ::%s::\n", opBuf );
				#endif


				break;
		}

		/*
		 * Start writing to the o/p file
		 * Set the address space to kernel one
		 */
		oldfs = get_fs();
		set_fs( KERNEL_DS );

		actWriteLen = opFilePtr->f_op->write( opFilePtr, opBuf, actReadLen, &opFilePtr->f_pos );

		/* Reset the address space to user one */
		set_fs( oldfs );

		#ifdef _DEBUG_
			printk( KERN_ALERT "Bytes written to O/P file ::%d::\n", actWriteLen );
		#endif
	}

	/* Free iv */
	OUT_IV:
		kfree( iv );
		iv = NULL;
		printk( KERN_ALERT "Memory for IV freed ..." );

	/* Free tfm */
	OUT_CIPHER:
		crypto_free_blkcipher( tfm );
		printk( KERN_ALERT "Encryption Transform freed ..." );

	/* Free i/p and o/p buffers */
	OUT_DATA_PAGE:
		if( ipBuf ) {
			kfree( ipBuf );
			ipBuf = NULL;
		}

		if( opBuf ) {
			kfree( opBuf );
			opBuf = NULL;
		}

		printk( KERN_ALERT "Memory for encrption/decryption freed ..." );

	/* Close any open files */
	OUT_FILE:
		if( inFilePtr ) {
			filp_close( inFilePtr, NULL );
			inFilePtr = NULL;
			printk( KERN_ALERT "I/p file closed ..." );
		}

		if( opFilePtr ) {
			filp_close( opFilePtr, NULL );
			opFilePtr = NULL;
			printk( KERN_ALERT "O/p file closed ..." );
		}

		if( delOpFile ) {
			opFilePtr = filp_open( opFile, O_WRONLY , 0 );
			if ( !opFilePtr || IS_ERR( opFilePtr ) ) {
				opFilePtr = NULL;
				goto OUT_IP;
			}

			tmpDentry = opFilePtr->f_path.dentry;
			tmpInode = tmpDentry->d_parent->d_inode;

			filp_close( opFilePtr, NULL );
			vfs_unlink( tmpInode, tmpDentry );
			printk( KERN_ALERT "O/p file deleted ..." );
		}

	OUT_IP:
		if( inFile ) {
			kfree( inFile );
			inFile = NULL;
		}

		if( opFile ) {
			kfree( opFile );
			opFile = NULL;
		}

		if( keyBuf ) {
			kfree( keyBuf );
			keyBuf = NULL;
		}

		printk( KERN_ALERT "Memory for I/P parameters freed ..." );

	/* Return final status */
	OUT_OK:
		printk( KERN_ALERT "Exiting function sys_xcrypt ..." );
		return errno;
}
