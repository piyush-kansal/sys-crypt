/*	
 *	FILE:		sys_xcrypt.h
 *	AUTHOR:		Piyush Kansal
 *	DESCRIPTION:	Header file to implement file encryption/decryption using static linking
 */


/*	
 *	Include appropriate header files
 */
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#include <linux/linkage.h>
#include <linux/init.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/scatterlist.h>
#include <asm/scatterlist.h>
#include <asm/uaccess.h>


/*	
 *	Declare required constants
 */
#define _FLAG_ENCRYPT_ 		1
#define _FLAG_DECRYPT_ 		0
#define _NEW_LINE_		'\n'
#define _NULL_CHAR_		'\0'
#define _TRUE_			1
#define _FALSE_			0
#define _ETX_			0x03
#define _UL_MAX_SIZE_		19
