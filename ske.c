#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+-------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(C) (32 bytes for SHA256) |
 * +------------+--------------------+-------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */

    if(entropy == NULL)
    {
        unsigned char* buff = malloc(HM_LEN); 
        // get hmacKey
        randBytes(buff, HM_LEN);
        memcpy((*K).hmacKey, buff, HM_LEN);
         // get aesKey
        randBytes(buff, HM_LEN);
        memcpy((*K).aesKey, buff, HM_LEN);
        
        free(buff);
    }
    else
    {
        // allocate 64 bytes
        unsigned char* keys = malloc(EVP_MAX_MD_SIZE);
        // get 512-bit authentication code of entropy with KDF_KEY
        HMAC(EVP_sha512(), &KDF_KEY, HM_LEN, entropy, entLen, keys, NULL);
        // half of keys array corresponds to HMAC key
        // the other half corresponds to AES key
        memcpy((*K).hmacKey, keys, HM_LEN);
        memcpy((*K).aesKey, keys + HM_LEN, HM_LEN);        

        free(keys);
    }

    return 0;
}

size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}

size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K, unsigned char* IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */

	size_t i;
	len = strlen(inBuf);
	int nWritten;
	size_t outBufLen = nWritten;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	//initializing the encryption oparation
	if (1!=EVP_EncryptInit_ex(ctx,EVP_aes_256_cbc(),0,(*K).hmacKey[len],randBytes(IV, len)))
		ERR_print_errors_fp(stderr);

	// Providing the plaintext to be encrypted
	if (1!=EVP_EncryptUpdate(ctx,outBuf,nWritten,inBuf,len))
		ERR_print_errors_fp(stderr);

	for (i = 0; i < outBufLen; i++) {
		fprintf(stderr, "%02x",outBuf[i]);
	}
	printf("The number of bytes writen is %i\n",nWritten ); // number of bytes witen

	// free up the memory
    	EVP_CIPHER_CTX_free(ctx);
	return 0; /* TODO: should return number of bytes written, which
	             hopefully matches ske_getOutputLen(...). */

}
size_t ske_encrypt_file(const char* fnout, const char* fnin,SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */

	unsigned char *mapped_file = mmap (NULL, offset_out, PROT_READ , MAP_PRIVATE,fnin, 0); 

	ske_encrypt(fnout, mapped_file, offset_out, (*k).hmacKey[offset_out],IV);

	return 0;
}

size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,SKE_KEY* K)

{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */

	size_t i;
	int nWritten = 0;
	size_t outBufLen = nWritten;

	len = strlen(inBuf);
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	

	//Initialize the decription operation
	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),NULL,(*k).hmacKey[len],NULL))
		ERR_print_errors_fp(stderr);

	// providing the message to be decrypted
	if (1!=EVP_DecryptUpdate(ctx,inBuf,&nWritten,outBuf,outBufLen))
		ERR_print_errors_fp(stderr);

	for (i = 0; i < outBufLen; i++) {
			fprintf(stderr, "%02x",outBuf[i]);
		}


	if (!outBuf){ // if ciphertext invalid return -1
		return -1;
	}else{ // otherwise return number of bytes writen 
		printf("%i\n",nWritten);
	}

	// fprintf(stderr, "%s\n",inBuf);


	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

size_t ske_decrypt_file(const char* fnout, const char* fnin,SKE_KEY* K, size_t offset_in)
{
	/* TODO: write this. */

	unsigned char *mapped_file = mmap (NULL, offset_in, PROT_READ , MAP_PRIVATE,fnout, 0); 

	ske_decrypt(mapped_file, fnin, offset_in, (*k).hmacKey[offset_in]);

	return 0;
}
