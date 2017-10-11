#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
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

        // setup a random initialization vector (IV) if none is given
        if(IV == NULL)
        {
                IV = malloc(AES_BLOCK_SIZE);
                randBytes(IV, AES_BLOCK_SIZE);
        }

	int nWritten;
        unsigned char* c = malloc(len);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	// setup context ctx for encryption
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, (*K).aesKey, IV))
	        ERR_print_errors_fp(stderr);
	// do the actual encryption
	if(1 != EVP_EncryptUpdate(ctx, c, &nWritten, inBuf, len))
		ERR_print_errors_fp(stderr);	

        // setup outBuf 
        unsigned char* tempBuf = malloc(AES_BLOCK_SIZE + nWritten + HM_LEN);
        memcpy(tempBuf, IV, AES_BLOCK_SIZE); 
        memcpy(tempBuf + AES_BLOCK_SIZE, c, nWritten); 
        HMAC(EVP_sha256(), (*K).hmacKey, HM_LEN, c, nWritten, tempBuf + AES_BLOCK_SIZE + nWritten, NULL); 
        memcpy(outBuf, tempBuf, AES_BLOCK_SIZE + nWritten + HM_LEN);

        // free up the memory
        free(c);
        free(tempBuf);
    	EVP_CIPHER_CTX_free(ctx);

	return (AES_BLOCK_SIZE + nWritten + HM_LEN); /* TODO: should return number of bytes written, which
	             hopefully matches ske_getOutputLen(...). */
}

size_t ske_encrypt_file(const char* fnout, const char* fnin,SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */

	//unsigned char *mapped_file = mmap (NULL, offset_out, PROT_READ , MAP_PRIVATE,fnin, 0); 

	//ske_encrypt(fnout, mapped_file, offset_out, (*k).hmacKey[offset_out],IV);

	return 0;
}

size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len, SKE_KEY* K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */

	// compute and check mac
	unsigned char* mac = malloc(HM_LEN);	
	HMAC(EVP_sha256(), (*K).hmacKey, HM_LEN, inBuf, len, mac, NULL); 
	if(0 != memcmp(mac, inBuf + len - HM_LEN, HM_LEN))
		return -1;

	int nWritten;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();	

	// extract IV 
	unsigned char* IV = malloc(AES_BLOCK_SIZE);
	memcpy(IV, inBuf, AES_BLOCK_SIZE);

	// setup ctx for decryption
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, (*K).aesKey, IV))
		ERR_print_errors_fp(stderr);

	// do the actual decryption
	if(1 != EVP_DecryptUpdate(ctx, outBuf, &nWritten, inBuf, len))
		ERR_print_errors_fp(stderr);

        // free up the memory
        free(mac);
	free(IV);
	EVP_CIPHER_CTX_free(ctx); 

	return 0;
}

size_t ske_decrypt_file(const char* fnout, const char* fnin,SKE_KEY* K, size_t offset_in)
{
	/* TODO: write this. */

//	unsigned char *mapped_file = mmap (NULL, offset_in, PROT_READ , MAP_PRIVATE,fnout, 0); 

//	ske_decrypt(mapped_file, fnin, offset_in, (*k).hmacKey[offset_in]);

	return 0;
}
