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
#define IV_LEN 16 
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
                // generate random aesKey and hmacKey
                // half of buff array corresponds to HMAC key
                // the other half corresponds to AES key
                unsigned char* buff = malloc(64); 
                randBytes(buff, 64);               
                memcpy((*K).aesKey, buff, 32); 
                memcpy((*K).hmacKey, buff + 32, 32); 
                free(buff);
        }
        else
        {
		unsigned int md_len;
                unsigned char* keys = malloc(64);
                // get 512-bit authentication code of entropy with KDF_KEY
                HMAC_CTX* mctx = HMAC_CTX_new();
	        HMAC_Init_ex(mctx, &KDF_KEY, 32, EVP_sha512(), 0);
	        HMAC_Update(mctx, entropy, entLen); 	
		HMAC_Final(mctx, keys, &md_len); 
		HMAC_CTX_free(mctx);
		printf("%d \n", md_len);
                // half of keys array corresponds to HMAC key
                // the other half corresponds to AES key
                memcpy((*K).aesKey, keys, 32); 
                memcpy((*K).hmacKey, keys + 32, 32);
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
                IV = malloc(IV_LEN);
                randBytes(IV, IV_LEN);
        }
	
	// setup context ctx for encryption
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if(0 == EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, (*K).aesKey, IV))
	        ERR_print_errors_fp(stderr);
	// do the actual encryption
	int nWritten;
        unsigned char* ct = malloc(len);
	if(0 == EVP_EncryptUpdate(ctx, ct, &nWritten, inBuf, len))
		ERR_print_errors_fp(stderr);	

	// free up cipher context
        EVP_CIPHER_CTX_free(ctx); 

	// compute hmac of IV + ct
	unsigned char* iv_ct = malloc(IV_LEN + nWritten);
	memcpy(iv_ct, IV, IV_LEN);
	unsigned char* ct_start = iv_ct + IV_LEN;
	memcpy(ct_start, ct, nWritten);
        unsigned int md_len = 32;
        unsigned char* md = malloc(md_len);
	HMAC_CTX* mctx = HMAC_CTX_new();
	HMAC_Init_ex(mctx, (*K).hmacKey, 32, EVP_sha256(), 0);
	HMAC_Update(mctx, iv_ct, IV_LEN + nWritten);
	HMAC_Final(mctx, md, &md_len);
	HMAC_CTX_free(mctx);
	
        //assemble message for specified format
	unsigned char* iv_ct_hmac = malloc(IV_LEN + nWritten + HM_LEN);
        unsigned char* hmac_start = iv_ct_hmac + IV_LEN + nWritten;
	memcpy(iv_ct_hmac, iv_ct, IV_LEN + nWritten);
	memcpy(hmac_start, md, md_len);
        
	// copy to outBuf
	memcpy(outBuf, iv_ct_hmac, IV_LEN + nWritten + HM_LEN);

	// free up heap memory
	free(ct);
	free(iv_ct);
 	free(md);
        free(iv_ct_hmac);
//	printf("%d \n", md_len);
/*	unsigned char* tempBuf = malloc(AES_BLOCK_SIZE + len + HM_LEN);
       	unsigned char* tempMac = malloc(HM_LEN);
	HMAC(EVP_sha256(), (*K).hmacKey, HM_LEN, c, len, tempMac, NULL);

	memcpy(tempBuf, IV, AES_BLOCK_SIZE);
	memcpy(tempBuf + AES_BLOCK_SIZE, c, len);
	memcpy(tempBuf + AES_BLOCK_SIZE + len, tempMac, HM_LEN); 

        memcpy(outBuf, tempBuf, AES_BLOCK_SIZE + nWritten + HM_LEN);	

	free(c);
	free(tempBuf);
	free(tempMac);*/
	return (IV_LEN + nWritten + HM_LEN); //(AES_BLOCK_SIZE + nWritten + HM_LEN); /* TODO: should return number of bytes written, which
	      //       hopefully matches ske_getOutputLen(...). */
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
	// compute hmac of IV + ct
/*	unsigned char* iv_ct = malloc();
	memcpy(iv_ct, inBuf, len - HM_LEN);
	unsigned char* ct_start = iv_ct + IV_LEN;
	memcpy(ct_start, ct, nWritten);
        unsigned int md_len = 32;
        unsigned char* md = malloc(md_len);
	HMAC_CTX* mctx = HMAC_CTX_new();
	HMAC_Init_ex(mctx, (*K).hmacKey, 32, EVP_sha256(), 0);
	HMAC_Update(mctx, iv_ct, IV_LEN + nWritten);
	HMAC_Final(mctx, md, &md_len);
	HMAC_CTX_free(mctx);*/

	unsigned char* mac = malloc(HM_LEN);	
	HMAC(EVP_sha256(), (*K).hmacKey, 32, inBuf, len - HM_LEN, mac, NULL); 
	if(0 != memcmp(mac, inBuf + len - HM_LEN, HM_LEN))
		return -1;

	// extract IV 
	unsigned char* IV = malloc(IV_LEN);
	memcpy(IV, inBuf, IV_LEN);

	// setup ctx for decryption
	int nWritten;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();	
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, (*K).aesKey, IV))
		ERR_print_errors_fp(stderr);

	// do the actual decryption
	if(1 != EVP_DecryptUpdate(ctx, outBuf, &nWritten, inBuf + IV_LEN, len - IV_LEN - HM_LEN))
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

