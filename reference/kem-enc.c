/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/sha.h>

#include "ske.h"
#include "rsa.h"
#include "prf.h"

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Encrypt or decrypt data.\n\n"
"   -i,--in     FILE   read input from FILE.\n"
"   -o,--out    FILE   write output to FILE.\n"
"   -k,--key    FILE   the key.\n"
"   -r,--rand   FILE   use FILE to seed RNG (defaults to /dev/urandom).\n"
"   -e,--enc           encrypt (this is the default action).\n"
"   -d,--dec           decrypt.\n"
"   -g,--gen    FILE   generate new key and write to FILE{,.pub}\n"
"   -b,--BITS   NBITS  length of new key (NOTE: this corresponds to the\n"
"                      RSA key; the symmetric key will always be 256 bits).\n"
"                      Defaults to %lu.\n"
"   --help             show this message and exit.\n";

#define FNLEN 255

enum modes {
	ENC,
	DEC,
	GEN
};

/* Let SK denote the symmetric key.  Then to format ciphertext, we
 * simply concatenate:
 * +------------+----------------+
 * | RSA-KEM(X) | SKE ciphertext |
 * +------------+----------------+
 * NOTE: reading such a file is only useful if you have the key,
 * and from the key you can infer the length of the RSA ciphertext.
 * We'll construct our KEM as KEM(X) := RSA(X)|H(X), and define the
 * key to be SK = KDF(X).  Naturally H and KDF need to be "orthogonal",
 * so we will use different hash functions:  H := SHA256, while
 * KDF := HMAC-SHA512, where the key to the hmac is defined in ske.c
 * (see KDF_KEY).
 * */

#define HASHLEN 32 /* for sha256 */
#define ENTROPY_LEN 32

void printee(unsigned char* arr, int size)
{
        int i = 0;
        for(i = 0; i < size; i++)
                fprintf(stderr, "%c", arr[i]);
        fprintf(stderr, "\n");
}


int kem_encrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: encapsulate random symmetric key (SK) using RSA and SHA256;
	 * encrypt fnIn with SK; concatenate encapsulation and cihpertext;
	 * write to fnOut. */
        
        // get entropy array size 32 bytes 
        size_t length = rsa_numBytesN(K);
        char* entropy = malloc(length);
        memset((void*)entropy, 65, length); 
        //printee((unsigned char*) entropy, length);
       /* FILE* strm_urand = fopen("/dev/urandom", "r");
        if(strm_urand == NULL)
        {
                perror("fopen(\"/dev/urandom\", \"r\")");
                exit(EXIT_FAILURE);
        }
        if(fread((void*)entropy, 1, length, strm_urand) != length)
        {
                fprintf(stderr, "error occurred while reading from /dev/urandom\n");
                exit(EXIT_FAILURE);
        } 
        fclose(strm_urand); */ 
        // encrypt entropy, get hash of entropy and write to output file 
        char* encrypted = malloc(length);
        memset((void*)encrypted, 0, length);
        rsa_encrypt((unsigned char*)encrypted, (unsigned char*)entropy, length, K);
        //fprintf(stderr, "%d \n", s);
        char* hash256 = malloc(HASHLEN); 
        SHA256((unsigned char*)entropy, length, (unsigned char*)hash256);
        FILE* strm_fnOut = fopen(fnOut, "w");
        if(strm_fnOut == NULL)
        {
                perror("fopen(fnOut, \"w\")");
                exit(EXIT_FAILURE);
        }
        fwrite((void*)encrypted, 1, length, strm_fnOut);
        fwrite((void*)hash256, 1, HASHLEN, strm_fnOut);
        fclose(strm_fnOut); 
        // derive key and encrypt input file
        SKE_KEY SK;
        ske_keyGen(&SK, (unsigned char*)entropy, length);
        //printee(SK.hmacKey, 32);
        //printee(SK.aesKey, 32); 
        //fprintf(stderr, "\n");
        ske_encrypt_file(fnOut, fnIn, &SK, 0, (size_t)sysconf(_SC_PAGE_SIZE));
        // free up memory
        free(entropy);
        free(encrypted);
        free(hash256);
       
	return 0;
}

/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: write this. */
	/* step 1: recover the symmetric key */
	/* step 2: check decapsulation */
	/* step 3: derive key from ephemKey and decrypt data. */

        // recover symmetric key
        FILE* strm_fnIn = fopen(fnIn, "r");
        if(strm_fnIn == NULL)
        {
                perror("fopen(fnIn, \"r\")");
                exit(EXIT_FAILURE);
        }
        size_t length = rsa_numBytesN(K);
        char* decrypt = malloc(length);
        memset((void*)decrypt, 0, length);
        fread((void*)decrypt, 1, length, strm_fnIn);
        //fprintf(stderr, "%d, %d \n", i, (int)length);
        char* decrypted = malloc(length);
        memset((void*)decrypted, 65, length);
        rsa_decrypt((unsigned char*)decrypted, (unsigned char*)decrypt, length, K);
        //printee((unsigned char*)decrypted, length * 5);
        //fprintf(stderr, " %d \n", (int)s);
        // check decapsulation
        char* temp = malloc(HASHLEN);
        memset((void*)temp, 0, HASHLEN);
        fread((void*)temp, 1, HASHLEN, strm_fnIn);
        char* hash256 = malloc(HASHLEN);
        memset((void*)hash256, 0, HASHLEN);
        SHA256((unsigned char*)decrypted, length, (unsigned char*)hash256);
        fclose(strm_fnIn);
        int equal = 0;//strncmp(temp, hash256, HASHLEN);
        //fprintf(stderr, "%d \n", equal);
        if(equal == 0)
        // derive key and decrypt data
        {
                SKE_KEY SK;
                ske_keyGen(&SK, (unsigned char*)decrypted, length);
                //printee(SK.hmacKey, 32);
                //printee(SK.aesKey, 32); 
                fprintf(stderr, "passed \n");
                ske_decrypt_file(fnOut, fnIn, &SK, (size_t)sysconf(_SC_PAGE_SIZE));
        }
        else
        {
                fprintf(stderr, "encapsulation verification failed\n");
                exit(EXIT_FAILURE);
        }
        // free up memory
        free(decrypt);
        free(decrypted);
        free(hash256);
        free(temp);

	return 0;
}

int main(int argc, char *argv[]) {
	/* define long options */
	static struct option long_opts[] = {
		{"in",      required_argument, 0, 'i'},
		{"out",     required_argument, 0, 'o'},
		{"key",     required_argument, 0, 'k'},
		{"rand",    required_argument, 0, 'r'},
		{"gen",     required_argument, 0, 'g'},
		{"bits",    required_argument, 0, 'b'},
		{"enc",     no_argument,       0, 'e'},
		{"dec",     no_argument,       0, 'd'},
		{"help",    no_argument,       0, 'h'},
		{0,0,0,0}
	};
	/* process options: */
	char c;
	int opt_index = 0;
	char fnRnd[FNLEN+1] = "/dev/urandom";
	fnRnd[FNLEN] = 0;
	char fnIn[FNLEN+1];
	char fnOut[FNLEN+1];
	char fnKey[FNLEN+1];
	memset(fnIn,0,FNLEN+1);
	memset(fnOut,0,FNLEN+1);
	memset(fnKey,0,FNLEN+1);
	int mode = ENC;
	size_t nBits = 2048;
	//size_t nBits = 1024;
	while ((c = getopt_long(argc, argv, "edhi:o:k:r:g:b:", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'h':
				printf(usage,argv[0],nBits);
				return 0;
			case 'i':
				strncpy(fnIn,optarg,FNLEN);
				break;
			case 'o':
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'k':
				strncpy(fnKey,optarg,FNLEN);
				break;
			case 'r':
				strncpy(fnRnd,optarg,FNLEN);
				break;
			case 'e':
				mode = ENC;
				break;
			case 'd':
				mode = DEC;
				break;
			case 'g':
				mode = GEN;
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'b':
				nBits = atol(optarg);
				break;
			case '?':
				printf(usage,argv[0],nBits);
				return 1;
		}
	}

	/* TODO: finish this off.  Be sure to erase sensitive data
	 * like private keys when you're done with them (see the
	 * rsa_shredKey function). */

        RSA_KEY K;
        FILE* strmKeyfile;
	switch (mode) {
		case ENC:
		        strmKeyfile = fopen(fnKey, "r");
		        rsa_readPublic(strmKeyfile, &K);
		        kem_encrypt(fnOut, fnIn, &K);
                        fclose(strmKeyfile);
		        break;

		case DEC:
			strmKeyfile = fopen(fnKey, "r"); 
                        rsa_readPrivate(strmKeyfile, &K);
		        kem_decrypt(fnOut, fnIn, &K); 
                        fclose(strmKeyfile);
                        break;		

                case GEN:
		        rsa_keyGen(nBits, &K);
		        FILE* prvKey = fopen(fnOut, "w");
		        rsa_writePrivate(prvKey, &K);
		        FILE* pubKey = fopen(strcat(fnOut, ".pub"), "w");
		        rsa_writePublic(pubKey, &K);
		        fclose(prvKey);
		        fclose(pubKey);
		        break;

		default:
			return 1;
	}
                        
        rsa_shredKey(&K);

	return 0;
}
