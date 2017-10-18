/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <stdlib.h>
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

int kem_encrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	// generating 32 byte random number for the KDF argument
	unsigned char* x=malloc(HASHLEN);
	int randomData= open("/dev/urandom",O_RDONLY);
 	if(read(rabdomData,x,HASHLEN)!=HASHLEN)
	printf("Error Occured");
	close(randomData);

	size_t rsa_size = mpz_size(K->n)*sizeof(mp_limb_size);
	unsigned char* rsa_out_buffer=malloc(rsa_size*sizeof(char));
        size_t rsa_len = rsa_encrypt(rsa_out_buffer,x,HASHLEN,K);
	unsigned char* x_Hash_Buffer = malloc(HASHLEN);
	SHA256(rsa_out_buffer,sizeof(x),x_Hash_Buffer);
	
	struct st ms;
	int filed =open(fnOut, O_RDWR);
	if(filed == -1 ){
		 ERR_print_errors_fp(stderr);
		 exit(1);
	}
	if(fstat(filed, &ms)<0){
		ERR_print_errors_fp("st");
		close(fd);
		exit(1);
	}
	size_t len = ms.st_size;

	// Generating SK
	SKE_KEY K;
	ske_keyGen(&K,x,HASHLEN);//  KDf to generate SKe
	unsigned char tempFn[len];
	strcpy(tempFn,fnOut);
	strcat(tempFn, ".tmp");
	size_t CT_SK_length = ske_encrypt_file(tempFn,fnIn,&K,NULL,0);

//	Combining RSA(x) and  H(x) into one file out  
File* out = fopen(fnOut,"w+");
if (fwrite(&rsa_len,sizeof(size_t),1,out)!=1);
perror("out write");
if (fwrite(&CT_SK_length,sizeof(size_t),1,out)!=1);
perror("out write");
if (rsa_len!=fwrite(rsa_out_buffer,1,rsa_len,out));
perror("out write");
if (CT_SK_length!=fwrite(tempFn,1,CT_SK_length,out));
perror("out write");
//

// Copy out into fnOut

File* convert =
















	/* TODO: encapsulate random symmetric key (SK) using RSA and SHA256;
	 * encrypt fnIn with SK; concatenate encapsulation and cihpertext;
	 * write to fnOut. */

	//Size of the file

	// FIle *file=fopen(fnin,"r");
	// fseek(file,0,SEEK_END);
	// size_t len=ftell(file);

/*	struct st ms;
	int filed =open(fnIn, O_RDWR);
	if(filed == -1 ){
		 ERR_print_errors_fp(stderr);
		 exit(1);
	}
	if(fstat(filed, &ms)<0){
		ERR_print_errors_fp("st");
		close(fd);
		exit(1);
	}
	size_t len = ms.st_size;

	//encapsulate random symmetric key (SK) using RSA and SHA256;
	unsigned char* x = malloc(len);
	SKE_KEY SK;
	ske_keyGen(&SK,x,len);
	HMAC(EVP_sha256(), &SK, HASHLEN, fnIn, len, x, NULL);

	//encrypt fnIn with SK
	ske_encrypt_file(fnOut, fnIn, &SK, NULL, len);

*/
	//concatenate encapsulation and cihpertext;



	//write to fnOut.


	return 0;
}

/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: write this. */
	/* step 1: recover the symmetric key */
	/* step 2: check decapsulation */
	/* step 3: derive key from ephemKey and decrypt data. */
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
	// size_t nBits = 2048;
	size_t nBits = 1024;
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
	switch (mode) {
		case ENC:
		case DEC:
		case GEN:
		default:
			return 1;
	}

	return 0;
}
