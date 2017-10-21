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
	SHA256(x,HASHLEN,x_Hash_Buffer);

	// Generating SK
	SKE_KEY K;
	ske_keyGen(&K,x,HASHLEN);//  KDf to generate SKe
	unsigned char tempCT_SK[strlen(fnOut)];
	strcpy(tempCT_SK,fnOut);
	strcat(tempCT_SK, ".tmp");
	size_t CT_SK_length = ske_encrypt_file(tempCT_SK,fnIn,&K,NULL,0);

//	Combining RSA(x) and  H(x) into one file fnOut
File* Out = fopen(fnOut,"w+");
// writing headers in order to keep a track of the sizes
fwrite(&rsa_len,sizeof(size_t),1,Out);
fwrite(HASHLEN,sizeof(size_t),1,Out);
// writing actual files into fnOut
fwrite(rsa_out_buffer,1,HASHLEN,Out));
fwrite(x_Hash_Buffer,1,CT_SK_length,Out));
//

// adding cihpertext into fnOut

File* tempCT = fopen(tempCT_SK,"r");
size_t temp_1,temp_2;
unsigned char tem_buffer[8192];
do{
	 temp_1 = fread(tem_buffer,1,sizeof(tem_buffer),tempCT);
	 if (temp_1) {
		  temp_2 = fwrite(tem_buffer,1,temp_1,Out);
		}
	 else temp_2=0;
 }
 while((temp_1>0) && (temp_1==temp_2));
 fclose(Out); fclose(tempCT_SK); unlink(tempCT_SK);

}

/* TODO: encapsulate random symmetric key (SK) using RSA and SHA256;
	 * encrypt fnIn with SK; concatenate encapsulation and cihpertext;
	 * write to fnOut. */



	return 0;
}

/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	// reading back the headers
size_t CT_rsa_len, x_hash_len;
File* In = fopen(fnIn, "r");
fread(&CT_rsa_len,sizeof(size_t),1,In);
fread(&x_hash_len,sizeof(size_t),1,In);
// getting temporary storages
unsigned char* x_kdf = malloc (HASHLEN*sizeof(char));
unsigned char* CT_rsa = malloc (CT_rsa_len*sizeof(char));
unsigned char* x_gen_hash = malloc (HASHLEN*sizeof(char));
unsigned char* x_hash = malloc (HASHLEN*sizeof(char));

// reading inputs
fread(CT_rsa,1,sizeof(size_t),In);
fread(x_hash,1,sizeof(size_t),In);
// decrypting rsa(x)
size_t rsa_x = rsa_decrypt(x_kdf,CT_rsa,CT_rsa_len, K);
SHA256(x_kdf,HASHLEN,x_gen_hash);
// if sha(x) != x_hash(which is also sha(x))
if (x_gen_hash != x_kdf)
printf("Corupted Message, Can not decapsulate");


unsigned char tempCT_SK[strlen(fnOut)];
strcpy(tempCT_SK,fnOut);
strcat(tempCT_SK, ".tmp");

File* tempCT = fopen(tempCT_SK,"w+");
size_t temp_1,temp_2;
unsigned char tem_buffer[8192];
do{
	 temp_1 = fread(tem_buffer,1,sizeof(tem_buffer),In);
	 if (temp_1) {
		  temp_2 = fwrite(tem_buffer,1,temp_1,tempCT);
		}
	 else temp_2=0;
 }
 while((temp_1>0) && (temp_1==temp_2));
 fclose(In); fclose(tempCT);
SKE_KEY SK;
ske_keyGen(&SK,x_kdf,HASHLEN);
ske_decrypt_file(fnOut,tempCT_SK,&SK,0);

  unlink(tempCT_SK);
	return 0;

}





















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
	RSA_KEY K;
	void* InBuf;
	void* OutBuf;
	char* keyfile;



	/* TODO: finish this off.  Be sure to erase sensitive data
	 * like private keys when you're done with them (see the
	 * rsa_shredKey function). */
	switch (mode) {
		case ENC:
		keyfile = fopen(fnKey,"r");
		rsa_readPublic(keyfile,&K);
		fclose(keyfile);
		kem_encrypt(fnOut,fnIn,&K);
		break;

		case DEC:
		keyfile = fopen(fnKey,"r");
		rsa_readPrivate(keyfile,&K);
		fclose(keyfile);
		kem_decrypt(fnOut,fnIn,&K);
		case GEN:
		rsa_keyGen(nBits,&K);
		FILE* prFD = fopen(fnOut,"w+");
		unsigned char* pFnExit = ".pub";
		strcat(fnOut,pFnExit);
		FILE* puFD = fopen(fnOut,"w+");
		rsa_writePublic(puFD,&K);
		rsa_writePrivate(prFD,&K);
		fclose(puFD);
		fclose(prFD);
		break;

		default:
			return 1;
	}
rsa_shredKey(&K);
	return 0;
}
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
