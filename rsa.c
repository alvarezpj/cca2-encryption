#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rsa.h"
#include "prf.h"

/* NOTE: a random composite surviving 10 Miller-Rabin tests is extremely
 * unlikely.  See Pomerance et al.:
 * http://www.ams.org/mcom/1993-61-203/S0025-5718-1993-1189518-9/
 * */
#define ISPRIME(x) mpz_probab_prime_p(x,10)
#define NEWZ(x) mpz_t x; mpz_init(x)
#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf)
#define Z2BYTES(buf,len,x) mpz_export(buf,&len,-1,1,0,0,x)

/* utility function for read/write mpz_t with streams: */
int zToFile(FILE* f, mpz_t x)
{
	size_t i,len = mpz_size(x)*sizeof(mp_limb_t);
	unsigned char* buf = malloc(len);
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b = (len >> 8*i) % 256;
		fwrite(&b,1,1,f);
	}
	Z2BYTES(buf,len,x);
	fwrite(buf,1,len,f);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}

int zFromFile(FILE* f, mpz_t x)
{
	size_t i,len=0;
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b;
		/* XXX error check this; return meaningful value. */
		fread(&b,1,1,f);
		len += (b << 8*i);
	}
	unsigned char* buf = malloc(len);
	fread(buf,1,len,f);
	BYTES2Z(x,buf,len);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}

int rsa_keyGen(size_t keyBits, RSA_KEY* K)
{
	rsa_initKey(K);
	/* TODO: write this.  Use the prf to get random byte strings of
	 * the right length, and then test for primality (see the ISPRIME
	 * macro above).  Once you've found the primes, set up the other
	 * pieces of the key ({en,de}crypting exponents, and n=pq). */
        mpz_t phi, temp1, temp2;
        mpz_inits(phi, temp1, temp2, NULL);	
        size_t factorBytes = keyBits / 16;		
        unsigned char* buf = malloc(factorBytes);

        // generate p 
        randBytes(buf, factorBytes);
        BYTES2Z(temp1, buf, factorBytes);	
	if(ISPRIME(temp1) != 2)
	        mpz_nextprime(temp1, temp1);
	mpz_set((*K).p, temp1);
	
	// generate q
	randBytes(buf, factorBytes);
        BYTES2Z(temp2, buf, factorBytes);	
	if(ISPRIME(temp2) != 2)
	        mpz_nextprime(temp2, temp2);
	mpz_set((*K).q, temp2);

	// compute n
	mpz_mul((*K).n, temp1, temp2);

	// generate e
        mpz_sub_ui(temp1, temp1, 1);
        mpz_sub_ui(temp2, temp2, 1);
        mpz_mul(phi, temp1, temp2);
        mpz_set_ui(temp1, 1);
        do
	{
	        mpz_add_ui(temp1, temp1, 1);
                mpz_gcd(temp2, phi, temp1);
	} while(mpz_cmp_ui(temp2, 1) != 0);		
	mpz_set((*K).e, temp1);

	// compute d
	mpz_invert((*K).d, temp1, phi);

	free(buf);
        mpz_clears(phi, temp1, temp2, NULL);	

	return 0;
}

size_t rsa_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	/* TODO: write this.  Use BYTES2Z to get integers, and then
	 * Z2BYTES to write the output buffer. */
        size_t bw;
	mpz_t ct, pt;
	mpz_inits(ct, pt, NULL);
        BYTES2Z(pt, inBuf, len);
	mpz_powm(ct, pt, (*K).e, (*K).n);
	Z2BYTES(outBuf, bw, ct);
	mpz_clears(ct, pt, NULL);
	return bw; /* TODO: return should be # bytes written */
}

size_t rsa_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	/* TODO: write this.  See remarks above. */
	size_t bw;
	mpz_t ct, pt; 
	mpz_inits(ct, pt, NULL);
	BYTES2Z(ct, inBuf, len);
	mpz_powm(pt, ct, (*K).d, (*K).n);
	Z2BYTES(outBuf, bw, pt);
	mpz_clears(ct, pt, NULL);
	return bw;
}

size_t rsa_numBytesN(RSA_KEY* K)
{
	return mpz_size(K->n) * sizeof(mp_limb_t);
}

int rsa_initKey(RSA_KEY* K)
{
	mpz_init(K->d); mpz_set_ui(K->d,0);
	mpz_init(K->e); mpz_set_ui(K->e,0);
	mpz_init(K->p); mpz_set_ui(K->p,0);
	mpz_init(K->q); mpz_set_ui(K->q,0);
	mpz_init(K->n); mpz_set_ui(K->n,0);
	return 0;
}

int rsa_writePublic(FILE* f, RSA_KEY* K)
{
	/* only write n,e */ 
	mpz_out_raw(f, (*K).n);
	mpz_out_raw(f, (*K).e);
	return 0;
}

int rsa_writePrivate(FILE* f, RSA_KEY* K)
{
	mpz_out_raw(f, (*K).n);
	mpz_out_raw(f, (*K).e);
	mpz_out_raw(f, (*K).p);
	mpz_out_raw(f, (*K).q);
	mpz_out_raw(f, (*K).d);
	return 0;
}

int rsa_readPublic(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K); /* will set all unused members to 0 */
	mpz_inp_raw((*K).n, f);
	mpz_inp_raw((*K).e, f);
	return 0;
}

int rsa_readPrivate(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K);
	mpz_inp_raw((*K).n, f);
	mpz_inp_raw((*K).e, f);
	mpz_inp_raw((*K).p, f);
	mpz_inp_raw((*K).q, f);
	mpz_inp_raw((*K).d, f);
	return 0;
}

int rsa_shredKey(RSA_KEY* K)
{
	/* clear memory for key. */
	mpz_t* L[5] = {&K->d,&K->e,&K->n,&K->p,&K->q};
	size_t i;
	for (i = 0; i < 5; i++) {
		size_t nLimbs = mpz_size(*L[i]);
		if (nLimbs) {
			memset(mpz_limbs_write(*L[i],nLimbs),0,nLimbs*sizeof(mp_limb_t));
			mpz_clear(*L[i]);
		}
	}
	/* NOTE: a quick look at the gmp source reveals that the return of
	 * mpz_limbs_write is only different than the existing limbs when
	 * the number requested is larger than the allocation (which is
	 * of course larger than mpz_size(X)) */
	return 0;
}
