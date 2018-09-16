/**
 * Author: Jacob Wachs
 * Institution: The University of Alabama
 * Date: 16 September 2018
 * Task 2
 */
#include <stdio.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


int brute_force(char *);

int main(void) {
	char plaintext[] = "This is a top secret.";
	char ciphertext[] = "8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9";

	int STATUS = brute_force("test1.txt");
printf("flag0\n");
	return 0;
}

int brute_force(char *outfile) {
        unsigned char outbuf[1024];
        int outlen, tmplen;
        /* Bogus key and IV: we'd normally set these from
         * another source.
         */
        unsigned char key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};	//FIXME: change this to iterate through words.txt
        unsigned char iv[] = {1,2,3,4,5,6,7,8};							//FIXME: change this to be all zero's
        char intext[] = "Some Crypto Text";
        EVP_CIPHER_CTX ctx;
        FILE *out;

        EVP_CIPHER_CTX_init(&ctx);
        EVP_DecryptInit_ex(&ctx, EVP_idea_cbc(), NULL, key, iv);


        if(!EVP_DecryptUpdate(&ctx, outbuf, &outlen, intext, strlen(intext))) {
                /* Error */
                return 0;
        }


        /* Buffer passed to EVP_DecryptFinal() must be after data just
         * encrypted to avoid overwriting it.
         */
        if(!EVP_DecryptFinal_ex(&ctx, outbuf + outlen, &tmplen)) {
                /* Error */
                return 0;
        }


        outlen += tmplen;
        EVP_CIPHER_CTX_cleanup(&ctx);


        /* Need binary mode for fopen because encrypted data is
         * binary data. Also cannot use strlen() on it because
         * it wont be null terminated and may contain embedded
         * nulls.
         */
        out = fopen(outfile, "wb");
        fwrite(outbuf, 1, outlen, out);
        fclose(out);
        return 1;
}
