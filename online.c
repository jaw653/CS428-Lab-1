/**
 * Author: Jacob Wachs
 * Institution: The University of Alabama
 * 16 September 2018
 */


#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

int encrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *);
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *);

int main (void) {
  	unsigned char *given_ciphertext = (unsigned char *) "8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9";
  	unsigned char *iv = (unsigned char *)"0000000000000000";

  	/* Message to be encrypted */
  	unsigned char *plaintext = (unsigned char *)"This is a top secret.";

  	/* Buffer for ciphertext. */
  	unsigned char ciphertext[128];
  	/* Buffer for the decrypted text */
  	unsigned char decryptedtext[128];

	int decryptedtext_len, ciphertext_len;

  	/*   Try each word in words.txt as the key, with 0's appended on the end up to 16 chars,
          if encrypted text matches given_ciphertext, stop, that key is the match!   */
	
	FILE *fp = fopen("words.txt", "r");
	
	unsigned char tmpKey[1024];
	fscanf(fp, "%s", tmpKey);

	while (!feof(fp)) {
		printf("Trying %s...\n", tmpKey);

		ciphertext_len = encrypt(plaintext, strlen( (char *)plaintext), tmpKey, iv, ciphertext);
		
		if (strcmp(ciphertext, given_ciphertext) == 0) {
			printf("Key found! It is: %s\n", tmpKey);
			return 0;
		}

		fscanf(fp, "%s", tmpKey);
	}
  	//printf("Encrypted text is: %s\n", ciphertext);

  	/* Decrypt the ciphertext *
  	decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
   		decryptedtext);

  	/* Add a NULL terminator. We are expecting printable text *
  	decryptedtext[decryptedtext_len] = '\0';

  	/* Show the decrypted text *
  	printf("Decrypted text is:\n");
  	printf("%s\n", decryptedtext); */
  	return 0;
}


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  	unsigned char *iv, unsigned char *ciphertext)
{
  	EVP_CIPHER_CTX *ctx;

  	int len;

  	int ciphertext_len;

  	/* Create and initialise the context */
  	ctx = EVP_CIPHER_CTX_new();
  	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
   	 * and IV size appropriate for your cipher
   	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   	 * IV size for *most* modes is the same as the block size. For AES this
   	 * is 128 bits */
  	EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);					//FIXME: change encryption algo to correct version
  	/* Provide the message to be encrypted, and obtain the encrypted output.
   	* EVP_EncryptUpdate can be called multiple times if necessary
   	*/
  	EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
  	ciphertext_len = len;

  	/* Finalise the encryption. Further ciphertext bytes may be written at
   	* this stage.
   	*/
  	EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
  	ciphertext_len += len;

  	/* Clean up */
  	EVP_CIPHER_CTX_free(ctx);

  	return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  	unsigned char *iv, unsigned char *plaintext)
{
  	EVP_CIPHER_CTX *ctx;

  	int len;

  	int plaintext_len;

  	/* Create and initialise the context */
  	ctx = EVP_CIPHER_CTX_new();

  	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
   	* and IV size appropriate for your cipher
   	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
   	* IV size for *most* modes is the same as the block size. For AES this
   	* is 128 bits */
  	EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

  	/* Provide the message to be decrypted, and obtain the plaintext output.
   	* EVP_DecryptUpdate can be called multiple times if necessary
   	*/
  	EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
  	plaintext_len = len;

  	/* Finalise the decryption. Further plaintext bytes may be written at
   	* this stage.
   	*/
  	EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
  	plaintext_len += len;

  	/* Clean up */
  	EVP_CIPHER_CTX_free(ctx);

  	return plaintext_len;
}
