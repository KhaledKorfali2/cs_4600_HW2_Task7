#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char* argv[])
{
    /* Output error if user doesn't enter appropriate console arguments*/
    if (argc != 2) {
        printf("Usage: %s <dictionary file> \n", argv[0]);
        return 1;
    }


    /* Allow enough space in output buffer for additional block */
    unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen, templen;
    EVP_CIPHER_CTX* ctx;
    /* Bogus key and IV: we'd normally set these from
     * another source.
     */
    unsigned char plaintext[] = "This is a top secret.";
    unsigned char key[] = "1234567891234567";
    unsigned char iv[] = { 0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22, 0x11 };
    unsigned char ciphertext[] =
    { 0x76,0x4a,0xa2,0x6b,0x55,0xa4,0xda,0x65,0x4d,0xf6,0xb1,0x9e,0x4b,0xce,0x00,0xf4,
      0xed,0x05,0xe0,0x93,0x46,0xfb,0x0e,0x76,0x25,0x83,0xcb,0x7d,0xa2,0xac,0x93,0xa2 };


    /* Read dictionary file */
    FILE* dict_file = fopen(argv[1], "r");
    if (dict_file == NULL) {
        printf("Could not open dictionary file.\n");
        return 1;
    }


    /* While there are still words in dict_file
       continue to read in the first 16 chars
       of each line*/
    while (fgets(key, 16, dict_file) != NULL) {

        /* Remove trailing newline */
        key[strcspn(key, "\n")] = 0;

        /* Append # to key */
        strncat(key, "################", 16 - strlen(key));
        /*printf("keys: %s\n", key);*/

        /* Don't set key or IV right away; we want to check lengths */
        ctx = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, 1);
        OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
        OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);



        /* Now we can set key and IV */
        EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, 1);
        if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, plaintext, strlen(plaintext)))
        {
            /* Error */
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        if (!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &templen)) {
            /* Error */
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        /* Display Output */
        if (memcmp(ciphertext, outbuf, 32) == 0) {
            printf("plaintextlength: %d\t ciphertext length:%d\n", strlen(plaintext),
                outlen + templen);
            printf("Actual Ciphertext:    ");
            for (int i = 0;i < outlen + templen;i++) {
                printf("%x", ciphertext[i]);
            }
            printf("\n");
            printf("Potential Ciphertext: ");
            for (int i = 0;i < outlen + templen;i++) {
                printf("%x", outbuf[i]);
            }
            printf("\n");
            printf("ciphertext matched!\n");
            printf("Key: %s\n", key);

            /* Data Management */
            EVP_CIPHER_CTX_cleanup(ctx);
            /* Indicae Success */
            return 0;
        }
    }
    /* Indicate that key was not found */
    printf("Key Not Found! \n");

    /* Data Management */
    EVP_CIPHER_CTX_cleanup(ctx);

    /* Indicate Failure */
    return 1;

}
