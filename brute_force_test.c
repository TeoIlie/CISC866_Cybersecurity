#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>

int do_crypt(FILE *in, FILE *out, int do_encrypt, unsigned char *key, unsigned char *iv)
{
    /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;

    /* Don't set key or IV right away; we want to check lengths */
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, do_encrypt);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

    /* Now we can set key and IV */
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    for (;;) {
        inlen = fread(inbuf, 1, 1024, in);
        if (inlen <= 0)
            break;
        if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            /* Error */
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(outbuf, 1, outlen, out);
    }
    if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int main() {
    FILE *infile, *outfile;
    unsigned char key[EVP_MAX_KEY_LENGTH] = {0};
    unsigned char iv[EVP_MAX_IV_LENGTH] = {0};


    // Convert key and IV from hex to byte arrays
    const char *hex_key = "6578616d706c65232323232323232323";
    const char *hex_iv =  "aabbccddeeff00998877665544332211";

    for (int i = 0; i < 16; i++) {
        sscanf(&hex_key[i*2], "%2hhx", &key[i]);
        sscanf(&hex_iv[i*2], "%2hhx", &iv[i]);
    }

    // Open the input (encrypted) file
    infile = fopen("ciphertext.bin", "rb");
    if (!infile) {
        perror("Opening input file");
        return EXIT_FAILURE;
    }

    // Open the output (decrypted) file
    outfile = fopen("test_result.txt", "wb");
    if (!outfile) {
        perror("Opening output file");
        fclose(infile);
        return EXIT_FAILURE;
    }

    // Decrypt the file (key and IV passed in)
    if (!do_crypt(infile, outfile, 0, key, iv)) {  // 0 for decryption
        fprintf(stderr, "Decryption failed\n");
        fclose(infile);
        fclose(outfile);
        return EXIT_FAILURE;
    }

    // Clean up
    fclose(infile);
    fclose(outfile);

    printf("Decryption successful. Output saved to test_result.txt\n");
    return EXIT_SUCCESS;

}