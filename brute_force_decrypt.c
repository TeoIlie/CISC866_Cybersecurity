#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>

void print_as_hex(unsigned char word[]) {
    // Print the word as hex bytes
    printf("Hex Bytes: ");
    for (size_t i = 0; i < 16; i++) {
        printf("0x%02x ", word[i]);
    }

    printf("\n\n");
}

/*
This function takes input file and encrypts/decrypts to an output file.
1. do_encrypt == 1 -> encryption
2. do_encrypt == 0 -> decryption
*/
int do_crypt(FILE *in, FILE *out, int do_encrypt)
{
    /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;
    /*
     * Bogus key and IV: we'd normally set these from
     * another source.
     */
    unsigned char key[] = "0123456789abcdeF";
    unsigned char iv[] = "1234567887654321";

    /* Don't set key or IV right away; we want to check lengths */
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL,
                      do_encrypt);
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
    // Open the file "words.txt" for reading
    FILE *file = fopen("words.txt", "r");
    
    // Check if the file opened successfully
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    // Buffer to hold the word read from the file
    char read_word[101];  // Allowing up to 100 characters for reading

    // Buffer to hold the word stored as unsigned char and padded
    unsigned char word[17]; // 16 characters + 1 for the null terminator

    // Read each word from the file until end-of-file is reached
    while (fgets(read_word, sizeof(read_word), file) != NULL) {
        // fgets() includes the newline, so remove it
        size_t len = strlen(read_word);
        if (len > 0 && read_word[len - 1] == '\n') {
            read_word[len - 1] = '\0';
            len--;
        }

        // If the word is 15 characters or less, proceed
        if (len <= 15) {
            // Copy the word to 'word' array as unsigned char
            strcpy((char *)word, read_word);

            // Pad with '#' characters if the word is shorter than 16 characters
            for (size_t i = len; i < 16; i++) {
                word[i] = '#';
            }
            word[16] = '\0';  // Null-terminate the string

            // Print the resulting padded word
            printf("Word: %s\n", word);
            print_as_hex(word);

            // decrypt the cyphertext using word as the key

        }
    }

    // Close the file
    fclose(file);

    return 0;
}