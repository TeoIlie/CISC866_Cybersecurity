#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>

/*
This function prints the contents of a file; used for testing
*/
void print_file(char name[100], char read_type[3]) {
    FILE *file = fopen(name, read_type);
    if (!file) {
        perror("Error opening file for printing.");
        return;
    }

    int ch;

    while ((ch = fgetc(file)) != EOF) {
        putchar(ch); // Print each character to stdout
    }

    printf("\n");

    // Close the file
    fclose(file);
}

/*
This function prints an unsigned char word as hex; used for testing
*/
void print_as_hex(unsigned char word[]) {
    printf("Hex Bytes: ");
    for (size_t i = 0; i < 16; i++) {
        printf("0x%02x ", word[i]);
    }

    printf("\n\n");
}

/*
This function can be used for encryption/decryption, based on the value of do_encrypt:
1. do_encrypt == 1 -> encryption
2. do_encrypt == 0 -> decryption

I am using it only for decryption for the scope of this problem. The input file "in"
is the contents of "ciphertext.bin", which stores the ciphertext. The output file
is "result.txt" which is the plain text. IV is hardcoded, and the key is read from
a file "words.txt" 
*/
int do_crypt(FILE *out, unsigned char *key, unsigned char *iv)
{
    // hard-code do_encrypt a 0 for decryption
    int do_encrypt = 0;

    // in holds the encrypted text in "ciphertext.bin"
    FILE *in = fopen("ciphertext.bin", "rb");
    if (!in) {
        perror("Error opening ciphertext file");
        return EXIT_FAILURE;
    }

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

    fclose(in);
}

/*
This program currently takes a hardcoded iv, keys from "words.txt"
and opens an encrypted file "ciphertext.bin", and outputs the result
to a decrypted file "test_result.txt".
*/
int main() {
    // IV is hardcoded, translated from hex_iv to iv
    unsigned char iv[17];
    const char *hex_iv =  "aabbccddeeff00998877665544332211";

    for (int i = 0; i < 16; i++) {
        sscanf(&hex_iv[i*2], "%2hhx", &iv[i]);
    }

    // outfile holds the decrypted text in "result.txt"
    // words holds the list of words we try as the key
    FILE *outfile, *words;

    outfile = fopen("result.txt", "wb");
    if (!outfile) {
        perror("Error opening output file");
        return EXIT_FAILURE;
    }

    words = fopen("words.txt", "r");
    if (!words) {
        perror("Error opening words file");
        return EXIT_FAILURE;
    }

    // buffer for word read
    char read_word[101];  

    // unsigned char to store word and pass to decryption function
    unsigned char word[17]; // 16 chars + 1 null terminator

    // read each word from the file until end-of-file is reached, trying encryption
    // using each word as the key
    while (fgets(read_word, sizeof(read_word), words) != NULL) {

        // fgets() takes the newline; i remove it
        size_t len = strlen(read_word);
        if (len > 0 && read_word[len - 1] == '\n') {
            read_word[len - 1] = '\0';
            len--;
        }

        // only use words of lenght <= 15
        if (len <= 15) {
            // copy read word to unsigned char array
            strcpy((char *)word, read_word);

            // pad words with hashtag (#)
            for (size_t i = len; i < 16; i++) {
                word[i] = '#';
            }
            // add null terminator
            word[16] = '\0'; 

            // Print the resulting padded word
            printf("Word: %s\n", word);
            print_as_hex(word);

            //Print other parameters
            printf("IV:\n");
            print_as_hex(iv);

            // decrypt the cyphertext using word as the key
            if (!do_crypt(outfile, word, iv)) {
                fprintf(stderr, "Decryption failed\n\n\n");
            } else {
                printf("Decryption succeeded!\n\n\n");
            }
        }
    }

    // Close files
    fclose(outfile);
    fclose(words);
    return EXIT_SUCCESS;

}