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

    unsigned char buffer[1024];  // Buffer to hold chunks of data
    size_t bytes_read;

    // Read the file in chunks and print
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        for (size_t i = 0; i < bytes_read; i++) {
            printf("%02x", buffer[i]);  // Print byte in hex format
        }
    }

    printf("\n");
}

/*
This function prints an unsigned char word as hex; used for testing
*/
void print_as_hex(unsigned char word[]) {
    // Print the word as hex bytes
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
int do_crypt(FILE *out, int do_encrypt, unsigned char *key, unsigned char *iv)
{
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
This program currently takes a hardcoded key and iv, opens an encrypted file
"ciphertext.bin", and outputs the result to a decrypted file "test_result.txt".

It has been tested and is working correctly.

The next step is to read the key from a file "words.txt", iterating line by line
of the file and attempting decryption.
*/
int main() {
    // IV is hardcoded, translated from hex_iv to iv
    unsigned char iv[17];
    const char *hex_iv =  "aabbccddeeff00998877665544332211";

    for (int i = 0; i < 16; i++) {
        sscanf(&hex_iv[i*2], "%2hhx", &iv[i]);
    }

    // outfile holds the decrypted text in "result.txt"
    // file holds the list of words we try as the key
    FILE *outfile, *words;

    // Open the output (decrypted) file, check for errors
    outfile = fopen("result.txt", "wb");
    if (!outfile) {
        perror("Error opening output file");
        return EXIT_FAILURE;
    }

    // Open words (keys) file and check for errors
    words = fopen("words.txt", "r");
    if (!words) {
        perror("Error opening words file");
        return EXIT_FAILURE;
    }

    // Buffer to hold the word read from the file
    char read_word[101];  // Allowing up to 100 characters for reading

    // Buffer to hold the word stored as unsigned char and padded
    unsigned char word[17]; // 16 characters + 1 for the null terminator

    // Read each word from the file until end-of-file is reached, trying encryption
    // using each word as the key
    while (fgets(read_word, sizeof(read_word), words) != NULL) {

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

            //the key is not the issue! it is failing when the correct key
            //is not the first one passed

            //Print other parameters
            printf("IV:\n");
            print_as_hex(iv);
            printf("infile:\n");
            print_file("ciphertext.bin", "rb");
            printf("outfile:\n");
            print_file("result.txt", "wb");

            // decrypt the cyphertext using word as the key
            if (!do_crypt(outfile, 0, word, iv)) {  // 0 for decryption
                fprintf(stderr, "Decryption failed\n\n");
            } else {
                printf("Decryption succeeded!\n\n");
            }
        }
    }

    // Close files
    fclose(outfile);
    fclose(words);
    return EXIT_SUCCESS;

}