#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int hex_to_bin(const char *hex, unsigned char *bin, size_t bin_size);

int main() {
    const char *hex_string = "3043a486eb13c28ad373f097e45486ddb078ed1ec12666a772ba5686e5a8ac8587ee2123f7150220ba041cb01cec872e88c6406a4a8a09bd96b55d1eafaeb170";
    size_t hex_len = strlen(hex_string);
    size_t bin_len = hex_len / 2;
    unsigned char bin[bin_len];

    // Convert hex string to binary data
    if (hex_to_bin(hex_string, bin, bin_len) != 0) {
        fprintf(stderr, "Invalid hex string\n");
        return EXIT_FAILURE;
    }

    // Write binary data to file
    FILE *outfile = fopen("ciphertext.bin", "wb");
    if (!outfile) {
        perror("Opening output file");
        return EXIT_FAILURE;
    }
    
    fwrite(bin, 1, bin_len, outfile);
    fclose(outfile);

    printf("File written successfully\n");
    return EXIT_SUCCESS;
}

int hex_to_bin(const char *hex, unsigned char *bin, size_t bin_size) {
    for (size_t i = 0; i < bin_size; i++) {
        if (sscanf(hex + 2 * i, "%2hhx", &bin[i]) != 1) {
            return -1;  // Invalid hex string
        }
    }
    return 0;
}
