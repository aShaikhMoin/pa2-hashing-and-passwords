#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>

uint8_t hex_to_byte(unsigned char h1, unsigned char h2){
    uint8_t x = 0;
    uint8_t y = 0;

    if (h1 >= '0' && h1 <= '9'){
        x = h1 - '0';
    } else if (h1 >= 'a' && h1 <= 'f'){
        x = h1 - 'a' + 10;
    } else if (h1 >= 'A' && h1 <= 'F'){
        x = h1 - 'A' + 10;
    }

    if (h2 >= '0' && h2 <= '9'){
        y = h2 - '0';
    } else if (h2 >= 'a' && h2 <= 'f'){
        y = h2 - 'a' + 10;
    } else if (h2 >= 'A' && h2 <= 'F'){
        y = h2 - 'A' + 10;
    }

    return (x * 16) + y;
}

void hexstr_to_hash(char hexstr[], unsigned char hash[32]){
    for (int i = 0; i < 32; i++){
        hash[i] = hex_to_byte(hexstr[2 * i], hexstr[2 * i + 1]);
    }
}

void print_hash(const unsigned char hash[32], const char *label){
    printf("%s: ", label);
    for (int i = 0; i < 32; i++){
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int8_t check_password(char password[], unsigned char given_hash[32]){
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)password, strlen(password), hash);

    for (int i = 0; i < 32; i++){
        if (hash[i] != given_hash[i]){
            return 0;
        }
    }
    return 1;
}

int8_t crack_password(char password[], unsigned char given_hash[32]){
    if (check_password(password, given_hash)){
        return 1;
    }

    int len = strlen(password);
    for (int i = 0; i < len; i++){
        char original_char = password[i];

        if (original_char >= 'a' && original_char <= 'z'){
            password[i] = original_char - 32;
            if (check_password(password, given_hash)){
                return 1;
            }
        } else if (original_char >= 'A' && original_char <= 'Z'){
            password[i] = original_char + 32;
            if (check_password(password, given_hash)){
                return 1;
            }
        }
        password[i] = original_char;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2){
        printf("Error: Not enough arguments provided\n");
        printf("Usage: %s <64-character SHA256 hash>\n", argv[0]);
        return 1;
    }

    if (strlen(argv[1]) != 64) {
        printf("Error: Invalid hash length, use a 64-character SHA256 hash\n");
        return 1;
    }

    unsigned char given_hash[32];
    hexstr_to_hash(argv[1], given_hash);

    char password[128];
    while (fgets(password, sizeof(password), stdin)){
        password[strcspn(password, "\n")] = 0;
        if (crack_password(password, given_hash)){
            printf("Found password: SHA256(%s) = %s\n", password, argv[1]);
            return 0;
        }
    }

    printf("Did not find a matching password\n");
    return 0;
}

