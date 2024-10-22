#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

uint8_t hex_to_byte(unsigned char h1, unsigned char h2) {
    uint8_t x = 0;
    uint8_t y = 0;

    // Convert h1 to a decimal value
    if (h1 >= '0' && h1 <= '9') {
        x += h1 - '0';
    }
    else if (h1 >= 'a' && h1 <= 'f') {
        x += h1 - 'a' + 10;
    }

    // Convert h2 to a decimal value
    if (h2 >= '0' && h2 <= '9') {
        y += h2 - '0';
    }
    else if (h2 >= 'a' && h2 <= 'f') {
        y += h2 - 'a' + 10;
    }
    return x*16 + y;
}
int main(int argc, char **argv) {

    // UNIT TESTING SECTION
    int test = 0; // Set this variable to 1 to run unit tests instead of the entire program
    if (test) {
        assert(hex_to_byte('a', '2') == 162);
        // ADD MORE TESTS HERE. MAKE SURE TO ADD TESTS THAT FAIL AS WELL TO SEE WHAT HAPPENS!
        
        printf("ALL TESTS PASSED!\n");
        return 0;
    }

    // MAIN PROGRAM SECTION
    if (argc < 2) {
        printf("Error: not enough arguments provided!\n");
        printf("Usage: %s <byte 1 in hex> <byte 2 in hex> ...\n", argv[0]);
        printf("Example: %s a2 b7 99\n", argv[0]);
        return 1;
    }

    int i = 1;
    for (; i < argc; i++) {
        printf("Value of hex byte %s is %d\n", argv[i], hex_to_byte(argv[i][0], argv[i][1]));
    }
}

