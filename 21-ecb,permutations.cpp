#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define BLOCK_SIZE 16 // AES block size (128 bits)
#define SEGMENT_SIZE 8 // Segment size for CFB mode

// Padding function (1 followed by 0's)
void pad(unsigned char* input, int* len) {
    int padding_length = BLOCK_SIZE - (*len % BLOCK_SIZE);
    for (int i = 0; i < padding_length; i++) {
        input[*len + i] = (i == 0) ? 0x80 : 0x00; // Padding: 1 followed by 0s
    }
    *len += padding_length;
}

// ECB mode encryption
void encrypt_ecb(unsigned char* plaintext, int len, unsigned char* key, unsigned char* ciphertext) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);

    for (int i = 0; i < len; i += BLOCK_SIZE) {
        AES_ecb_encrypt(plaintext + i, ciphertext + i, &aes_key, AES_ENCRYPT);
    }
}

// CBC mode encryption
void encrypt_cbc(unsigned char* plaintext, int len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    
    unsigned char prev_block[BLOCK_SIZE];
    memcpy(prev_block, iv, BLOCK_SIZE);

    for (int i = 0; i < len; i += BLOCK_SIZE) {
        for (int j = 0; j < BLOCK_SIZE; j++) {
            plaintext[i + j] ^= prev_block[j]; // XOR with previous block (or IV for the first block)
        }
        AES_ecb_encrypt(plaintext + i, ciphertext + i, &aes_key, AES_ENCRYPT);
        memcpy(prev_block, ciphertext + i, BLOCK_SIZE); // Update prev_block with the current ciphertext block
    }
}

// CFB mode encryption
void encrypt_cfb(unsigned char* plaintext, int len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    
    unsigned char prev_block[BLOCK_SIZE];
    memcpy(prev_block, iv, BLOCK_SIZE);

    for (int i = 0; i < len; i += SEGMENT_SIZE) {
        unsigned char temp_block[BLOCK_SIZE];
        AES_ecb_encrypt(prev_block, temp_block, &aes_key, AES_ENCRYPT); // Encrypt IV or previous block

        for (int j = 0; j < SEGMENT_SIZE; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ temp_block[j]; // XOR segment with temp_block
        }

        // Shift the IV for the next segment
        memcpy(prev_block, ciphertext + i, SEGMENT_SIZE);
        memcpy(prev_block + SEGMENT_SIZE, prev_block + SEGMENT_SIZE, BLOCK_SIZE - SEGMENT_SIZE);
    }
}

int main() {
    unsigned char key[BLOCK_SIZE] = "1234567890abcdef"; // Example key (16 bytes)
    unsigned char iv[BLOCK_SIZE]; // Initialization vector
    RAND_bytes(iv, BLOCK_SIZE); // Randomly generate IV

    // Example plaintext (multiple of block size)
    unsigned char plaintext[] = "This is a test plaintext for ECB, CBC, and CFB.";
    int len = strlen((char*)plaintext);

    // Padding the plaintext
    pad(plaintext, &len);

    // Ciphertext buffers
    unsigned char ciphertext_ecb[len];
    unsigned char ciphertext_cbc[len];
    unsigned char ciphertext_cfb[len];

    // Encrypt in ECB mode
    encrypt_ecb(plaintext, len, key, ciphertext_ecb);

    // Encrypt in CBC mode
    encrypt_cbc(plaintext, len, key, iv, ciphertext_cbc);

    // Encrypt in CFB mode
    encrypt_cfb(plaintext, len, key, iv, ciphertext_cfb);

    // Output ciphertext for ECB, CBC, and CFB modes
    printf("ECB Ciphertext: ");
    for (int i = 0; i < len; i++) {
        printf("%02x ", ciphertext_ecb[i]);
    }
    printf("\n");

    printf("CBC Ciphertext: ");
    for (int i = 0; i < len; i++) {
        printf("%02x ", ciphertext_cbc[i]);
    }
    printf("\n");

    printf("CFB Ciphertext: ");
    for (int i = 0; i < len; i++) {
        printf("%02x ", ciphertext_cfb[i]);
    }
    printf("\n");

    return 0;
}
