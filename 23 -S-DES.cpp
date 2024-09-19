#include <stdio.h>
#include <stdint.h>

// Function prototypes
uint8_t sdes_encrypt(uint8_t plaintext, uint8_t key);
uint8_t sdes_decrypt(uint8_t ciphertext, uint8_t key);
uint8_t key_generation(uint16_t key10, int round);
uint8_t fk(uint8_t half, uint8_t subkey);
uint8_t permute(uint8_t input, int *perm, int size);
uint8_t sbox(uint8_t input, int sbox[4][4]);

// Define constants for S-DES key schedule and encryption
int IP[] = {1, 5, 2, 0, 3, 7, 4, 6}; // Initial Permutation
int IP_inv[] = {3, 0, 2, 4, 6, 1, 7, 5}; // Inverse of IP
int P4[] = {1, 3, 2, 0}; // Permutation P4
int EP[] = {3, 0, 1, 2, 1, 2, 3, 0}; // Expansion permutation for fK

int S0[4][4] = { {1, 0, 3, 2}, {3, 2, 1, 0}, {0, 2, 1, 3}, {3, 1, 3, 2} };
int S1[4][4] = { {0, 1, 2, 3}, {2, 0, 1, 3}, {3, 0, 1, 0}, {2, 1, 0, 3} };

// Helper function to print 8-bit binary
void print_binary(uint8_t num) {
    for (int i = 7; i >= 0; i--) {
        printf("%d", (num >> i) & 1);
    }
}

// Permutation function
uint8_t permute(uint8_t input, int *perm, int size) {
    uint8_t result = 0;
    for (int i = 0; i < size; i++) {
        result |= ((input >> (7 - perm[i])) & 1) << (size - 1 - i);
    }
    return result;
}

// S-box lookup function
uint8_t sbox(uint8_t input, int sbox[4][4]) {
    int row = ((input >> 3) & 0x2) | (input & 0x1);
    int col = (input >> 1) & 0x3;
    return sbox[row][col];
}

// Function fk: Applies round function using subkey
uint8_t fk(uint8_t half, uint8_t subkey) {
    uint8_t ep_half = permute(half, EP, 8); // Expansion permutation
    ep_half ^= subkey; // XOR with subkey
    
    // Split to two 4-bit halves for S-boxes
    uint8_t left = ep_half >> 4;
    uint8_t right = ep_half & 0x0F;
    
    // Apply S-boxes
    uint8_t sbox_output = (sbox(left, S0) << 2) | sbox(right, S1);
    
    // Apply P4 permutation
    return permute(sbox_output, P4, 4);
}

// Key generation: Generate subkey for round 1 and round 2 from 10-bit key
uint8_t key_generation(uint16_t key10, int round) {
    // Shift the 10-bit key and return the required subkey (for simplicity)
    return (round == 1) ? (key10 >> 2) & 0xFF : (key10 >> 4) & 0xFF;
}

// S-DES encryption function
uint8_t sdes_encrypt(uint8_t plaintext, uint8_t key) {
    uint8_t k1 = key_generation(key, 1);
    uint8_t k2 = key_generation(key, 2);
    
    // Initial Permutation
    uint8_t ip = permute(plaintext, IP, 8);
    
    // Split to left and right halves
    uint8_t left = ip >> 4;
    uint8_t right = ip & 0x0F;
    
    // Round 1
    uint8_t round1_output = left ^ fk(right, k1);
    
    // Round 2 (Swap and apply fk again)
    uint8_t round2_output = round1_output ^ fk(left, k2);
    
    // Concatenate and apply inverse IP
    uint8_t ciphertext = permute((right << 4) | round2_output, IP_inv, 8);
    
    return ciphertext;
}

// S-DES decryption function (similar to encryption but with reverse subkeys)
uint8_t sdes_decrypt(uint8_t ciphertext, uint8_t key) {
    uint8_t k1 = key_generation(key, 1);
    uint8_t k2 = key_generation(key, 2);
    
    // Initial Permutation
    uint8_t ip = permute(ciphertext, IP, 8);
    
    // Split to left and right halves
    uint8_t left = ip >> 4;
    uint8_t right = ip & 0x0F;
    
    // Round 1 (reverse round 2 of encryption)
    uint8_t round1_output = left ^ fk(right, k2);
    
    // Round 2 (Swap and apply fk with k1)
    uint8_t round2_output = round1_output ^ fk(left, k1);
    
    // Concatenate and apply inverse IP
    uint8_t plaintext = permute((right << 4) | round2_output, IP_inv, 8);
    
    return plaintext;
}

// Main function: Encrypt/Decrypt in Counter Mode
int main() {
    // Test data (S-DES with counter starting at 0000 0000)
    uint8_t key = 0b0111111101; // 10-bit binary key
    uint8_t counter = 0b00000000; // Start counter at 0000 0000
    uint8_t plaintext[] = {0b00000001, 0b00000010, 0b00000100}; // Binary plaintext blocks
    uint8_t expected_ciphertext[] = {0b00111000, 0b01001111, 0b00110010}; // Expected ciphertext
    
    // Encrypt plaintext using S-DES in Counter Mode
    printf("Encrypting in Counter Mode:\n");
    for (int i = 0; i < 3; i++) {
        uint8_t encrypted_counter = sdes_encrypt(counter, key); // Encrypt the counter
        uint8_t ciphertext = plaintext[i] ^ encrypted_counter; // XOR with plaintext
        
        printf("Plaintext block %d: ", i + 1);
        print_binary(plaintext[i]);
        printf(" -> Ciphertext: ");
        print_binary(ciphertext);
        printf("\n");
        
        counter++; // Increment counter for next block
    }
    
    return 0;
}
