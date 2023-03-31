#include "hash.h"

uint32_t K[64] = {
    0x428a2f98,    0x71374491,    0xb5c0fbcf,    0xe9b5dba5,    0x3956c25b,    0x59f111f1,    0x923f82a4,    0xab1c5ed5,
	0xd807aa98,    0x12835b01,    0x243185be,    0x550c7dc3,    0x72be5d74,    0x80deb1fe,    0x9bdc06a7,    0xc19bf174,
	0xe49b69c1,    0xefbe4786,    0x0fc19dc6,    0x240ca1cc,    0x2de92c6f,    0x4a7484aa,    0x5cb0a9dc,    0x76f988da,
	0x983e5152,    0xa831c66d,    0xb00327c8,    0xbf597fc7,    0xc6e00bf3,    0xd5a79147,    0x06ca6351,    0x14292967,
	0x27b70a85,    0x2e1b2138,    0x4d2c6dfc,    0x53380d13,    0x650a7354,    0x766a0abb,    0x81c2c92e,    0x92722c85,
	0xa2bfe8a1,    0xa81a664b,    0xc24b8b70,    0xc76c51a3,    0xd192e819,    0xd6990624,    0xf40e3585,    0x106aa070,
	0x19a4c116,    0x1e376c08,    0x2748774c,    0x34b0bcb5,    0x391c0cb3,    0x4ed8aa4a,    0x5b9cca4f,    0x682e6ff3,
	0x748f82ee,    0x78a5636f,    0x84c87814,    0x8cc70208,    0x90befffa,    0xa4506ceb,    0xbef9a3f7,    0xc67178f2
};

uint32_t bitRotateRight(uint32_t x, int n) {
    //Rotate X right by n bits
    return (x >> n) | (x << (32-(n)));
}

uint32_t sigma0(uint32_t x) {
    // Defined as: (RIGHT ROTATE 7) XOR (RIGHT ROTATE 18) XOR (SHIFT RIGHT 3)
    return (bitRotateRight(x, 7) ^ bitRotateRight(x, 18) ^ (x >> 3));
}

uint32_t sigma1(uint32_t x) {
    // Defined as: (RIGHT ROTATE 17) XOR (RIGHT ROTATE 19) XOR (SHIFT RIGHT 10)
    return (bitRotateRight(x, 17) ^ bitRotateRight(x, 19) ^ (x >> 10));
}

uint32_t capSigma0(uint32_t x) {
    // Defined as: (RIGHT ROTATE 2) XOR (RIGHT ROTATE 13) XOR (RIGHT ROTATE 22)
    return (bitRotateRight(x, 2) ^ bitRotateRight(x, 13) ^ bitRotateRight(x, 22));
}

uint32_t capSigma1(uint32_t x) {
    // Defined as: (RIGHT ROTATE 6) XOR (RIGHT ROTATE 11) XOR (RIGHT ROTATE 25)
    return (bitRotateRight(x, 6) ^ bitRotateRight(x, 11) ^ bitRotateRight(x, 25));
}

uint32_t choose(uint32_t x, uint32_t y, uint32_t z) {
    // Output is dependent on the value stored in X
    // If bit0 in X is a 0 then bit0 of the output will be the stored value in bit0 of Z
    // If bit0 in X is a 1 then bit0 of the output will be the stored value in bit0 of Y
    // For Example: (O = output, sample also is 8bit istead of 32) 
    // X: 00110011
    // Y: 00001111
    // Z: 11110000
    // O: 11000011

    return ((x & y) ^ (~x & z));
}

uint32_t majority(uint32_t x, uint32_t y, uint32_t z) {
    // Output is dependent on all thre input values
    // Output is given by getting a bitwise majority
    // if more than one input is 1 then output will be 1 if more than 1 input is 0 then output will be 0
    // For Example: (O = output, sample also is 8bit istead of 32) 
    // X: 00110011
    // Y: 00001111
    // Z: 11110000
    // O: 00110011

    return ((x & y) | (x & z) | (y & z));
}

char* sha256(char* inputString) {
    char* hashString = malloc(65); //Allocate 65 because last bit is null terminater
    strcpy(hashString, ""); // Initilise hash as nothing

    // Initilise the states Defined in NIST FIPS 180-4
    uint32_t sha256_state[8] = {
        0x6a09e667,
        0xbb67ae85,
	    0x3c6ef372,
	    0xa54ff53a,
	    0x510e527f,
	    0x9b05688c,
	    0x1f83d9ab,
	    0x5be0cd19
    };

    sha256Main(inputString, sha256_state, hashString);

    return hashString;

}

void sha256Main(char* inputString, uint32_t state[], char* outputHash) {
    // Split input string into 512bit blocks
    // Once a 512 block is created it will be processed
    // Once processed the next block will be created and processed and so on

    // Splitting
    uint64_t stringLen = strlen(inputString);
    uint64_t bitLen = stringLen * 8;
    uint64_t blockLen = 0;
    uint32_t sha_block[16]; // store temp block here

    // Calculate how many blocks will be needed
    if ((stringLen % 64) > 55) {
        blockLen = (stringLen / 64) + 2; // if there isnt 64bits free at end of last block we will need an extra one to padd properly
    } else {
        blockLen = (stringLen / 64) + 1; // Else if there is space for the bitLen at the end no need for extra block
    }

    // For every 512bit Block needed
    int index = 0; // Holds the current position in inputString[]
    for (int i = 0; i < blockLen; i++) {

        // For Every block other than the final one
        if ((i+1) != blockLen) {
            for (size_t j = 0; j < 16; j++) {
                uint32_t val = 0;
                for (size_t k = 0; k < 4; k++) {
                    if (index >= stringLen) { // If true end of inputString[] has been reached
                        if (index == stringLen) { // Begin the padding with a leading 1, hence the first byte of padding is 0x80 (1000 0000)
                            val |= 0x80 << (8*(3-k));
                        }
                    } else {
                        val |= (uint32_t)inputString[index] << (8*(3-k)); // Each 32bit holds 4 bytes hence bit shift to fill (0x33221100)
                    }
                    index++; // add one to index every character input
                }
                sha_block[j] = val; // Save current val to coresponding index in sha_block[]
            }

            // Print 512bit Block in 16 words (32bit number)
            /*
            printf("Block %d: ", i);
            for (int w = 0; w < 16; w++) {
                printf("%08x ", sha_block[w]);
            }
            printf("\n");
            */

            // Here we need to update state[] with next 512 bit block
            sha256Update(state, sha_block);

        } 
        
        // For the final block, one with padding and bitlen, also must return the final hash
        else {
            for (size_t j = 0; j < 16; j++) {
                uint32_t val = 0;
                for (size_t k = 0; k < 4; k++) {
                    if (index >= stringLen) { // If true end of inputString[] has been reached
                        if (index == stringLen) { // Begin the padding with a leading 1, hence the first byte of padding is 0x80 (1000 0000)
                            val |= 0x80 << (8*(3-k));
                        }
                        if (j == 14) { // If second last word then input most significant bits of bitLen
                            val = (uint32_t)(bitLen >> 32);
                        } else if (j == 15) { // If last word then input the least significant bits of bitLen
                            val = (uint32_t)bitLen;
                        }
                    } else {
                        val |= (uint32_t)inputString[index] << (8*(3-k)); // Each 32bit holds 4 bytes hence bit shift to fill (0x33221100)
                    }
                    index++; // add one to index every character input
                }
                sha_block[j] = val; // Save current val to coresponding index in sha_block[]
            }

            // Print 512bit Block in 16 words (32bit number)
            /*
            printf("Block %d: ", i);
            for (int w = 0; w < 16; w++) {
                printf("%08x ", sha_block[w]);
            }
            printf("\n");
            */

            // Here we need to update state[] with last 512 bit block and return hash

            sha256Update(state, sha_block);

            /*
            printf("Hash: ");
            for (int w = 0; w < 8; w++) {
                printf("%08x ", state[w]);
            }
            printf("\n");
            */

            for (int w = 0; w < 8; w++) {
                sprintf(&outputHash[w*8], "%08" PRIx32, state[w]);
            }
        }


    }
}

void sha256Update(uint32_t state[], uint32_t block[]) {
    uint32_t w[64];

    // Generate Message Schedule
    // The first 16 words of the message schedule are the exact same as in the 512bit block
    for (int i = 0; i < 16; i++) {
        w[i] = block[i];
    }
    // The next 48 words are generated using the formula W(t) = sigma1(t-2) + (t-7) + sigma0(t-15) + (t-16)
    for (int i = 16; i < 64; i++) {
        w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
    }
    //printf("W16: %08x\n", w[16]);

    // Initilise A-H with state[]
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    // For every word in message schedule
    for (int i = 0; i < 64; i++) {
        // T1 defined as T1 = capSigma1(E) + choose(E, F, G) + H + K[i] + W[i]
        uint32_t T1 = capSigma1(e) + choose(e, f, g) + h + K[i] + w[i];
        // T2 defined as T2 = capSigma0(A) + majority(A, B, C)
        uint32_t T2 = capSigma0(a) + majority(a, b, c);
        //printf("ITERATION %d:  T1=%08x,  T2=%08x\n", i, T1, T2);

        // Shift all words down, hence b = a, c = b.... each word equal to the previous word
        // A = T1 + T2 and E = D + T1
        // must decend as e is reliant on d's past value
        h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
    }


    // Add state[] with A-H to get update
    state[0] = state[0] + a;
    state[1] = state[1] + b;
    state[2] = state[2] + c;
    state[3] = state[3] + d;
    state[4] = state[4] + e;
    state[5] = state[5] + f;
    state[6] = state[6] + g;
    state[7] = state[7] + h;
}