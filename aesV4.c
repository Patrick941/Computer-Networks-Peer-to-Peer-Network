#include "aesV4.h"

//-------------------------------
//  REFERENCE TABLES FOR AES
//-------------------------------

// Substitution Box
unsigned char s_box[256] = {
    0x63,   0x7c,   0x77,   0x7b,   0xf2,   0x6b,   0x6f,   0xc5,   0x30,   0x01,   0x67,   0x2b,   0xfe,   0xd7,   0xab,   0x76,
    0xca,   0x82,   0xc9,   0x7d,   0xfa,   0x59,   0x47,   0xf0,   0xad,   0xd4,   0xa2,   0xaf,   0x9c,   0xa4,   0x72,   0xc0,
    0xb7,   0xfd,   0x93,   0x26,   0x36,   0x3f,   0xf7,   0xcc,   0x34,   0xa5,   0xe5,   0xf1,   0x71,   0xd8,   0x31,   0x15,
    0x04,   0xc7,   0x23,   0xc3,   0x18,   0x96,   0x05,   0x9a,   0x07,   0x12,   0x80,   0xe2,   0xeb,   0x27,   0xb2,   0x75,
    0x09,   0x83,   0x2c,   0x1a,   0x1b,   0x6e,   0x5a,   0xa0,   0x52,   0x3b,   0xd6,   0xb3,   0x29,   0xe3,   0x2f,   0x84,
    0x53,   0xd1,   0x00,   0xed,   0x20,   0xfc,   0xb1,   0x5b,   0x6a,   0xcb,   0xbe,   0x39,   0x4a,   0x4c,   0x58,   0xcf,
    0xd0,   0xef,   0xaa,   0xfb,   0x43,   0x4d,   0x33,   0x85,   0x45,   0xf9,   0x02,   0x7f,   0x50,   0x3c,   0x9f,   0xa8,
    0x51,   0xa3,   0x40,   0x8f,   0x92,   0x9d,   0x38,   0xf5,   0xbc,   0xb6,   0xda,   0x21,   0x10,   0xff,   0xf3,   0xd2,
    0xcd,   0x0c,   0x13,   0xec,   0x5f,   0x97,   0x44,   0x17,   0xc4,   0xa7,   0x7e,   0x3d,   0x64,   0x5d,   0x19,   0x73,
    0x60,   0x81,   0x4f,   0xdc,   0x22,   0x2a,   0x90,   0x88,   0x46,   0xee,   0xb8,   0x14,   0xde,   0x5e,   0x0b,   0xdb,
    0xe0,   0x32,   0x3a,   0x0a,   0x49,   0x06,   0x24,   0x5c,   0xc2,   0xd3,   0xac,   0x62,   0x91,   0x95,   0xe4,   0x79,
    0xe7,   0xc8,   0x37,   0x6d,   0x8d,   0xd5,   0x4e,   0xa9,   0x6c,   0x56,   0xf4,   0xea,   0x65,   0x7a,   0xae,   0x08,
    0xba,   0x78,   0x25,   0x2e,   0x1c,   0xa6,   0xb4,   0xc6,   0xe8,   0xdd,   0x74,   0x1f,   0x4b,   0xbd,   0x8b,   0x8a,
    0x70,   0x3e,   0xb5,   0x66,   0x48,   0x03,   0xf6,   0x0e,   0x61,   0x35,   0x57,   0xb9,   0x86,   0xc1,   0x1d,   0x9e,
    0xe1,   0xf8,   0x98,   0x11,   0x69,   0xd9,   0x8e,   0x94,   0x9b,   0x1e,   0x87,   0xe9,   0xce,   0x55,   0x28,   0xdf,
    0x8c,   0xa1,   0x89,   0x0d,   0xbf,   0xe6,   0x42,   0x68,   0x41,   0x99,   0x2d,   0x0f,   0xb0,   0x54,   0xbb,   0x16
};

// Inverse Substitution Box
unsigned char inv_s_box[256] = {
    0x52,   0x09,   0x6a,   0xd5,   0x30,   0x36,   0xa5,   0x38,   0xbf,   0x40,   0xa3,   0x9e,   0x81,   0xf3,   0xd7,   0xfb,
    0x7c,   0xe3,   0x39,   0x82,   0x9b,   0x2f,   0xff,   0x87,   0x34,   0x8e,   0x43,   0x44,   0xc4,   0xde,   0xe9,   0xcb,
    0x54,   0x7b,   0x94,   0x32,   0xa6,   0xc2,   0x23,   0x3d,   0xee,   0x4c,   0x95,   0x0b,   0x42,   0xfa,   0xc3,   0x4e,
    0x08,   0x2e,   0xa1,   0x66,   0x28,   0xd9,   0x24,   0xb2,   0x76,   0x5b,   0xa2,   0x49,   0x6d,   0x8b,   0xd1,   0x25,
    0x72,   0xf8,   0xf6,   0x64,   0x86,   0x68,   0x98,   0x16,   0xd4,   0xa4,   0x5c,   0xcc,   0x5d,   0x65,   0xb6,   0x92,
    0x6c,   0x70,   0x48,   0x50,   0xfd,   0xed,   0xb9,   0xda,   0x5e,   0x15,   0x46,   0x57,   0xa7,   0x8d,   0x9d,   0x84,
    0x90,   0xd8,   0xab,   0x00,   0x8c,   0xbc,   0xd3,   0x0a,   0xf7,   0xe4,   0x58,   0x05,   0xb8,   0xb3,   0x45,   0x06,
    0xd0,   0x2c,   0x1e,   0x8f,   0xca,   0x3f,   0x0f,   0x02,   0xc1,   0xaf,   0xbd,   0x03,   0x01,   0x13,   0x8a,   0x6b,
    0x3a,   0x91,   0x11,   0x41,   0x4f,   0x67,   0xdc,   0xea,   0x97,   0xf2,   0xcf,   0xce,   0xf0,   0xb4,   0xe6,   0x73,
    0x96,   0xac,   0x74,   0x22,   0xe7,   0xad,   0x35,   0x85,   0xe2,   0xf9,   0x37,   0xe8,   0x1c,   0x75,   0xdf,   0x6e,
    0x47,   0xf1,   0x1a,   0x71,   0x1d,   0x29,   0xc5,   0x89,   0x6f,   0xb7,   0x62,   0x0e,   0xaa,   0x18,   0xbe,   0x1b,
    0xfc,   0x56,   0x3e,   0x4b,   0xc6,   0xd2,   0x79,   0x20,   0x9a,   0xdb,   0xc0,   0xfe,   0x78,   0xcd,   0x5a,   0xf4,
    0x1f,   0xdd,   0xa8,   0x33,   0x88,   0x07,   0xc7,   0x31,   0xb1,   0x12,   0x10,   0x59,   0x27,   0x80,   0xec,   0x5f,
    0x60,   0x51,   0x7f,   0xa9,   0x19,   0xb5,   0x4a,   0x0d,   0x2d,   0xe5,   0x7a,   0x9f,   0x93,   0xc9,   0x9c,   0xef,
    0xa0,   0xe0,   0x3b,   0x4d,   0xae,   0x2a,   0xf5,   0xb0,   0xc8,   0xeb,   0xbb,   0x3c,   0x83,   0x53,   0x99,   0x61,
    0x17,   0x2b,   0x04,   0x7e,   0xba,   0x77,   0xd6,   0x26,   0xe1,   0x69,   0x14,   0x63,   0x55,   0x21,   0x0c,   0x7d
};

// Matrix For Mixing Columns
unsigned char mixColMatrix[BLOCK_HEIGHT][BLOCK_WIDTH] = {
    { 0x02, 0x03, 0x01, 0x01 },
    { 0x01, 0x02, 0x03, 0x01 },
    { 0x01, 0x01, 0x02, 0x03 },
    { 0x03, 0x01, 0x01, 0x02 }
};

// Matrix For Inverse Mixing Columns
unsigned char inv_mixColMatrix[BLOCK_HEIGHT][BLOCK_WIDTH] = {
    { 0x0E, 0x0B, 0x0D, 0x09 },
    { 0x09, 0x0E, 0x0B, 0x0D },
    { 0x0D, 0x09, 0x0E, 0x0B },
    { 0x0B, 0x0D, 0x09, 0x0E }
};


//-------------------------------
//  USEFUL FUNCTIONS
//-------------------------------


unsigned char gfMultiplication(unsigned char num1, unsigned char num2) {
    // GF = Galois Field 2^8
    unsigned char p = 0;

    for (int i = 0; i < 8; i++) {
        if (num2 & 0x01) { // If the least significant bit high, addition is needed as there is a '1' in the polynomial of g2
            p ^= num1; // XOR is equal to p += g1 in GF
        }

        int MSB = (num1 & 0x80); // if most significant bit high, msb = 1 else msb = 0
        num1 <<= 1; // rotate g1 left is equal to multiplying by x in the GF
        if (MSB) {
            // reduce
            num1 ^= 0x1B; // g1 -= 0001 1011 is equal to mod (x^8 + x^4 + x^3 + x + 1)
        }
        num2 >>= 1; // rotate g2 right is equal to dividing by x in GF
    }

    return p;
}

void reverseArray(char* array, int start, int end) {
    // Starting at either end swap the elements stored at array[start] and array[end]
    while (start < end) {
        char temp = array[start];
        array[start] = array[end];
        array[end] = temp;
        //move along the array, start increases and end decreases until they meet
        start++;
        end--;
    }
}

void leftRotate(char* array, int n, int size) {
    //using reverse array to rotate left
    reverseArray(array, 0, n - 1);
    reverseArray(array, n, size - 1);
    reverseArray(array, 0, size - 1);
}

void rightRotate(char* array, int n, int size) {
    // Rotating right using the complimentary left rotation
    leftRotate(array, size - n, size);
}


//-------------------------------
//  AES ENCRYPTION
//-------------------------------

// AES ENCRYPTION LAYERS

void addRoundKey(unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH], unsigned char roundKey[BLOCK_HEIGHT][BLOCK_WIDTH]) {
    // adding correspondiing bytes of the roundKey to the block
    // adding is XOR in GF 2^8

    for (int row = 0; row < BLOCK_HEIGHT; row++) {
        //traverse rows from left to right
        for (int col = 0; col < BLOCK_WIDTH; col++) {
            //traverse columns from left to right

            fourByFour[row][col] ^= roundKey[row][col]; // XOR each corresponding byte
        }
    }
}

void byteSub(unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH]) {
    // Substitute each byte stored in fourByFour using s_box
    // replace byte in fourByFour with the element stored in s_box at the index of the number previously stored in fourByFour
    // Before: fourByFour[0][0] = 0011 0101 (53)
    // After: fourByFour[0][0] = s_box[53]

    for (int row = 0; row < BLOCK_HEIGHT; row++) {
        //traverse rows from left to right
        for (int col = 0; col < BLOCK_WIDTH; col++) {
            //traverse columns from left to right

            fourByFour[row][col] = s_box[fourByFour[row][col]]; // Substiute byte
        }
    }
}

void shiftRows(unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH]) {
    //rotate every row according to its position/height
    // Row0 rotates 0 left, Row1 rotates 1 left.... Row3 rotates 3 left

    for (int row = 0; row < BLOCK_HEIGHT; row++) {
        leftRotate(fourByFour[row], row, BLOCK_HEIGHT);
    }
}

void mixColumns(unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH]) {
    //for matrix multiplication we cannot update fourByFour while working on it so result temporarily stored here
    unsigned char result[BLOCK_HEIGHT][BLOCK_WIDTH];

    // for multiplication in galois field use gfMultiplication function and addition is XOR in GF
    for (int row = 0; row < BLOCK_HEIGHT; row++) {
        for (int col = 0; col < BLOCK_WIDTH; col++) {
            result[row][col] = 0x00;

            // dot product of the row of mixColMatrix and the col of fourByFour
            for (int i = 0; i < 4; i++) {
                result[row][col] ^= gfMultiplication(mixColMatrix[row][i], fourByFour[i][col]);
            }
        }
    }

    // Copy output to fourByFour
    memcpy(fourByFour, result, BLOCK_LEN*sizeof(unsigned char));
}

// AES ENCRYPTION

void aesEncryptBlock(unsigned char* text, int len, unsigned char roundKeys[][BLOCK_HEIGHT][BLOCK_WIDTH], int numRoundKeys, unsigned char result[BLOCK_LEN]) {
    unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH];

    int i = 0;
    // AES Blocks are Column Major order hence fill down colums first then move across rows
    for (int col = 0; col < BLOCK_WIDTH; col++) {
        for (int row = 0; row < BLOCK_HEIGHT; row++) {
            if (i < len) {
                fourByFour[row][col] = text[i++]; //while there is still text copy over to fourByFour
            } else {
                fourByFour[row][col] = 0; //adds padding of 0 if text is not 128 bits
            }
            
        }
    }

    // ROUND 0
    addRoundKey(fourByFour, roundKeys[0]);

    // ROUND 1 -> numRoundKeys-1
    for (int i = 1; i < numRoundKeys; i++) {
        byteSub(fourByFour);
        shiftRows(fourByFour);
        mixColumns(fourByFour);
        addRoundKey(fourByFour, roundKeys[i]);
    }

    // Last ROUND
    // last round we dont mix Columnns because it achieves nothing
    byteSub(fourByFour);
    shiftRows(fourByFour);
    addRoundKey(fourByFour, roundKeys[numRoundKeys]);

    // Output the Encrypted text to result[]
    i = 0;
    for (int col = 0; col < BLOCK_WIDTH; col++) {
        for (int row = 0; row < BLOCK_HEIGHT; row++) {
            result[i++] = fourByFour[row][col];
        }
    }
}

int aesEncrypt(unsigned char* text, int len, unsigned char* key, unsigned char **result) {
    // assumnes keylen is 128bit hence the number of rounds is 10
    int numRoundKeys = 10;

    // 11 roundKeys, first round key is the key itself and round 0 simply adds this the following 10 rounds need a key
    unsigned char (*roundKeys)[BLOCK_HEIGHT][BLOCK_WIDTH] = malloc((numRoundKeys + 1) * sizeof(unsigned char[BLOCK_HEIGHT][BLOCK_WIDTH]));
    genKeySchedule(key, roundKeys); // Fill roundKeys with the roundKeys

    //divide input into blocks
    int numBlocks = len >> 4; // n / BLOCK_LEN
    int extra = len & 0x0f; // n % BLOCK_LEN checks if there is less than a block, hence will we need to padd a block

    int resultLen = numBlocks * BLOCK_LEN;
    if (extra) {
        //if there isnt a full block at the end padd
        *result = malloc((numBlocks+1) * BLOCK_LEN * sizeof(unsigned char)); //malloc number of blocks plus the last partial one
        resultLen += BLOCK_LEN; // add block_len if there is a need for an extra block to finish string


        aesEncryptBlock(text+(numBlocks << 4), extra, roundKeys, numRoundKeys, *result + (numBlocks << 4));
    } else {
        *result = malloc(numBlocks * BLOCK_LEN * sizeof(unsigned char));
    }

    for (int i = 0; i < numBlocks; i++) {
        aesEncryptBlock(text+(i << 4), BLOCK_LEN, roundKeys, numRoundKeys, *result+(i << 4));
    }

    free(roundKeys); // Free memory after encryption is complete

    return resultLen/BLOCK_LEN; // returns the number of blocks in the encryption
}


//-------------------------------
//  AES DECRYPTION
//-------------------------------

// AES DECRYPTION LAYERS

void inv_addRoundKey(unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH], unsigned char roundKey[BLOCK_HEIGHT][BLOCK_WIDTH]) {
    addRoundKey(fourByFour, roundKey);
}

void inv_byteSub(unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH]) {
    for (int row = 0; row < BLOCK_HEIGHT; row++) {
        for (int col = 0; col < BLOCK_WIDTH; col++) {
            fourByFour[row][col] = inv_s_box[fourByFour[row][col]];
        }
    }
}

void inv_shiftRows(unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH]) {
    for (int row = 0; row < BLOCK_HEIGHT; row++) {
        rightRotate(fourByFour[row], row, BLOCK_HEIGHT);
    }
}

void inv_mixColumns(unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH]) {
    unsigned char output[BLOCK_HEIGHT][BLOCK_WIDTH];

    for (int row = 0; row < BLOCK_HEIGHT; row++) {
        for (int col = 0; col < BLOCK_WIDTH; col++) {
            output[row][col] = 0x00;
            // dot product
            for (int i = 0; i < 4; i++) {
                output[row][col] ^= gfMultiplication(inv_mixColMatrix[row][i], fourByFour[i][col]);
            }
        }
    }

    memcpy(fourByFour, output, BLOCK_LEN*sizeof(unsigned char));
}

// AES DECRYPTION

void aesDecryptBlock(unsigned char *text, unsigned char roundKeys[][BLOCK_HEIGHT][BLOCK_WIDTH], int numRoundKeys, unsigned char result[BLOCK_LEN]) {
    unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH];

    //read encrypted text into fourByFour matrix, Column Major Order
    int i = 0;
    for (int col = 0; col < BLOCK_WIDTH; col++) {
        for (int row = 0; row < BLOCK_HEIGHT; row++) {
            fourByFour[row][col] = text[i];
            i++;
        }
    }

    // ROUNDS IN REVERSE FROM LAST ROUND -> ROUND 0

    // LAST ROUND
    inv_addRoundKey(fourByFour, roundKeys[numRoundKeys]);
    inv_shiftRows(fourByFour);
    inv_byteSub(fourByFour);

    // numRoundKeys - 1 --> 1
    for (i = numRoundKeys-1; i > 0; i--) {
        // Inverse of the AES Encryption Layers
        inv_addRoundKey(fourByFour, roundKeys[i]);
        inv_mixColumns(fourByFour);
        inv_shiftRows(fourByFour);
        inv_byteSub(fourByFour);
    }

    // ROUND 0
    inv_addRoundKey(fourByFour, roundKeys[0]);


    i = 0;
    for (int col = 0; col < BLOCK_WIDTH; col++) {
        for (int row = 0; row < BLOCK_HEIGHT; row++) {
            result[i++] = fourByFour[row][col];
        }
    }
}

int aesDecrypt(unsigned char *text, int numBlocks, unsigned char *key, unsigned char **result) {
    int numRoundKeys = 10;

    unsigned char (*roundKeys)[BLOCK_HEIGHT][BLOCK_WIDTH] = malloc((numRoundKeys+1) * sizeof(unsigned char[BLOCK_HEIGHT][BLOCK_WIDTH]));
    genKeySchedule(key, roundKeys);

    *result = malloc(numBlocks*BLOCK_LEN*sizeof(unsigned char));

    for (int i = 0; i < numBlocks; i++) {
        aesDecryptBlock(text +(i << 4), roundKeys, numRoundKeys, *result + (i << 4));
    }

    free(roundKeys);

    return numBlocks * BLOCK_LEN;
}

//-------------------------------
//  GENERATE KEY SCHEDULE
//-------------------------------

void genKeySchedule(unsigned char *key, unsigned char roundKeys[11][BLOCK_HEIGHT][BLOCK_WIDTH]) {
    // https://www.crypto-textbook.com/download/Understanding-Cryptography-Chapter4.pdf
    // Following AES key schedule for 128-bit key size

    //round 0 is original KEY
    int i = 0;
    // column by column first
    for (int col = 0; col < BLOCK_WIDTH; col++) {
        for (int row = 0; row < BLOCK_HEIGHT; row++) {
            roundKeys[0][row][col] = key[i++];
        }
    }

    //generate each round 
    unsigned char roundCoeff = 0x01;
    for (i = 1; i <= 10; i++) {
        //transform key, taken from ref link
        unsigned char g[4] = {
            s_box[roundKeys[i-1][1][3]] ^ roundCoeff,
            s_box[roundKeys[i-1][2][3]],
            s_box[roundKeys[i-1][3][3]],
            s_box[roundKeys[i-1][0][3]],
        };
        for (int row = 0; row < BLOCK_HEIGHT; row++) {
            roundKeys[i][row][0] = roundKeys[i-1][row][0] ^ g[row]; //i-1 is previous round key
        }
        for (int col = 1; col < BLOCK_WIDTH; col++) {
            for (int row = 0; row < BLOCK_HEIGHT; row++) {
                roundKeys[i][row][col] = roundKeys[i-1][row][col] ^ roundKeys[i][row][col-1];
            }
        }

        roundCoeff = gfMultiplication(roundCoeff, 0x02); //increase round coefficient by multiply coefficient by x (0000 0010)
    }
}