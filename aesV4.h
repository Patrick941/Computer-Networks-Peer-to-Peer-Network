//------------------------------------------------------
//  AES Algorithm
//  V4 includes comments and code rearranged
//  This Code assumes the key passed is 128-bit
//  will only use first 128-bits of key if anything bigger is passed
//  Encryption follows the AES standards 128-bit blocks
//  10 rounds for 128-bit key
//  generates round keys as specified in https://www.crypto-textbook.com/download/Understanding-Cryptography-Chapter4.pdf
//------------------------------------------------------

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef AESV4_H
#define AESV4_H

#define BLOCK_WIDTH 4 // Block width (4 * 4 of 8-bit blocks)
#define BLOCK_HEIGHT 4 // Block Height (4 * 4 of 8-bit blocks)
#define BLOCK_LEN 16 // Total number of 8-bit Blocks (BLOCK_WIDTH * BLOCK_WIDTH)


//-------------------------------
//  REFERENCE TABLES FOR AES
//-------------------------------

// Substitution Boxs
extern unsigned char s_box[256];
extern unsigned char inv_s_box[256];

// Matrixs For Mixing Columns
extern unsigned char mixColMatrix[BLOCK_HEIGHT][BLOCK_WIDTH];
extern unsigned char inv_mixColMatrix[BLOCK_HEIGHT][BLOCK_WIDTH];

//-------------------------------
//  USEFUL FUNCTIONS
//-------------------------------

unsigned char gfMultiplication(unsigned char num1, unsigned char num2); // Galois Field (2^8) Multiplication

// Functions for Shifting Rows
// Algorithm for Rotating Arrays @ https://www.geeksforgeeks.org/program-for-array-rotation-continued-reversal-algorithm/
void reverseArray(char* array, int start, int end); // Reverse the Order of Array it is Passed
void leftRotate(char* array, int n, int size); // Rotate array N positions left
void rightRotate(char* array, int n, int size); // Rotate array N positions right

//-------------------------------
//  AES ENCRYPTION
//-------------------------------

// AES ENCRYPTION LAYERS
void addRoundKey(unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH], unsigned char roundKey[BLOCK_HEIGHT][BLOCK_WIDTH]); // XORs roundKey with current value in fourByFour (XOR = addition in Galois Field)
void byteSub(unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH]); // Substitute Bytes in fourByFour with corresponding byte from s_box
void shiftRows(unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH]); // Shift Rows in fourByFour, height of row = how many left it is shifted (row 0 is shifted 0 left and so on)
void mixColumns(unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH]); // Mix Columns by multiplying fourByFour by the mixColsMatrix, USES GALOIS FIELD (2^8) MULTIPLICATION

// AES ENCRYPTION 
void aesEncryptBlock(unsigned char* text, int len, unsigned char roundKeys[][BLOCK_HEIGHT][BLOCK_WIDTH], int numRoundKeys, unsigned char result[BLOCK_LEN]); // Encrypts 128-bit blocks aka 1 fourByFour
int aesEncrypt(unsigned char* text, int len, unsigned char* key, unsigned char **result); // Encrypt string text of length 'len' using key. Assumes key is 128-bit

//-------------------------------
//  AES DECRYPTION
//-------------------------------

// AES DECRYPTION LAYERS
void inv_addRoundKey(unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH], unsigned char roundKey[BLOCK_HEIGHT][BLOCK_WIDTH]); // XORs roundKey with current value in fourByFour (INVERSE DOESNT CHANGGE)
void inv_byteSub(unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH]); // Substitute Bytes in fourByFour with corresponding byte from inverse s_box
void inv_shiftRows(unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH]); // Shift Rows in fourByFour, height of row = how many positions right it gets shifted
void inv_mixColumns(unsigned char fourByFour[BLOCK_HEIGHT][BLOCK_WIDTH]); // Mix Columns by multiplying fourByFour by the inverse mixColsMatrix

// AES DECRYPTION
void aesDecryptBlock(unsigned char *text, unsigned char roundKeys[][BLOCK_HEIGHT][BLOCK_WIDTH], int numRoundKeys, unsigned char result[BLOCK_LEN]); // Decrpts 128-bit Blocks
int aesDecrypt(unsigned char *text, int numBlocks, unsigned char *key, unsigned char **result); // Decrypt string text of length 'len' using key. Assumes key is 128-bit

//-------------------------------
//  GENERATE KEY SCHEDULE
//-------------------------------

// Asumes key is 128-bits, DO NOT PUT LARGER KEY IN
void genKeySchedule(unsigned char *key, unsigned char roundKeys[11][BLOCK_HEIGHT][BLOCK_WIDTH]); // Generates the RoundKeys for AES layers


#endif