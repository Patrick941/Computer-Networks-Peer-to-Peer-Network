#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>

#ifndef HASH_H
#define HASH_H

// SHA-256 NIST Documentation
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf


extern uint32_t K[64]; // Pre-defined in NIST FIPS 180-4

//-------------------------------
//  SHA - 256 Functions
//-------------------------------

uint32_t bitRotateRight(uint32_t x, int n); // Rotate X right by n number of bits
uint32_t sigma0(uint32_t x); // Defined as: (RIGHT ROTATE 7) XOR (RIGHT ROTATE 18) XOR (SHIFT RIGHT 3)
uint32_t sigma1(uint32_t x); // Defined as: (RIGHT ROTATE 17) XOR (RIGHT ROTATE 19) XOR (SHIFT RIGHT 10)
uint32_t capSigma0(uint32_t x); // Defined as: (RIGHT ROTATE 2) XOR (RIGHT ROTATE 13) XOR (RIGHT ROTATE 22)
uint32_t capSigma1(uint32_t x); // Defined as: (RIGHT ROTATE 6) XOR (RIGHT ROTATE 11) XOR (RIGHT ROTATE 25)
uint32_t choose(uint32_t x, uint32_t y, uint32_t z); // Choose depending on X's bits (Explained more in hash.c)
uint32_t majority(uint32_t x, uint32_t y, uint32_t z); // Output the most common bits (the majority bits)

char* sha256(char* inputString); // Input data wished to be hashed as a string, outputs the hash as an array of characters

void sha256Main(char* inputString, uint32_t state[], char* outputHash); // Called in sha256, where all real hashing is done
void sha256Update(uint32_t state[], uint32_t block[]); // Updates current state with a 512bit block



#endif