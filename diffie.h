#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <gmp.h>

#ifndef DIFFIE_H
#define DIFFIE_H


#define RAND() (rand() & 0x7fff)  // Ensure only 15-bits
#define KEY_SIZE 256 // Private Key Size

//-------------------------------
//  Diffie Hellman Functions
//-------------------------------

// Initilise Diffie Hellman Variables, Using Agreed Prime and Generator (Group 15 - 3072-bit MODP Group)
void diffieInit(mpz_t prime, mpz_t generator, mpz_t privKey, mpz_t myPubKey, mpz_t recievedPubKey, mpz_t secretKey);

// Diffie Hellman Key Exchange Calculations
void genPrivKey(mpz_t privKey);
void calcPubKey(mpz_t privKey, mpz_t generator, mpz_t prime, mpz_t pubKey);
void calcSecretKey(mpz_t privKey, mpz_t recievedPubKey, mpz_t prime, mpz_t secretKey);

#endif