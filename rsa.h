#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifndef RSA_H
#define RSA_H

#define NUM_NODES 5 // Number of Nodes in the network
#define RSA_KEYLEN 256/32 // Number should be in multiples of 32bits

// 5 is number of Nodes, 16 is length of IP, possibly could just store the last 3 digits of ip for less storage/lookup time
extern char Node_IPs[NUM_NODES][16];
extern uint32_t Node_PubKeys[NUM_NODES][RSA_KEYLEN];

//-------------------------------
//  Digital Signature Functions
//-------------------------------

void rsaGetPubKey(char* IP, uint32_t publicKey[]); // Input an ip, publicKey[] will return null if user isnt in the network, or a key if they are
int verifySig(char* IP, char* rawMsg, char* signature); // Pass IP of sender, RAW message, and signature of sender, Will return 1 if match 0 if false.

void rsaEncrypt(char* inputMsg, char* privKey, char* encryptedMsg); // inputMsg should be 256bit hash, priv key and output will be in encrypted msg
void rsaDecrypt(char* encryptedMsg, char* pubKey, char* decrypedMsg); // input msg to decrypt, public key and output will be in decrypted msg


#endif