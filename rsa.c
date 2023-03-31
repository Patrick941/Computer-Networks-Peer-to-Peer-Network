#include "rsa.h"

char Node_IPs[5][16] = {
    "10.35.70.7",
    "10.35.70.27",
    "10.35.70.37",
    "10.35.70.47",
    "10.35.70.57"
};

uint32_t Node_PubKeys[5][RSA_KEYLEN] = {
    {0x428a2f98,    0x71374491,    0xb5c0fbcf,    0xe9b5dba5,    0x3956c25b,    0x59f111f1,    0x923f82a4,    0xab1c5ed5},
    {0xd807aa98,    0x12835b01,    0x243185be,    0x550c7dc3,    0x72be5d74,    0x80deb1fe,    0x9bdc06a7,    0xc19bf174},
    {0xe49b69c1,    0xefbe4786,    0x0fc19dc6,    0x240ca1cc,    0x2de92c6f,    0x4a7484aa,    0x5cb0a9dc,    0x76f988da},
    {0x983e5152,    0xa831c66d,    0xb00327c8,    0xbf597fc7,    0xc6e00bf3,    0xd5a79147,    0x06ca6351,    0x14292967},
    {0x27b70a85,    0x2e1b2138,    0x4d2c6dfc,    0x53380d13,    0x650a7354,    0x766a0abb,    0x81c2c92e,    0x92722c85}
};

void rsaGetPubKey(char* IP, uint32_t publicKey[]) {
    for (int i = 0; i < NUM_NODES; i++) {
        if (strcmp(IP, Node_IPs[i]) == 0) {
            // If IP is found in the network list, find public Key
            for (int j = 0; j < 8; j++) {
                publicKey[j] = Node_PubKeys[i][j];
            }
        }
    }
}