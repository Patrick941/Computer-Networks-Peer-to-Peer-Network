#include "diffie.h"

//-------------------------------
//  Diffie Hellman Functions
//-------------------------------

void diffieInit(mpz_t prime, mpz_t generator, mpz_t privKey, mpz_t myPubKey, mpz_t recievedPubKey, mpz_t secretKey) {
    // Initialise mpz_t variables to be used in later calculations
    mpz_inits(prime, generator, privKey, myPubKey, recievedPubKey, secretKey, NULL); //list of mpz_t, NULL terminated

    // Set prime and generator values
    mpz_set_str(prime, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16);
    mpz_set_str(generator, "2", 10);

    //seed random
    srand(time(NULL));
}

void genPrivKey(mpz_t privKey) {
    long long unsigned temp;
    char temp_hex[17]; // 16 bytes plus null terminate
    char num_hex[(KEY_SIZE/4) + 1]; // Add one to null terminate string

    for (int i = 0; i < (KEY_SIZE/64); i++) {
        // Using rand to generate 256-bit private key, this is not ideal
        // In an ideal world we would code our own psuedo random function or use one from library like OpenSSL
        temp = ((uint64_t)RAND()<<48) ^ ((uint64_t)RAND()<<35) ^ ((uint64_t)RAND()<<22) ^ ((uint64_t)RAND()<< 9) ^ ((uint64_t)RAND()>> 4);
        sprintf(temp_hex, "%016llX", temp);

        if (i == 0) {
            strcpy(num_hex, temp_hex);
        } else {
            strcat(num_hex, temp_hex);
        }

    }

    //printf("Private Key: %s\n", num_hex);
    mpz_set_str(privKey, num_hex, 16); // update privKey = num_hex
}

void calcPubKey(mpz_t privKey, mpz_t generator, mpz_t prime, mpz_t pubKey) {
    // Calculate the public key to be sent
    // Using GNU Multiple Precision Arithmetic Library to compute pubKey = generator^privKey mod prime
    mpz_powm(pubKey, generator, privKey, prime);
}


void calcSecretKey(mpz_t privKey, mpz_t recievedPubKey, mpz_t prime, mpz_t secretKey) {
    // Calculate the secret key using our private key and the public key that was recieved
    // Using GNU Multiple Precision Arithmetic Library to compute secretKey = recievedPubKey^privKey mod prime
    mpz_powm(secretKey, recievedPubKey, privKey, prime);
}