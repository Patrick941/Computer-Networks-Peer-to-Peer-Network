#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include "diffie.c"
#include "diffie.h"
#include "aesV4.h"
#include "aesV4.c"
//#include "hash.h"
//#include "hash.c"
#include "rsa.h"
#include "rsa.c"

#define PORT 3333
#define messageSize 4096

char* rsaPrivKey = "83687677931c16a51794628acc0c73178e282635f670ae1257d7d67cafcb5a2651b8aa600e09fdbf10402ec02fcef915c6cc950ee113ab3c13c1456faf77601d5ceeeb3f4ad01d9e41a3d4943fb2ff89b9f02ab7793b3204c1026597f90da63bfd51e87c70d998d492ce00dbde5dceebd0c9c7acfd3fda89242b9c4633b28ed2b5159592572d27171998569e87f1c9e6fecf89bb306addbedd2e0c9f19bef74c78141d2c14848bdb1ab71b0bf969a26735ad93d45493f852d31a2bea8e57f07d3782006cc497de0f37cb8f363ad5e8cb55f2d7ed263321effba9fb43d2acd4801bc9aa15798b6be0b44bd86880dd5a3f871e6c644307d02e4b60da746f287db6e14a1e5988d9212e2c2d626618b4e7ea5fe5c4232238aafac314cf6ad9524f279c3622e3f0bcc52da3215af939f9b503507249f81473299a5ef03a83a853a111bbc4ce0b28852733d208f9b857028f61cf05e6ad461e003feb84d208c2b7f8a155a87f297deb5ffc9e0467647bfcf3147974e1a3a28f47d3613cd1c5300909adbc5c33c35bd3cee114ad227deafde4d0b3927eb53d0fba86fffaac10045c4f8b9c9e6248422935017906c4933a7a1df005297786ca61ffda82508c242671b6b570831ed8b66062e349dba8684f7a70d0b48c487019a82cba59dd983db98b87d9b59909c719c72dee1677808e24a98eabb242418aac3291a5a3d16991080c159";
char* rsaPubKey = "bc1b51e0c075f8589b0d5073f07ef25f913d72b652bca1361eddda9e164f88d75d7aee87c14bcdd68e19bfd25d51ab9510d0e0fafc2f1af7830bec1f2398aff5dfb73886d04e54587fe712eab402f8704998920176f7057396f0bb93e54db98b3bdb8217253eee7e6112c4e3f9e74240b17100cdcc597c978665eff09c9d17daf03a4d3831b1fcd06fa65b53a8b4af9a539053e3a10b392672883b85fb75c25dc47f5c7546c10344e5b1560b3dde6a751f3bc40be0fac12916e458153749706732ce73d6fc5a2c786e5396bb40690d8597cbc8f4cfda339b009bfa266cd3c85b91cf8dbf6a3d5ec012800496496d92d2ccb2643a42dd5de95447004ad8d04d9b72316ef8f67abed88f336cb323f94a2042bbe6fb1290fe8d3c38ae16b037d47755f37962e2e5294d1f33cfe7ce58b2b6bd95868493550cb5dba4029312fcc381a026baf74746b1817c327817f4e6c49fa8c6ad7dbc33a18b5a7af1a471c605cf0f2a804c7b8ef7eb248f79b3d00e5922ebfaac2829167b2326ed5c990d50d51d18f6b67db1bc487650fb89a37daafd54c4f1dd9b420958587ece9ceb006eb2bb82ba06f9df64fe0911784dd1422441749939a26071180d00851e64d5d4b375264970560e673d0d52e7a9408e555304bdce1eb5a7894b40bd72f98684538d78c7426ce3c51bda35f0219d73ee74aebb5f31fef355ea7e23b2b355331158b621b";

char ip[16];
int firstMessage = 1;

int currentSequence = 1;
int calculatedACK = -1;
char calculatedACKStr[30];
char secretKeyStr[17];
int recentACK = -1;

pthread_mutex_t lock;

void getIPandPort();

void * sending();

void * receiving();

// Type declaration for socket structs
typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr sockaddr;

// Decleration of variables
    pthread_t sendingThread;
    pthread_t receivingThread;
    int sock = 0, breakCondition = 0;
    sockaddr_in serv_addr, peer_addr;
    char message[messageSize];
    char buffer[4096] = {0}; // 4096 to allow 2 keys (1000*2ish) 1 signature (1000ish)
    char ack[20];
    mpz_t prime, generator, privKey, myPubKey, recievedPubKey, secretKey;
// Run with:
// gcc peerToPeer.c -pthread -lgmp
// ./a.out

int main(int argc, char const *argv[]) {

    // Can be hardcoded to make testing faster
    // strcpy(message, "Hello World\n");
    // strcpy(ip, "192.168.1.39");

    diffieInit(prime, generator, privKey, myPubKey, recievedPubKey, secretKey);
    genPrivKey(privKey);
    calcPubKey(privKey, generator, prime, myPubKey);


    // Read Ip from user input
    getIPandPort();

    // Create UDP socket
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
    
    
    // Set server family, socket structure and port
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(PORT);

    // Bind socket
    if (bind(sock, (sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\n Bind failed \n");
        return -1;
    }

    // Set address family and port
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(PORT);

    // Convert ip to binary and check it is supported by the given family
    if (inet_pton(AF_INET, ip, &peer_addr.sin_addr) <= 0) {
        printf("\n Invalid address/ Address not supported \n");
        return -1;
    }

    printf("'~1' to change ip\n'~2' to quit\nMax message length of %i characters\n", messageSize - 100);

    // Create a thread for receiving and create a thread for sending
    int result = pthread_create(&receivingThread, NULL, receiving, NULL);
    if (result != 0) {
        perror("Thread creation failed");
        return 1;
    }
    result = pthread_create(&sendingThread, NULL, sending, NULL);
    if (result != 0) {
        perror("Thread creation failed");
        return 1;
    }
    
    // Wait for threads to finish and join them
    result = pthread_join(receivingThread, NULL);
    if (result != 0) {
        perror("Thread join failed");
        return 1;
    }
    result = pthread_join(sendingThread, NULL);
    if (result != 0) {
        perror("Thread join failed");
        return 1;
    }

    // Close socket
    close(sock);
    
    // Destroy Mutex
    pthread_mutex_destroy(&lock);

    return 0;
}

void getIPandPort(){
    printf("What is your destination IP?\n");
    scanf("%15s", ip);
}



void * sending(){
    // Temporary variables for creating message
    char temp[30];
    char tempMsg[messageSize - 33];

    while(1){

        // Declare variable to track whether a message should be sent or not
        int ackBool = 0;

        // Prevent print statement running twice when creating connection
        if(firstMessage != 1){
            pthread_mutex_lock(&lock);
            printf("Message %s:%i: ", ip, PORT);
            pthread_mutex_unlock(&lock);
        }
        fflush(stdout);

        // Get the message from stdin and check it isn't NULL
        fgets(message, sizeof(message), stdin);
        if(strcmp(message, "\n") == 0 || strcmp(message, "") == 0){
            if(firstMessage == 0){
                printf("Message cannot be empty\n");
                continue;
            } else {
                // Attempt to send Public Key

                char * initMessage = mpz_get_str(NULL, 16, myPubKey);
                sprintf(message, "%s%s", "KEY", initMessage);
                //printf("Sending following message: %s\n", message);
                sendto(sock, message, strlen(message), 0, (sockaddr *)&peer_addr, sizeof(peer_addr));

                firstMessage = 0;
                continue;
            }
        }

        // Check if the message is a message or a command
        if(strcmp("~1\n", message) == 0){
            //This was not finished in time and does not yet function correctly
            getIPandPort();
        } else if(strcmp("~2\n", message) == 0){
            breakCondition = 1;
            break;
        }
        firstMessage = 0;

        // Lock the receive thread so that print statements don't intefere with one another
        pthread_mutex_lock(&lock);

        // Format the string as desired for sending a message
        sprintf(temp, "%s%d%c", "SEQ", currentSequence, '~');
        strcpy(tempMsg, message);

        // Check the string does not contain a flag at the start of the message, shouldn't cause an issue if it did, just a precaution
        if((message[0] == 'A' && message[1] == 'C' && message[2] == 'K') || (message[0] == 'S' && message[1] == 'E' && message[2] == 'Q')){
            printf("\nMessage cannot begin with ACK or SEQ\n");
            ackBool = 1;
        }
        sprintf(message, "%s%s%c", temp, tempMsg, '~');
        message[strcspn(message, "\n")] = '\0'; 

        if(ackBool == 0){
            const int giveUp = 1;
            int attempts = 0;
            unsigned char * encryptedMessage;

            // Calculate sequence number
            
            aesEncrypt(message, strlen(message), secretKeyStr, &encryptedMessage);
            currentSequence += strlen(encryptedMessage);

            // Send message
            sendto(sock, encryptedMessage, strlen(encryptedMessage), 0, (sockaddr *)&peer_addr, sizeof(peer_addr));
            
            // Inefficient implementation of time-out with hardcoded timeout value, since the network is LAN only
            // this will not cause an issue but if the code was extended to a wider network it would need be improved
            while(attempts <= giveUp){
                usleep(200000);
                if(currentSequence != recentACK){
                    attempts++;
                    if(attempts <= giveUp){
                        printf("Acknowledgement for %i and message %s was not received, trying again\n", currentSequence, message);
                        // Encrypyt message again to ensure encyrption was correct and send again
                        aesEncrypt(message, strlen(message), secretKeyStr, &encryptedMessage);
                        sendto(sock, encryptedMessage, strlen(encryptedMessage), 0, (sockaddr *)&peer_addr, sizeof(peer_addr));     
                    } else{
                        printf("Acknowledgement still not received, message may not have been delivered, try again\n");
                    }
                } else {
                    //printf("Success for string %s, with acknowledgement %i\n", message, currentSequence);
                    break;
                }
            }
            sprintf(calculatedACKStr, "%s%d", "ACK", currentSequence);
            
        }
        pthread_mutex_unlock(&lock);
    }
}

void * receiving(){
    // Temporary variables for creating ACK messages
    char temp[30];
    char ackNo[27];
    char tempKey[messageSize];
    while(1){
        // RSA SIGNATURE ONCE THIS MESSAGE IS RECIEVED
        // KEY:"010101010"YOURS:"01010101010011"SIGN:"0101010101000010"
        //if statement, check if its got a signature or not first,
        // Wait until a message is received
        socklen_t addr_len = sizeof(peer_addr);
        int n = recvfrom(sock, buffer, 4096, 0, (sockaddr *)&peer_addr, &addr_len);
        buffer[n] = '\0';
        int boolSent = 0; //store boolean if already sent signature

        if (buffer[0] == 'K' && buffer[1] == 'E' && buffer[2] == 'Y') {
            if (strlen(buffer) < 1000) {
                // contains just public key
                strcpy(tempKey, &buffer[3]);
                // tempKey = received public key
                // we dont want to calc secret key yet for diffie because we dont know who sent it
                strcpy(message, "KEY");
                char * initMessage = mpz_get_str(NULL, 16, myPubKey);
                strcat(message, initMessage);

                strcat(message, "\nPUB");
                strcat(message, tempKey);

                char* hashSTR = sha256(message);
                
                strcat(message, "\nSIG");
                strcat(message, rsaEncrypt(hashSTR, rsaPrivKey, rsaPubKey));

                printf("Sending the following message:\n%s\n", message);
                boolSent = 1;
                sendto(sock, message, strlen(message), 0, (sockaddr *)&peer_addr, sizeof(peer_addr));

            } else {
                // contains 2 keys and a signature
                //printf("I JUST RECIEVED THIS:\n%s\n", buffer);
                char s[2] = "\n";
                char* token;
                if (boolSent) {
                    //if already sent dont send a message just verify


                } else {
                    // verify and send signature back
                    token = strtok(buffer, s);
                    printf("%s\n", token);
                    // KEY74187281928481...
                    char* BobPubKey = token;

                    token = strtok(NULL, s);
                    printf("OUR %s\n", token);
                    // PUB849267388284682...
                    
                    char* AlicePubKey = token;
                    char* initMessage = mpz_get_str(NULL, 16, myPubKey);
                    printf("OUR KEY: %s\n", initMessage);
                    if (strcmp(&AlicePubKey[3], initMessage)) {
                        printf("\n\nWas my pub key whoop\n\n");
                    }


                    token = strtok(NULL, s);
                    //printf("%s\n", token);

                }
                break;
            }
        }

        // Check if the message is a key
        if(buffer[0] == 'K' && buffer[1] == 'E' && buffer[2] == 'Y'){
            // Parse public key and use it to calculate secretKey
            strcpy(tempKey, &buffer[3]);
            mpz_set_str(recievedPubKey, tempKey, 16);
            calcSecretKey(privKey, recievedPubKey, prime, secretKey);

            // Shorten secret key
            char * key = mpz_get_str(NULL, 16, secretKey);
            for (int i = 0; i < 32; i += 2) {
                char c1 = key[i];
                char c2 = key[i + 1];
                int value = 0;
            
                if (c1 >= '0' && c1 <= '9') {
                    value += (c1 - '0') * 16;
                } else if (c1 >= 'a' && c1 <= 'f') {
                    value += (c1 - 'a' + 10) * 16;
                }
            
                if (c2 >= '0' && c2 <= '9') {
                    value += c2 - '0';
                } else if (c2 >= 'a' && c2 <= 'f') {
                    value += c2 - 'a' + 10;
                }

                secretKeyStr[i/2] = value;
            }
            //gmp_printf("Secret Key: %ZX\n", secretKey);
            //printf("Key has beeen receievd: %gmp\n", recievedPubKey);
            //gmp_printf("Received %ZX\n",recievedPubKey);
            char * initMessage = mpz_get_str(NULL, 16, myPubKey);
            sprintf(message, "%s%s", "KEY", initMessage);
            //printf("Sending following message: %s\n", message);
            sendto(sock, message, strlen(message), 0, (sockaddr *)&peer_addr, sizeof(peer_addr));
            break;
        }
    }


    while(1){
        // When signalled by the send function break the loop and eventually end execution
        if(breakCondition == 1){
            break;
        }
        
        // Set up receive correctly and receive the message if there is one, if not move past the line
        socklen_t addr_len = sizeof(peer_addr);
        int n = recvfrom(sock, buffer, 1024, MSG_DONTWAIT, (sockaddr *)&peer_addr, &addr_len);
        buffer[n] = '\0';

        if(n > 0){
            // If a message has been received enter the following block
            // Get the buffer Length, needed for decryption
            int bufferLength = strlen(buffer) / 16;
            if(strlen(buffer) % 16 != 0){
                bufferLength++;
            }
            // printf("Buffer length is %i", bufferLength);
            // If the message is an ACK enter this code block
            
            unsigned char * decryptedBuffer;
            // Decrypt buffer into decryptedBuffer
            aesDecrypt(buffer, bufferLength, secretKeyStr, &decryptedBuffer);

            //printf("\n\nDecrypted Buffer is: %s\n\n", decryptedBuffer);
            
            // Check decryptedBuffer will not cause a segmentation fault
            if(strlen(decryptedBuffer) > 2 ){
                //printf("\nResponse received: %s\n", decryptedBuffer);
                if(decryptedBuffer[0] == 'A' && decryptedBuffer[1] == 'C' && decryptedBuffer[2] == 'K'){

                    // Get ACK number from message and set to shared variable between 
                    // here and send to determine whether there is a timeout or not
                    char * ptr;
                    ptr = strtok(decryptedBuffer, "~");
                    strcpy(ackNo, &ptr[4]);
                    recentACK = atoi(ackNo);

                    //printf("received ACK is: %i\n", recentACK);

                    // Statements for debugging ACKS if further better implementation was done
                    //if(recentACK == expec ) printf("message was acked\n");
                    //else printf("\nMessage was not acked\nActual: %s\nExpected: ACK%i\n", decryptedBuffer, currentSequence);
                } else if (decryptedBuffer[0] == 'S' && decryptedBuffer[1] == 'E' && decryptedBuffer[2] == 'Q'){ // Enter this block when the message is a normal message
                    
                    // Get the sequence number from the message
                    char * ptr;
                    ptr = strtok(decryptedBuffer, "~");
                    char *msg = strtok(NULL, "~");
                    strcpy(ackNo, &ptr[3]);
                    int ackInt = atoi(ackNo);
                    
                    // printf("\nSequence number is: %i\nMessage is: %s", ackInt, msg);

                    // Calculate expected ACK, encrypt and send
                    unsigned char * encryptedACK;
                    strcpy(ack, "ACK");
                    sprintf(temp, "%s%c%d", ack, '~', ackInt + n);
                    aesEncrypt(temp, strlen(temp), secretKeyStr, &encryptedACK);
                    sendto(sock, encryptedACK, strlen(encryptedACK), 0, (sockaddr *)&peer_addr, sizeof(peer_addr));

                    // Print the received message
                    printf("\nResponse received: %s", msg);
                    //printf("\nResponse received: %s", buffer);
                    
                    printf("\nMessage %s:%i: ", ip, PORT);
                    strcpy(decryptedBuffer, "");
                    fflush(stdout);   
                }
                free(decryptedBuffer);
            }
        }        
    }
}
