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

#define PORT 3333
#define messageSize 1025

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
    char buffer[1024] = {0};
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
        // Wait until a message is received
        socklen_t addr_len = sizeof(peer_addr);
        int n = recvfrom(sock, buffer, 1024, 0, (sockaddr *)&peer_addr, &addr_len);
        buffer[n] = '\0';
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
