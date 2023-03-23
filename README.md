# Instructions:
## Step 1: Pre-Requisites
Use a unix machine
## Step 2: Install Libraries
    sudo apt-get install libgmp-dev
    sudo apt-get install libgmp3-dev
## Step 3: Run code
    gcc -o peer peerToPeer.c -pthread -lgmp
## Step 4: Run executable
    ./peer