#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <openssl/des.h>

void decrypt(unsigned char *key, unsigned char *ciph, int len){
    DES_cblock des_key;
    DES_key_schedule schedule;

    memcpy(des_key, key, 8);
    DES_set_odd_parity(&des_key);

    if (DES_set_key_checked(&des_key, &schedule) != 0) {
        return;
    }

    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(ciph + i), (DES_cblock *)(ciph + i), &schedule, DES_DECRYPT);
    }
}

int tryKey(unsigned char *key, unsigned char *ciph, int len){
    unsigned char temp[len+1];
    memcpy(temp, ciph, len);
    temp[len] = 0;  
    decrypt(key, temp, len);

    return strstr((char *)temp, " the ") != NULL;
}

unsigned char cipher[] = {108, 245, 65, 63, 125, 200, 150, 66, 17, 170, 207, 170, 34, 31, 70, 215, 0};

int main(int argc, char *argv[]) {
    int N, id;
    long upper = (1L << 56); // upper bound for DES keys 2^56
    long mylower, myupper;
    MPI_Status st;
    MPI_Request req;
    int flag;
    int ciphlen = 16;  

    MPI_Comm comm = MPI_COMM_WORLD;

    MPI_Init(NULL, NULL);
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    long range_per_node = upper / N;
    mylower = range_per_node * id;
    myupper = range_per_node * (id + 1) - 1;
    if (id == N - 1) {
        myupper = upper;
    }

    long found = 0;
    unsigned char key[8];

    // Start receiving the key if found
    MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

    // Try keys within the range assigned to this process
    for (long i = mylower; i < myupper && found == 0; ++i) {
        MPI_Test(&req, &flag, &st);
        if (flag) {
            break;  // Exit the loop if the key was found
        }
        for (int j = 0; j < 8; ++j) {
            key[j] = (i >> (j * 8)) & 0xFF;
        }

        if (tryKey(key, cipher, ciphlen)) {
            found = i;
            for (int node = 0; node < N; node++) {
                MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
            }
            break;
        }
    }

    // If process 0, wait for the key and print the decrypted message
    if (id == 0) {
        MPI_Wait(&req, &st);
        if (found != 0) {
            // Convert the found key into an 8-byte key and decrypt
            for (int j = 0; j < 8; ++j) {
                key[j] = (found >> (j * 8)) & 0xFF;
            }
            decrypt(key, cipher, ciphlen);
            printf("Key: %li, Decrypted message: %s\n", found, cipher);
        } else {
            printf("No valid key found.\n");
        }
    }

    MPI_Finalize();
}