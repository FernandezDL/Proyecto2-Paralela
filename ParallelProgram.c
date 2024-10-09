#include <mpi.h>
#include <openssl/des.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

// Función para eliminar padding después del descifrado (PKCS5 padding)
int remove_padding(unsigned char *text, size_t *text_len) {
    unsigned char padding_value = text[*text_len - 1];
    if (padding_value > 8) {
        return 0;
    }
    *text_len -= padding_value;
    text[*text_len] = '\0';
    return 1;
}

// Función para agregar padding (PKCS5 padding)
void add_padding(unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len) {
    size_t padding_length = 8 - (input_len % 8);
    memcpy(output, input, input_len);
    for (size_t i = 0; i < padding_length; i++) {
        output[input_len + i] = padding_length;
    }
    *output_len = input_len + padding_length;
}

// Función para enmascarar los 56 bits efectivos de la clave
void mask_56_bits(unsigned long long *key) {
    *key &= 0x00FFFFFFFFFFFFFF;
}

// Función para cifrar un texto con una clave DES en modo CBC, todo en memoria
void encrypt_with_key(unsigned long long key, const unsigned char *iv, unsigned char *output, const unsigned char *input, size_t input_len) {
    DES_cblock key_block;
    DES_key_schedule schedule;

    mask_56_bits(&key);
    memcpy(key_block, &key, 8);
    DES_set_key_unchecked(&key_block, &schedule);
    DES_cbc_encrypt(input, output, input_len, &schedule, (DES_cblock *)iv, DES_ENCRYPT);
}

// Función para descifrar el texto cifrado con una clave DES en modo CBC, todo en memoria
int decrypt_with_key(unsigned long long key, const unsigned char *iv, unsigned char *encrypted_text, unsigned char *decrypted_output, size_t *text_len, const char *keyword) {
    DES_cblock key_block;
    DES_key_schedule schedule;

    mask_56_bits(&key);
    memcpy(key_block, &key, 8);
    DES_set_key_unchecked(&key_block, &schedule);
    DES_cbc_encrypt(encrypted_text, decrypted_output, *text_len, &schedule, (DES_cblock *)iv, DES_DECRYPT);

    if (!remove_padding(decrypted_output, text_len)) {
        return 0;
    }

    if (strstr((char *)decrypted_output, keyword) != NULL) {
        return 1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);

    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    if (argc < 4) {
        if (rank == 0) {
            printf("Uso: %s <archivo_texto> <clave_inicial> <keyword>\n", argv[0]);
        }
        MPI_Finalize();
        return 1;
    }

    const char *input_filename = argv[1];
    unsigned char iv[DES_KEY_SZ] = {0};
    unsigned char encrypted_text[128];
    unsigned char decrypted_text[128];
    unsigned char padded_plaintext[128];
    size_t padded_len = 0;
    size_t decrypted_len;
    FILE *file = fopen(input_filename, "r");

    if (!file) {
        if (rank == 0) {
            printf("No se pudo abrir el archivo %s\n", input_filename);
        }
        MPI_Finalize();
        return 1;
    }

    char plaintext[128];
    fgets(plaintext, sizeof(plaintext), file);
    fclose(file);

    add_padding((unsigned char *)plaintext, strlen(plaintext), padded_plaintext, &padded_len);

    unsigned long long key_start = strtoull(argv[2], NULL, 10);
    encrypt_with_key(key_start, iv, encrypted_text, padded_plaintext, padded_len);

    if (rank == 0) {
        FILE *encrypted_file = fopen("encrypted_text.bin", "wb");
        fwrite(encrypted_text, 1, padded_len, encrypted_file);
        fclose(encrypted_file);
    }

    unsigned long long int max_key = 0xFFFFFFFFFFFFFF;
    unsigned long long int range_per_process = max_key / size;
    unsigned long long int start = rank * range_per_process;
    unsigned long long int end = (rank + 1) * range_per_process - 1;
    unsigned long long int found_key = 0;
    int found = 0;

    clock_t start_time = clock();

    for (unsigned long long int i = start; i <= end && !found; i++) {
        decrypted_len = padded_len;

        if (decrypt_with_key(i, iv, encrypted_text, decrypted_text, &decrypted_len, argv[3])) {
            found_key = i;
            found = 1;
            printf("Proceso %d: ¡Clave encontrada!: %016llX\n", rank, found_key);
            printf("Texto descifrado: %s\n", decrypted_text);
        }

        int temp_found = found;
        MPI_Allreduce(&temp_found, &found, 1, MPI_INT, MPI_MAX, MPI_COMM_WORLD);
    }

    clock_t end_time = clock();
    double time_taken = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    if (rank == 0) {
        if (found) {
            printf("Clave encontrada en algún proceso. Tiempo total: %.6f segundos\n", time_taken);
        } else {
            printf("Clave no encontrada en el rango dado. Tiempo total: %.6f segundos\n", time_taken);
        }
    }

    MPI_Finalize();
    return 0;
}
