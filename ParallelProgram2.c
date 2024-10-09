#include <mpi.h>
#include <openssl/des.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

// Función para eliminar padding (PKCS5)
int remove_padding(unsigned char *text, size_t *text_len) {
    unsigned char padding_value = text[*text_len - 1];
    if (padding_value > 8) {
        return 0;
    }
    *text_len -= padding_value;
    text[*text_len] = '\0';
    return 1;
}

// Función para agregar padding (PKCS5)
void add_padding(unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len) {
    size_t padding_length = 8 - (input_len % 8);
    memcpy(output, input, input_len);
    for (size_t i = 0; i < padding_length; i++) {
        output[input_len + i] = padding_length;
    }
    *output_len = input_len + padding_length;
}

// Enmascarar los 56 bits efectivos de la clave
void mask_56_bits(unsigned long long *key) {
    *key &= 0x00FFFFFFFFFFFFFF;
}

// Cifrar un texto con una clave DES en modo CBC
void encrypt_with_key(unsigned long long key, const unsigned char *iv, unsigned char *output, const unsigned char *input, size_t input_len) {
    DES_cblock key_block;
    DES_key_schedule schedule;
    mask_56_bits(&key);
    memcpy(key_block, &key, 8);
    DES_set_key_unchecked(&key_block, &schedule);
    DES_cbc_encrypt(input, output, input_len, &schedule, (DES_cblock *)iv, DES_ENCRYPT);
}

// Intentar descifrar con una clave específica
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
    return strstr((char *)decrypted_output, keyword) != NULL;
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
    unsigned long long key_start = strtoull(argv[2], NULL, 10);
    const char *keyword = argv[3];
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

    // Leer el texto del archivo
    char plaintext[128];
    fgets(plaintext, sizeof(plaintext), file);
    fclose(file);

    // Añadir padding al texto
    add_padding((unsigned char *)plaintext, strlen(plaintext), padded_plaintext, &padded_len);

    // Cifrar el texto usando la clave inicial
    encrypt_with_key(key_start, iv, encrypted_text, padded_plaintext, padded_len);

    // Dividir el rango de claves entre los procesos
    unsigned long long int range_per_process = 0xFFFFFFFFFFFFFFFF / size;
    unsigned long long int start = rank * range_per_process;
    unsigned long long int end = (rank == size - 1) ? 0xFFFFFFFFFFFFFFFF : start + range_per_process - 1;

    // Variable para controlar si se encontró la clave
    int found = 0;
    unsigned long long found_key = 0;
    char found_decrypted_text[128] = {0};

    // Fuerza bruta para encontrar la clave
    clock_t start_time = clock();
    for (unsigned long long i = start; i <= end && !found; i++) {
        decrypted_len = padded_len;
        if (decrypt_with_key(i, iv, encrypted_text, decrypted_text, &decrypted_len, keyword)) {
            found = 1;
            found_key = i;
            // Copiar el texto descifrado para que sea enviado al proceso 0
            strncpy(found_decrypted_text, (char *)decrypted_text, decrypted_len);
            found_decrypted_text[decrypted_len] = '\0';

            // Notificar a otros procesos que se encontró la clave
            MPI_Bcast(&found, 1, MPI_INT, rank, MPI_COMM_WORLD);
            MPI_Bcast(&found_key, 1, MPI_UNSIGNED_LONG_LONG, rank, MPI_COMM_WORLD);
            MPI_Bcast(found_decrypted_text, 128, MPI_CHAR, rank, MPI_COMM_WORLD);
            break;
        }
        // Revisar periódicamente si otro proceso ya encontró la clave
        if (i % 10000 == 0) {
            MPI_Bcast(&found, 1, MPI_INT, 0, MPI_COMM_WORLD);
        }
    }

    // Solo el proceso 0 muestra la clave encontrada y el texto descifrado
    if (rank == 0 && found) {
        printf("¡Clave encontrada!: %016llX\n", found_key);
        printf("Texto descifrado: %s\n", found_decrypted_text);
        clock_t end_time = clock();
        double time_taken = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
        printf("Tiempo total de ejecución: %.6f segundos\n", time_taken);
    }

    MPI_Finalize();
    return 0;
}
