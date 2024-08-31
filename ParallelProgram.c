#include <mpi.h>
#include <openssl/des.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>     /* strtoull */


// Texto original que queremos cifrar
const char *plaintext = "Este es un ejemplo";
// Frase clave conocida (palabra clave en el texto)
char *keyword = "ejemplo";

// Función para eliminar padding después del descifrado (PKCS5 padding)
int remove_padding(unsigned char *text, size_t *text_len) {
    unsigned char padding_value = text[*text_len - 1];  // Valor del padding
    if (padding_value > 8) {
        return 0;  // Valor de padding inválido
    }
    *text_len -= padding_value;
    text[*text_len] = '\0';  // Agregar terminador nulo después de quitar padding
    return 1;
}

// Función para agregar padding (PKCS5 padding)
void add_padding(unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len) {
    size_t padding_length = 8 - (input_len % 8);
    memcpy(output, input, input_len);  // Copiar texto original
    for (size_t i = 0; i < padding_length; i++) {
        output[input_len + i] = padding_length;  // Añadir padding
    }
    *output_len = input_len + padding_length;  // Longitud con padding
}

// Función para enmascarar los 56 bits efectivos de la clave
void mask_56_bits(unsigned long long *key) {
    *key &= 0x00FFFFFFFFFFFFFF;  // Aplicar una máscara para usar solo los primeros 56 bits
}

// Función para cifrar un texto con una clave DES en modo CBC, todo en memoria
void encrypt_with_key(unsigned long long key, const unsigned char *iv, unsigned char *output, const unsigned char *input, size_t input_len) {
    DES_cblock key_block;
    DES_key_schedule schedule;

    // Enmascarar los 56 bits efectivos
    mask_56_bits(&key);

    // Convertir el número de clave en 8 bytes
    memcpy(key_block, &key, 8);

    // Usar DES_set_key_unchecked para evitar modificar la clave
    DES_set_key_unchecked(&key_block, &schedule);

    // Cifrar en modo CBC
    DES_cbc_encrypt(input, output, input_len, &schedule, (DES_cblock *)iv, DES_ENCRYPT);
}

// Función para descifrar el texto cifrado con una clave DES en modo CBC, todo en memoria
int decrypt_with_key(unsigned long long key, const unsigned char *iv, unsigned char *encrypted_text, unsigned char *decrypted_output, size_t *text_len, const char *keyword) {
    DES_cblock key_block;
    DES_key_schedule schedule;

    // Enmascarar los 56 bits efectivos
    mask_56_bits(&key);

    // Convertir el número de clave en 8 bytes
    memcpy(key_block, &key, 8);

    // Usar DES_set_key_unchecked para evitar modificar la clave
    DES_set_key_unchecked(&key_block, &schedule);

    // Desencriptar en modo CBC
    DES_cbc_encrypt(encrypted_text, decrypted_output, *text_len, &schedule, (DES_cblock *)iv, DES_DECRYPT);

    // Eliminar padding PKCS5 después del descifrado
    if (!remove_padding(decrypted_output, text_len)) {
        return 0;  // Error al eliminar padding
    }

    // Comprobar si el texto descifrado contiene la palabra clave
    if (strstr((char *)decrypted_output, keyword) != NULL) {
        return 1;  // Clave encontrada
    }

    return 0;  // Clave incorrecta
}

// Función para imprimir la clave en formato hexadecimal
void print_key_hex(unsigned long long key) {
    printf("Clave actual en hexadecimal: %016llX\n", key);  // Imprimir la clave en hexadecimal (16 caracteres, relleno con ceros si es necesario)
}

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);

    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);  // Identificador del proceso
    MPI_Comm_size(MPI_COMM_WORLD, &size);  // Número de procesos

    if (argc < 4) {
        if (rank == 0) {
            printf("Uso: %s <archivo_texto> <clave> <keyword>\n", argv[0]);
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

    // Añadir padding al texto leído
    add_padding((unsigned char *)plaintext, strlen(plaintext), padded_plaintext, &padded_len);

    // Cifrar el texto original en memoria usando la clave proporcionada
    encrypt_with_key(key_start, iv, encrypted_text, padded_plaintext, padded_len);

    // Guardar el texto cifrado en un archivo (solo el proceso 0)
    if (rank == 0) {
        FILE *encrypted_file = fopen("encrypted_text.bin", "wb");
        fwrite(encrypted_text, 1, padded_len, encrypted_file);
        fclose(encrypted_file);
    }

    // Fuerza bruta paralelizada para encontrar la clave
    unsigned long long int range_per_process = 0xFFFFFFFFFFFFFFFF / size;
    unsigned long long int start = rank * range_per_process;
    unsigned long long int end = start + range_per_process;

    printf("Proceso %d: Rango de claves %016llX a %016llX\n", rank, start, end);

    clock_t start_time = clock();
    for (unsigned long long i = start; i <= end; i++) {
        decrypted_len = padded_len;
        if (decrypt_with_key(i, iv, encrypted_text, decrypted_text, &decrypted_len, keyword)) {
            printf("Proceso %d: ¡Clave encontrada!: %016llX\n", rank, i);
            printf("Texto descifrado: %s\n", decrypted_text);
            break;
        }
    }
    clock_t end_time = clock();
    double time_taken = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    printf("Proceso %d: Tiempo de ejecución: %.6f segundos\n", rank, time_taken);

    MPI_Finalize();
    return 0;
}
