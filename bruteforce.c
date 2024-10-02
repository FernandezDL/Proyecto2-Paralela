#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>
#include <time.h>

// Función para cifrar un texto con una clave DES utilizando la API DES directa
int encrypt(unsigned char *key, unsigned char *plaintext, int len, unsigned char *ciphertext) {
    DES_cblock keyBlock;
    DES_key_schedule schedule;

    // Se ciopia clave
    memcpy(keyBlock, key, 8);

    // Ajustar la paridad de la clave a impar
    DES_set_odd_parity(&keyBlock);

    // Configurar la clave DES
    if (DES_set_key_checked(&keyBlock, &schedule) != 0) {
        printf("Error configurando la clave\n");
        return 0;
    }

    // Cifrar el texto en bloques de 8 bytes
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(plaintext + i), (DES_cblock *)(ciphertext + i), &schedule, DES_ENCRYPT);
    }

    return len; // El texto cifrado es del mismo tamaño que el original con padding
}

// Función para agregar padding (PKCS7)
void add_padding(unsigned char *plaintext, int *len) {
    int padding_len = 8 - (*len % 8);
    for (int i = *len; i < (*len + padding_len); i++) {
        plaintext[i] = padding_len;
    }
    *len += padding_len;
}

// Función para desencriptar un texto cifrado con una clave DES utilizando la API DES directa
int decrypt(unsigned char *key, unsigned char *ciphertext, int len, unsigned char *plaintext) {
    DES_cblock keyBlock;
    DES_key_schedule schedule;

    // Se ciopia clave
    memcpy(keyBlock, key, 8);

    // Ajustar la paridad de la clave a impar
    DES_set_odd_parity(&keyBlock);

    // Configurar la clave DES
    if (DES_set_key_checked(&keyBlock, &schedule) != 0) {
        printf("Error configurando la clave\n");
        return 0;
    }

    // Desencriptar el texto en bloques de 8 bytes
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(ciphertext + i), (DES_cblock *)(plaintext + i), &schedule, DES_DECRYPT);
    }

    return len; // El texto desencriptado es del mismo tamaño que el cifrado
}

// Generar todas las combinaciones posibles de claves (fuerza bruta)
void bruteForceSearch(unsigned char *ciphertext, int len, char *keyword) {
    unsigned char key[9] = "00000000"; // Llave inicial de 8 caracteres
    unsigned char plaintext[64]; // Aquí se almacenará el texto descifrado

    while (1) {
        if (decrypt(key, ciphertext, len, plaintext) > 0 && strstr((char *)plaintext, keyword) != NULL) {
            printf("Llave encontrada: %s\n", key);
            printf("Texto descifrado: %s\n", plaintext);
            break;
        }

        // Incrementar la llave
        for (int i = 7; i >= 0; i--) {
            if (key[i] < 'z') {
                key[i]++;
                break;
            } else {
                key[i] = '0'; // Reinicia el carácter y avanza al siguiente
            }
        }

        // Si la llave es "zzzzzzzz" entonces ya probamos todas
        if (strcmp((char *)key, "zzzzzzzz") == 0) {
            printf("No se encontró la llave correcta.\n");
            break;
        }
    }
}

int main() {
    // Definir texto original a cifrar
    unsigned char plaintext[] = "Esta es una prueba de proyecto 2"; // Texto de ejemplo
    unsigned char ciphertext[64];  // Aquí se almacenará el texto cifrado
    unsigned char key[] = "segurida"; // Clave de 8 bytes

    int len = strlen((char *)plaintext);

    // Agregar padding para ajustar al tamaño múltiplo de 8
    add_padding(plaintext, &len);

    printf("Texto original (con padding): %s\n", plaintext);

    // Cifrar el texto
    int cipher_len = encrypt(key, plaintext, len, ciphertext);
    if (cipher_len == 0) {
        printf("Error en el cifrado\n");
        return 1;
    }

    printf("Texto cifrado: ");
    for (int i = 0; i < cipher_len; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    // Definir la palabra clave para la búsqueda en el texto descifrado
    char keyword[] = "es una prueba de"; // Palabra clave a buscar

    // Medir el tiempo de ejecución
    clock_t start = clock();

    // Realizar búsqueda por fuerza bruta
    bruteForceSearch(ciphertext, cipher_len, keyword);

    // Calcular y mostrar el tiempo de ejecución
    clock_t end = clock();
    double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Tiempo de búsqueda: %.6f segundos\n", time_taken);

    return 0;
}

