#include <openssl/des.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// Texto original que queremos cifrar
const char *plaintext = "Este es un ejemplo";
// Frase clave conocida
char *keyword = "ejemplo";

// Función para cifrar un texto con una clave DES en modo CBC
void encrypt_with_key(const unsigned char *key, const unsigned char *iv, unsigned char *output, const unsigned char *input) {
    DES_cblock key_block;
    DES_key_schedule schedule;

    // Convertir la clave a formato DES_cblock
    memcpy(key_block, key, 8);
    DES_set_key_unchecked(&key_block, &schedule);

    // Cifrar en modo CBC
    DES_ncbc_encrypt(input, output, strlen((char *)input) + 1, &schedule, (DES_cblock *)iv, DES_ENCRYPT);
}

// Función para descifrar el texto cifrado con una clave DES en modo CBC
int decrypt_with_key(const unsigned char *key, const unsigned char *iv, unsigned char *output) {
    DES_cblock key_block;
    DES_key_schedule schedule;

    // Convertir la clave a formato DES_cblock
    memcpy(key_block, key, 8);
    if (DES_set_key_checked(&key_block, &schedule) != 0) {
        return 0; // Error al setear la clave
    }

    // Inicializar el buffer de salida
    unsigned char decrypted_output[128];

    // Desencriptar en modo CBC
    DES_ncbc_encrypt(output, decrypted_output, strlen((char *)output) + 1, &schedule, (DES_cblock *)iv, DES_DECRYPT);

    // Verificar si la frase clave aparece en el texto descifrado
    if (strstr((char *)decrypted_output, keyword) != NULL) {
        strcpy((char *)output, (char *)decrypted_output);
        return 1; // Frase clave encontrada
    }

    return 0; // Clave incorrecta
}

int main() {
    unsigned char key[9] = "12345678"; // Clave de 8 bytes para cifrado
    unsigned char iv[DES_KEY_SZ]; // Vector de inicialización para CBC
    unsigned char encrypted_text[128]; // Almacenar el texto cifrado
    unsigned char decrypted_text[128]; // Almacenar el texto descifrado
    time_t start_time, end_time;
    unsigned long long int i;

    // Generar un vector de inicialización aleatorio
    if (!RAND_bytes(iv, DES_KEY_SZ)) {
        fprintf(stderr, "Error generando IV\n");
        return 1;
    }

    // Cifrar el texto original
    printf("Texto original: %s\n", plaintext);
    encrypt_with_key(key, iv, encrypted_text, (unsigned char *)plaintext);
    printf("Texto cifrado (en hexadecimal):\n");
    for (i = 0; i < strlen((char *)plaintext); i++) {
        printf("%02X ", encrypted_text[i]);
    }
    printf("\n");

    // Iniciar temporizador para descifrado por fuerza bruta
    start_time = time(NULL);

    // Fuerza bruta: probar todas las combinaciones de claves de 8 caracteres (hasta 0xFFFFFFFFFFFF)
    for (i = 0; i <= 0xFFFFFFFFFFFF; i++) {
        sprintf((char *)key, "%08llX", i); // Convertir i en una clave hexadecimal de 8 caracteres

        // Intentar descifrar con la clave actual
        if (decrypt_with_key(key, iv, encrypted_text)) {
            printf("¡Clave encontrada!: %s\n", key);
            printf("Texto descifrado: %s\n", encrypted_text);
            break;
        }
    }

    // Finalizar temporizador
    end_time = time(NULL);
    printf("Tiempo total: %ld segundos\n", end_time - start_time);

    return 0;
}
