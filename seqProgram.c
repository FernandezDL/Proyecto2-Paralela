#include <openssl/des.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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

// Función para convertir una palabra a su representación hexadecimal
void string_to_hex(const char *input, char *output) {
    while (*input) {
        sprintf(output, "%02X", (unsigned char)*input++);
        output += 2;
    }
    *output = '\0';
}

// Función para cifrar un texto con una clave DES en modo CBC, todo en memoria
void encrypt_with_key(const unsigned char *key, const unsigned char *iv, unsigned char *output, const unsigned char *input, size_t input_len) {
    DES_cblock key_block;
    DES_key_schedule schedule;

    // Convertir la clave a formato DES_cblock
    memcpy(key_block, key, 8);
    DES_set_key_unchecked(&key_block, &schedule);

    // Cifrar en modo CBC
    DES_cbc_encrypt(input, output, input_len, &schedule, (DES_cblock *)iv, DES_ENCRYPT);
}

// Función para descifrar el texto cifrado con una clave DES en modo CBC, todo en memoria
int decrypt_with_key(const unsigned char *key, const unsigned char *iv, unsigned char *encrypted_text, unsigned char *decrypted_output, size_t *text_len, const char *keyword_hex) {
    DES_cblock key_block;
    DES_key_schedule schedule;

    // Convertir la clave a formato DES_cblock
    memcpy(key_block, key, 8);

    DES_set_key_unchecked(&key_block, &schedule);

    // Desencriptar en modo CBC
    DES_cbc_encrypt(encrypted_text, decrypted_output, *text_len, &schedule, (DES_cblock *)iv, DES_DECRYPT);

    // Eliminar padding PKCS5 después del descifrado
    if (!remove_padding(decrypted_output, text_len)) {
        return 0;  // Error al eliminar padding
    }

    // Convertir el texto descifrado a hexadecimal
    char decrypted_hex[256];
    string_to_hex((char *)decrypted_output, decrypted_hex);

    // Verificar si la frase clave aparece en la representación hexadecimal del texto descifrado
    if (strstr(decrypted_hex, keyword_hex) != NULL) {
        return 1;  // Frase clave encontrada en formato hexadecimal
    }

    return 0;  // Clave incorrecta
}

int main() {
    unsigned char key[9] = "00005678";  // Clave de 8 bytes para cifrado
    unsigned char iv[DES_KEY_SZ] = {0};  // Vector de inicialización estático (todos ceros)
    unsigned char encrypted_text[128];  // Almacenar el texto cifrado
    unsigned char decrypted_text[128];  // Almacenar el texto descifrado
    unsigned char padded_plaintext[128];  // Texto con padding
    size_t padded_len = 0;  // Longitud del texto con padding
    size_t decrypted_len;  // Almacenar la longitud del texto descifrado
    char keyword_hex[64];  // Palabra clave en formato hexadecimal
    clock_t start_time, end_time;
    double time_taken;
    unsigned long long int i;

    // Convertir la palabra clave a su representación en hexadecimal
    string_to_hex(keyword, keyword_hex);

    // Añadir padding al texto original
    add_padding((unsigned char *)plaintext, strlen(plaintext), padded_plaintext, &padded_len);

    // Cifrar el texto original en memoria
    encrypt_with_key(key, iv, encrypted_text, padded_plaintext, padded_len);

    // Iniciar temporizador para descifrado por fuerza bruta
    start_time = clock();

    // Fuerza bruta: probar todas las combinaciones de claves de 56 bits (8 caracteres en hexadecimal)
    for (i = 0x000000000000; i <= 0xFFFFFFFFFFFF; i++) {  // Probar todo el rango de 56 bits
        decrypted_len = padded_len;  // Restablecer la longitud descifrada en cada intento

        // Intentar descifrar con la clave actual
        if (decrypt_with_key(key, iv, encrypted_text, decrypted_text, &decrypted_len, keyword_hex)) {
            printf("¡Clave encontrada!: %s\n", key);
            printf("Texto descifrado: %s\n", decrypted_text);
            break;
        }
    }

    // Finalizar temporizador
    end_time = clock();

    // Calcular tiempo total en segundos (con mayor precisión)
    time_taken = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    printf("Tiempo total: %.6f segundos\n", time_taken);

    return 0;
}
