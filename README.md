# Proyecto: Cifrado y Descifrado de Texto usando MPI y Fuerza Bruta 🔒

## Descripción General
Este proyecto consiste en implementar un programa en C/C++ para la búsqueda de una llave privada con la que fue cifrado un texto plano, utilizando el método de fuerza bruta. El programa se ejecuta en un entorno de memoria distribuida, utilizando **MPI (Message Passing Interface)** para la paralelización de la búsqueda de la clave. Se proporciona tanto una versión secuencial como una versión paralela del algoritmo.

La búsqueda de la clave correcta se realiza probando todas las posibles combinaciones hasta encontrar la que descifra el texto. La validación de un descifrado exitoso se hace buscando una palabra o frase clave conocida que debería estar presente en el texto descifrado.

## Objetivos del Proyecto
- Diseñar e implementar programas para la paralelización de procesos con memoria distribuida usando **Open MPI**.
- Optimizar el uso de recursos distribuidos y mejorar el *speedup* de un programa paralelo.
- Utilizar el método de fuerza bruta para descubrir la llave privada utilizada en el cifrado de un texto.
- Analizar y comprender el comportamiento del *speedup* de forma estadística para optimizar la distribución del espacio de búsqueda.

## Requisitos Técnicos
1. **Lenguaje y Herramientas**:
   - Lenguaje de programación: C/C++
   - Biblioteca de cifrado: OpenSSL (`libssl` y `libcrypto`)
   - Biblioteca de paralelización: Open MPI
2. **Funciones Implementadas**:
   - Cifrado y descifrado de un texto utilizando **DES** (Data Encryption Standard) en modo CBC (Cipher Block Chaining).
   - Implementación de un algoritmo de fuerza bruta para probar todas las posibles combinaciones de llaves.
   - Distribución de la carga de trabajo entre múltiples procesos usando MPI.
3. **Entorno de Ejecución**:
   - Se utiliza un entorno compatible con Open MPI.
   - Compatible con sistemas Linux y probado en Ubuntu.

## Estructura del Proyecto
- `seqProgram.c`: Implementación secuencial del algoritmo para descifrar un texto cifrado utilizando fuerza bruta.
- `ParallelProgram.c`: Implementación paralela del algoritmo utilizando MPI para la búsqueda de la clave.
- `README.md`: Archivo con instrucciones de ejecución y descripción del proyecto.
- `encrypted_text.bin`: Archivo generado que contiene el texto cifrado.
- `texto.txt`: Archivo de entrada que contiene el texto original a cifrar.
  
## Instrucciones de Ejecución

### Compilación
Para compilar los programas, asegúrate de tener **Open MPI** y las bibliotecas de **OpenSSL** instaladas. Puedes compilar cada archivo de la siguiente manera:

- **Compilación del programa secuencial**:
  
  ```bash
  gcc seqProgram.c -o seqProgram -lssl -lcrypto

- **Compilación del programa paralelo**:
  ```bash
    mpicc ParallelProgram.c -o ParallelProgram -lssl -lcrypto

### Ejecución

- **Compilación del programa secuencial**:
  
  ```bash
  ./seqProgram texto.txt 42

- **Compilación del programa paralelo**:
  ```bash
    mpirun -np 4 ./ParallelProgram texto.txt 36028797018963969 "es una prueba de"

## Notas importantes
- Asegúrate de que el archivo texto.txt esté en la misma carpeta desde la cual se ejecuta el programa o proporciona la ruta completa al archivo.
- El programa generará un archivo encrypted_text.bin que contiene el texto cifrado.
- OpenSSL versión 1.1.1 es necesaria para la compatibilidad con las funciones de cifrado DES.


