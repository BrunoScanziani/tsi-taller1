#include "tsi_authenticator.h"
#include <cotp.h>
#include <time.h>
#include <string.h>
#include <gcrypt.h>

/* Funcion encargada de validar un código TOTP */
static int validate_token(const char *secret_b32, char *code, int *valid) {

        /* Comienzo pesimista */
        *valid = 0;

        long now = (long) time(NULL);       /* Tiempo actual */
        long block = now / DEFAULT_PERIOD; /* Numero de bloque de 30 s en el que estamos */
        int half = DEFAULT_WINDOW / 2;      /* Cant de ventanas de 30s hacia atras y adelante a partir de la actual */

        /* Calculamos los códigos para cada ventana */
        for (int i = -half; i <= half; i++) {

            /* Obtengo un tiestamp dentro del periodo de 30s para el que estoy calculando el codigo */
            long timestamp = (block + i) * DEFAULT_PERIOD;

            /* Uso la libreria libcotp para calular el codigo */
            cotp_error_t err;

            /* Como pretendemos usar la app Google Authentiator del cel, que asume SHA1, ponemos como algoritmo COTP_SHA1. 
                SHA1 es lo default que indica el RFC */
            char* calculated_code = get_totp(secret_b32, DEFAULT_DIGITS, DEFAULT_PERIOD, COTP_SHA1, &err);

            /* Si hubo error salgo con fallo */
            if (err || calculated_code == NULL) {
                return 1;
            }

            /* Comparo los digitos */

            if (strncmp(code, calculated_code, DEFAULT_DIGITS) != 0) {
                /* Los codigos son diferentes */
                free(calculated_code);      /* Liberar memoria con info importante */
                return 0;
            } else {
                /* Los codigos son iguales */
                free(calculated_code);      /* Liberar memoria con info importante */
                *valid = 1;
                return 0;
            }
        }
    }

/* Funcion encargada de generar un secreto de largo SECRET_BITS_NUMBER */
int generate_secret(char *secret_b32, size_t secret_bytes_len, size_t secret_b32_len) {

    /* Vamos a usar libgcrypt para generar el secreto, 
        le ponemos GCRY_VERY_STRONG_RANDOM para generar 
        una clave de calidad */

    uint8_t key[secret_bytes_len];
    gcry_randomize(key, secret_bytes_len, GCRY_VERY_STRONG_RANDOM);

    /* Pasar el secreto a base32 */
    cotp_error_t err;
    char* base32 = base32_encode(key, secret_bytes_len, &err);

    
    if (base32 == NULL) {
        /* Si hubo algun error limpio memoria y salgo con error */
        explicit_bzero(key, secret_bytes_len);
        return 1;
    }

    /* Si no hubo error pongo en secret_b32 el resultado, cheqeuo tamanios */
    if (strlen(base32) >= secret_b32_len) {
        /* No entra en el buffer */
        explicit_bzero(key, secret_bytes_len);
        explicit_bzero(base32, strlen(base32));
        free(base32);
        return 1;
    }

    /* Copia el \0 que marca el final del string */
    strcpy(secret_b32, base32);

    /* Limpio la memorai de base32 y key */
    explicit_bzero(base32, strlen(base32));
    free(base32);
    explicit_bzero(key, secret_bytes_len);

    /* Salgo con exito */
    return 0;
}
