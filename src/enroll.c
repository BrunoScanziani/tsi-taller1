/*
    Codigo de la aplicacion para compartir el secreto entre
    el usuario y el sistema
*/


#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <gcrypt.h>
#include "tsi_authenticator.h"

#define ISSUER      "TSI"
#define URI_MAX     256
#define GCRYPT_MIN_VERSION "1.8.0"

/* Funcion main que ejecuta el hilo principal */
int main() {

    /* Variables que voy a usar */
    char user[LOGIN_NAME_MAX + 1];                  /* Buffer para el nombre del usuario */
    char path[PATH_MAX];                            /* Buffer para crear el path del secreto */
    char secret_b32[SECRET_B32_MAX];                /* Buffer para almacenar el secreto en base32 */
    size_t secret_bytes = SECRET_BITS_NUMBER / 8;   /* 160 bits / 8 = 20 bytes */
    char uri[URI_MAX];                              /* Buffer para el uri del qr */

    /* Inicializar libgcrypt  */
    if (!gcry_check_version(GCRYPT_MIN_VERSION)) {
        fprintf(stderr, "Error: versión de libgcrypt incorrecta\n");
        return EXIT_FAILURE;
    }
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    /* Obtener usuario y ruta del secreto */
    if (get_current_username(user, sizeof(user)) != 0) {
        fprintf(stderr, "Error: no se pudo obtener el nombre de usuario\n");
        return EXIT_FAILURE;
    }
    if (build_secret_path(path, sizeof(path)) != 0) {
        fprintf(stderr, "Error: no se pudo construir la ruta del secreto\n");
        return EXIT_FAILURE;
    }

    /* Generar el secreto */
    if (generate_secret(secret_b32, secret_bytes, sizeof(secret_b32)) != 0) {
        fprintf(stderr, "Error: no se pudo generar el secreto\n");
        return EXIT_FAILURE;
    }

    /* Guardar el secreto y la config con window y rate limit en su valor default */
    if (save_secret(path, secret_b32, DEFAULT_WINDOW, RATE_LIMIT) != 0) {
        fprintf(stderr, "Error: no se pudo guardar el secreto\n");

        /* Sobreescribo la memoria del secreto antes de salir */
        explicit_bzero(secret_b32, sizeof(secret_b32));
        return EXIT_FAILURE;
    }

    /* Construyo el uri que despues paso a qr para la app */
    if (build_otpauth_uri(uri, sizeof(uri), ISSUER, user, secret_b32, DEFAULT_DIGITS, DEFAULT_PERIOD) != 0) {
        fprintf(stderr, "Error: no se pudo construir el URI\n");

        /* Sobreescribo la memoria del secreto antes de salir */
        explicit_bzero(secret_b32, sizeof(secret_b32));
        return EXIT_FAILURE;
    }

    /*  Mostrar el qr y el secreto para que lo vincule */
    printf("\nEscaneá este QR con tu app autenticadora (Aegis/FreeOTP, 8 digitos):\n\n");
    if (generate_qr(uri) != 0) {
        fprintf(stderr, "Aviso: no se pudo generar el QR\n");
    }
    printf("\nO ingresá manualmente el secreto: %s\n", secret_b32);

    /* Pedir que ingrese el codigo para chequear que se vinculo bien */
    printf("\nIngresá un código de tu app.\n");

    /* Prubeo RATE_LIMIT veces */
    int verified = 0;
    for (int try = 1; try <= RATE_LIMIT && !verified; try++) {
        char code[DEFAULT_DIGITS + 2];                  /* El +2 es para el salto de linea y el retorno de carro */

        if (fgets(code, sizeof(code), stdin) == NULL) { /* error de lectura */
            fprintf(stderr, "Error: error de lectura \n"); 

            /* Sobreescribir memoria sensible */
            explicit_bzero(secret_b32, sizeof(secret_b32));
            explicit_bzero(uri, sizeof(uri));
            explicit_bzero(code, sizeof(code));

            return EXIT_FAILURE;                          
        }

        code[strcspn(code, "\n")] = '\0';   /* saco el salto de linea */

        int valid = 0;
        if (validate_token(secret_b32, code, DEFAULT_WINDOW, &valid) != 0) { /* error en la validacion */
            fprintf(stderr, "Error al validar el código\n");
            
            /* Sobreescribir memoria sensible */
            explicit_bzero(secret_b32, sizeof(secret_b32));
            explicit_bzero(uri, sizeof(uri));
            explicit_bzero(code, sizeof(code));
            
            return EXIT_FAILURE;
        }

        if (valid) {
            verified = 1;
        } else {
            printf("Código incorrecto.\n");
        }

        explicit_bzero(code, sizeof(code));  /* limpio el codigo */
    }

    if (!verified) {
        fprintf(stderr, "\nNo se pudo verificar el vínculo\n");
        
        /* Sobreescribir memoria sensible */
        explicit_bzero(secret_b32, sizeof(secret_b32));
        explicit_bzero(uri, sizeof(uri));

        if (delete_secret(path) != 0) {     /* Error al borrar */
              return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }


    /* Sobreescribir memoria sensible */
    explicit_bzero(secret_b32, sizeof(secret_b32));
    explicit_bzero(uri, sizeof(uri));

    return EXIT_SUCCESS;
}