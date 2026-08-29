/*
    Codigo de la aplicacion para compartir el secreto entre
    el usuario y el sistema
*/


#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <gcrypt.h>
#include "tsi_authenticator.h"

#define ISSUER      "TSI"
#define URI_MAX     256
#define GCRYPT_MIN_VERSION "1.8.0"
#define HELPER_PATH "/usr/local/bin/tsi-config-init"
#define SEED_CRYPTO_PATH "/usr/local/bin/tsi-seed-crypto"
#define ENCRYPTED_BLOB_MAX (1 + 12 + 16 + SECRET_B32_MAX)

/* Ejecuta el helper setuid que crea el archivo de config root-only del usuario.
   0 si el helper salio con exito, -1 en cualquier otro caso. */
static int create_user_config(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        /* Hijo: ejecuta el helper. Sin argumentos: toma el uid del proceso. */
        execl(HELPER_PATH, "tsi-config-init", (char *)NULL);
        _exit(127);   /* solo se llega si execl fallo */
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* Pasa el seed al helper por stdin y recoge su blob binario por stdout. */
static int encrypt_seed_with_helper(const char *seed, unsigned char *blob,
                                    size_t blob_capacity, size_t *blob_len)
{
    int input_pipe[2], output_pipe[2];
    pid_t pid;
    size_t seed_len = strlen(seed);
    size_t received = 0;

    if (pipe(input_pipe) != 0 || pipe(output_pipe) != 0)
        return -1;
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        close(input_pipe[1]);
        close(output_pipe[0]);
        if (dup2(input_pipe[0], STDIN_FILENO) < 0 ||
            dup2(output_pipe[1], STDOUT_FILENO) < 0)
            _exit(127);
        close(input_pipe[0]);
        close(output_pipe[1]);
        execl(SEED_CRYPTO_PATH, "tsi-seed-crypto", (char *)NULL);
        _exit(127);
    }

    close(input_pipe[0]);
    close(output_pipe[1]);
    if (write(input_pipe[1], seed, seed_len) != (ssize_t)seed_len ||
        write(input_pipe[1], "\n", 1) != 1) {
        close(input_pipe[1]);
        close(output_pipe[0]);
        waitpid(pid, NULL, 0);
        return -1;
    }
    close(input_pipe[1]);

    while (received < blob_capacity) {
        ssize_t n = read(output_pipe[0], blob + received, blob_capacity - received);
        if (n > 0) received += (size_t)n;
        else if (n == 0) break;
        else if (errno != EINTR) {
            close(output_pipe[0]);
            waitpid(pid, NULL, 0);
            return -1;
        }
    }
    close(output_pipe[0]);
    int status;
    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0 || received == 0 || received == blob_capacity)
        return -1;
    *blob_len = received;
    return 0;
}

/* Funcion main que ejecuta el hilo principal */
int main() {

    /* Variables que voy a usar */
    char user[LOGIN_NAME_MAX + 1];                  /* Buffer para el nombre del usuario */
    char path[PATH_MAX];                            /* Buffer para crear el path del secreto */
    char secret_b32[SECRET_B32_MAX];                /* Buffer para almacenar el secreto en base32 */
    size_t secret_bytes = SECRET_BITS_NUMBER / 8;   /* 160 bits / 8 = 20 bytes */
    char uri[URI_MAX];                              /* Buffer para el uri del qr */
    unsigned char encrypted_blob[ENCRYPTED_BLOB_MAX] = {0};
    size_t encrypted_blob_len = 0;

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

        return EXIT_SUCCESS;
    }

    /* El seed no se persiste en claro: el helper setuid devuelve un blob binario GCM. */
    if (encrypt_seed_with_helper(secret_b32, encrypted_blob, sizeof(encrypted_blob),
                                 &encrypted_blob_len) != 0 ||
        save_encrypted_secret(path, encrypted_blob, encrypted_blob_len) != 0) {
        fprintf(stderr, "Error: no se pudo cifrar y guardar el secreto\n");
        explicit_bzero(secret_b32, sizeof(secret_b32));
        explicit_bzero(uri, sizeof(uri));
        explicit_bzero(encrypted_blob, sizeof(encrypted_blob));
        return EXIT_FAILURE;
    }

    /* Vinculo confirmado: creo el archivo de config root-only via el helper setuid.
       Si falla, borro el secreto para no dejar un enrolamiento a medias. */
    if (create_user_config() != 0) {
        fprintf(stderr, "Error: no se pudo crear la configuración del sistema para el 2FA\n");
        explicit_bzero(secret_b32, sizeof(secret_b32));
        explicit_bzero(uri, sizeof(uri));
        delete_secret(path);
        explicit_bzero(encrypted_blob, sizeof(encrypted_blob));
        return EXIT_FAILURE;
    }

    /* Sobreescribir memoria sensible */
    explicit_bzero(secret_b32, sizeof(secret_b32));
    explicit_bzero(uri, sizeof(uri));
    explicit_bzero(encrypted_blob, sizeof(encrypted_blob));

    return EXIT_SUCCESS;
}
