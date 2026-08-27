/*
    tsi_config_init.c
    Helper setuid-root que crea el archivo root-only de config+estado del usuario
    que lo ejecuta: <TSI_STATE_DIR>/<uid>_tsi_config, propiedad de root, 0600.

    Se instala setuid root y lo invoca tsi-enroll tras confirmar el vinculo.

    Reglas de seguridad (corre como root, invocado por un usuario sin privilegios):
      - El uid objetivo se toma de getuid() (el uid REAL), nunca de un argumento:
        un usuario solo puede crear SU propio archivo.
      - La ruta se arma con la constante compilada TSI_STATE_DIR; se ignoran
        argumentos y variables de entorno.
      - No usa el entorno, ni popen/system. umask restrictiva.
      - El archivo se crea con O_EXCL: si ya existe no se toca (no resetea el
        estado ni la politica de un usuario ya enrolado).

    Autores: Bruno Scanziani, Agustin Manganelli
*/

#define _GNU_SOURCE

#include "tsi_authenticator.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(void)
{
    /* No confiamos en el entorno ni en la umask heredada. */
    umask(077);

    /* El objetivo es SIEMPRE el usuario real que ejecuta el helper. */
    uid_t uid = getuid();

    /* Valores por defecto del .h (la politica no la elige el usuario). */
    AuthState state = {
        .window = DEFAULT_WINDOW,
        .rate_limit = RATE_LIMIT,
        .lock_time = TIEMPO_RATE_LIMIT,
        .fail_count = 0,
        .locked_until = 0};

    /* Aseguro el directorio root-only (se crea como root, 0700). */
    if (ensure_state_dir(TSI_STATE_DIR) != 0) {
        fprintf(stderr, "tsi-config-init: no se pudo preparar %s\n", TSI_STATE_DIR);
        return EXIT_FAILURE;
    }

    char path[PATH_MAX];
    if (build_state_path(uid, path, sizeof(path)) != 0) {
        fprintf(stderr, "tsi-config-init: no se pudo construir la ruta del config\n");
        return EXIT_FAILURE;
    }

    int rc = create_config_file(path, &state);
    if (rc < 0) {
        fprintf(stderr, "tsi-config-init: no se pudo crear el config\n");
        return EXIT_FAILURE;
    }
    /* rc == 1: ya existia; se conserva (re-enrolamiento). Es exito para el llamador. */
    return EXIT_SUCCESS;
}
