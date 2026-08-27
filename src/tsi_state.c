/*
    tsi_state.c
    Funciones compartidas para el archivo root-only de config+estado por usuario.
    Sin dependencias de crypto: lo linkea tambien el helper setuid tsi-config-init,
    asi su superficie de ataque queda minima.
    Autores: Bruno Scanziani, Agustin Manganelli
*/

#define _GNU_SOURCE

#include "tsi_authenticator.h"

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Construye <TSI_STATE_DIR>/<uid>_tsi_config en 'buf'. Ruta fija, sin overrides. */
int build_state_path(uid_t uid, char *buf, size_t size)
{
    int n = snprintf(buf, size, "%s/%u%s", TSI_STATE_DIR, (unsigned)uid, STATE_FILE_SUFFIX);
    if (n < 0 || (size_t)n >= size) {
        return -1;
    }
    return 0;
}

/* Crea el directorio con permisos 0700 si no existe. */
int ensure_state_dir(const char *dir)
{
    if (mkdir(dir, 0700) == 0) {
        return 0;
    }
    return (errno == EEXIST) ? 0 : -1;
}

/* Crea el archivo de config+estado con los valores de 'state'.
   Usa O_EXCL: si ya existe no lo toca (no pisa config ni estado previos).
   0 = creado, 1 = ya existia, -1 = error. */
int create_config_file(const char *path, const AuthState *state)
{
    if (path == NULL || state == NULL) {
        return -1;
    }

    /* O_EXCL: falla si existe. O_NOFOLLOW: no seguir symlinks. O_CLOEXEC: no heredar. */
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        if (errno == EEXIST) {
            return 1;   /* ya existia: se conserva */
        }
        return -1;
    }

    /* Refuerzo los permisos por si la umask heredada dejo algo raro. */
    if (fchmod(fd, 0600) != 0) {
        close(fd);
        unlink(path);
        return -1;
    }

    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        unlink(path);
        return -1;
    }

    int n = fprintf(f, "%s=%u\n%s=%u\n%s=%u\n%s=%u\n%s=%ld\n",
                    WINDOW_KEY, state->window,
                    RATE_LIMIT_KEY, state->rate_limit,
                    LOCK_TIME_KEY, state->lock_time,
                    FAIL_COUNT_KEY, state->fail_count,
                    LOCKED_UNTIL_KEY, state->locked_until);
    if (n < 0) {
        fclose(f);
        unlink(path);
        return -1;
    }
    if (fclose(f) != 0) {
        unlink(path);
        return -1;
    }
    return 0;
}
