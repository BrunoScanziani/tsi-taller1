/* Inicializa una unica clave maestra y conserva una existente segura. */
#define _GNU_SOURCE
#include "tsi_key_init.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define GCRYPT_MIN_VERSION "1.8.0"

/* Escribe todos los bytes del buffer en el descriptor de archivo, manejando interrupciones. Devuelve 0 si OK, -1 si error. */
static int write_all(int fd, const unsigned char *buffer, size_t len)
{
    size_t written = 0;
    while (written < len)
    {
        ssize_t bytes = write(fd, buffer + written, len - written);
        if (bytes > 0)
            written += (size_t)bytes;
        else if (bytes < 0 && errno == EINTR)
            continue;
        else
            return -1;
    }
    return 0;
}
/*
    Asegura que el directorio de claves exista y sea seguro.
*/
static int ensure_key_dir(void)
{
    struct stat st;
    if (mkdir(TSI_KEY_DIR, 0700) != 0 && errno != EEXIST) // crea el directorio si no existe
        return -1;
    if (lstat(TSI_KEY_DIR, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & 077) != 0) // verifica que sea un directorio seguro
        return -1;
    return 0;
}

/* Verifica que la clave maestra existente sea segura: archivo regular, propietario root, tamaño correcto, permisos 0400. */
static int existing_key_is_safe(void)
{
    struct stat st;
    if (lstat(MASTER_KEY_PATH, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != 0 || st.st_size != MASTER_KEY_SIZE ||
        (st.st_mode & 077) != 0)
        return -1;
    return 0;
}

int main(void)
{
    unsigned char master_key[MASTER_KEY_SIZE];
    int fd = -1, rc = EXIT_FAILURE;

    if (geteuid() != 0)
    {
        fprintf(stderr, "tsi-key-init: debe ejecutarse como root\n");
        goto cleanup;
    }
    umask(077);
    if (!gcry_check_version(GCRYPT_MIN_VERSION))
    {
        fprintf(stderr, "tsi-key-init: version de libgcrypt incompatible\n");
        goto cleanup;
    }
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    if (ensure_key_dir() != 0)
    {
        fprintf(stderr, "tsi-key-init: directorio de claves inseguro\n");
        goto cleanup;
    }

    fd = open(MASTER_KEY_PATH, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0400); // lo crea si no existe, con permisos 0400 (solo root puede leer)
    if (fd < 0)
    {
        if (errno == EEXIST && existing_key_is_safe() == 0)
            rc = EXIT_SUCCESS;
        else
            fprintf(stderr, "tsi-key-init: no se pudo crear una clave maestra segura\n");
        goto cleanup;
    }
    if (fchmod(fd, 0400) != 0)
        goto remove_partial_key;
    gcry_randomize(master_key, sizeof(master_key), GCRY_STRONG_RANDOM);
    if (write_all(fd, master_key, sizeof(master_key)) != 0 || fsync(fd) != 0)
    {
        goto remove_partial_key;
    }
    if (close(fd) != 0)
    {
        fd = -1;
        goto remove_partial_key;
    }
    fd = -1;
    rc = EXIT_SUCCESS;
    goto cleanup;

remove_partial_key:
    if (fd >= 0)
    {
        (void)close(fd);
        fd = -1;
    }
    (void)unlink(MASTER_KEY_PATH);
    fprintf(stderr, "tsi-key-init: no se pudo guardar la clave maestra\n");
cleanup:
    if (fd >= 0)
        (void)close(fd);
    explicit_bzero(master_key, sizeof(master_key));
    return rc;
}
