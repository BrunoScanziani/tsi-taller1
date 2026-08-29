#define _GNU_SOURCE

#include "tsi_authenticator.h"
#include "tsi_key_init.h"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <gcrypt.h>
/* Formato v1 del blob que el helper devuelve por stdout. */
#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE 16

/*
 * Lee un seed Base32 desde stdin en un buffer de tamano fijo.
 * Debe rechazar entrada vacia, demasiado larga o con datos luego del '\n'.
 */
static int read_seed_from_stdin(char seed[SECRET_B32_MAX])
{
    if (fgets(seed, SECRET_B32_MAX, stdin) == NULL)
    {
        return -1; // error al leer
    }
    size_t len = strcspn(seed, "\r\n"); // longitud hasta el primer salto de linea
    if (len == 0 || len >= SECRET_B32_MAX - 1)
    {
        return -1; // vacio o demasiado largo
    }
    seed[len] = '\0'; // reemplazo el salto de linea por null terminator
    return 0;
};

/* Verifica que seed tenga exclusivamente caracteres Base32 permitidos. */
static int validate_seed(const char *seed)
{
    for (const char *p = seed; *p != '\0'; ++p)
    {
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= '2' && *p <= '7')))
        {
            return -1; // caracter no permitido
        }
    }
    return 0;
};

/* Lee exactamente MASTER_KEY_SIZE bytes de MASTER_KEY_PATH. */
static int read_master_key(unsigned char master_key[MASTER_KEY_SIZE])
{
    struct stat st;
    int fd = open(MASTER_KEY_PATH, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != 0 || st.st_size != MASTER_KEY_SIZE) {
        if (fd >= 0) close(fd);
        return -1;
    }
    size_t read_bytes = 0;
    while (read_bytes < MASTER_KEY_SIZE) {
        ssize_t n = read(fd, master_key + read_bytes, MASTER_KEY_SIZE - read_bytes);
        if (n > 0) read_bytes += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else { close(fd); return -1; }
    }
    return close(fd) == 0 ? 0 : -1;
};

/* Construye los datos autenticados: version de formato + UID real del invocador. */
static int build_aad(uid_t uid, unsigned char *aad, size_t aad_capacity,
                     size_t *aad_len)
{
    if (aad_capacity < sizeof(uint32_t) + 1)
    {
        return -1; // buffer insuficiente
    }
    aad[0] = 1; // version del formato
    uint32_t uid_net = htonl((uint32_t)uid);
    memcpy(aad + 1, &uid_net, sizeof(uid_net));
    *aad_len = sizeof(uint32_t) + 1;
    return 0;
};

/* Cifra seed con AES-256-GCM y genera nonce aleatorio y tag de autenticacion. */
static int encrypt_seed(const char *seed,
                        const unsigned char master_key[MASTER_KEY_SIZE],
                        const unsigned char *aad, size_t aad_len,
                        unsigned char nonce[GCM_NONCE_SIZE],
                        unsigned char tag[GCM_TAG_SIZE],
                        unsigned char *ciphertext, size_t ciphertext_capacity,
                        size_t *ciphertext_len)
{
    gcry_cipher_hd_t cipher;
    if (gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0) != 0)
    {
        return -1; // error al abrir el cifrador
    }
    if (gcry_cipher_setkey(cipher, master_key, MASTER_KEY_SIZE) != 0)
    {
        gcry_cipher_close(cipher);
        return -1; // error al establecer la clave
    }
    gcry_randomize(nonce, GCM_NONCE_SIZE, GCRY_STRONG_RANDOM);
    if (gcry_cipher_setiv(cipher, nonce, GCM_NONCE_SIZE) != 0)
    {
        gcry_cipher_close(cipher);
        return -1; // error al establecer el IV
    }
    if (gcry_cipher_authenticate(cipher, aad, aad_len) != 0)
    {
        gcry_cipher_close(cipher);
        return -1; // error al autenticar los datos
    }
    size_t seed_len = strlen(seed);
    if (ciphertext_capacity < seed_len)
    {
        gcry_cipher_close(cipher);
        return -1; // buffer de salida insuficiente
    }
    if (gcry_cipher_encrypt(cipher, ciphertext, seed_len, (const unsigned char *)seed, seed_len) != 0)
    {
        gcry_cipher_close(cipher);
        return -1; // error al cifrar
    }
    if (gcry_cipher_gettag(cipher, tag, GCM_TAG_SIZE) != 0)
    {
        gcry_cipher_close(cipher);
        return -1; // error al obtener el tag
    }
    *ciphertext_len = seed_len;
    gcry_cipher_close(cipher);
    return 0;
};

/* Escribe por stdout solo el blob VERSION/NONCE/TAG/CIPHERTEXT, nunca el seed. */
static int write_encrypted_blob(const unsigned char nonce[GCM_NONCE_SIZE],
                                const unsigned char tag[GCM_TAG_SIZE],
                                const unsigned char *ciphertext,
                                size_t ciphertext_len)
{
    size_t total_len = 1 + GCM_NONCE_SIZE + GCM_TAG_SIZE + ciphertext_len;
    unsigned char *blob = malloc(total_len);
    if (blob == NULL)
    {
        return -1; // error de memoria
    }
    blob[0] = 1; // version del formato
    memcpy(blob + 1, nonce, GCM_NONCE_SIZE);
    memcpy(blob + 1 + GCM_NONCE_SIZE, tag, GCM_TAG_SIZE);
    memcpy(blob + 1 + GCM_NONCE_SIZE + GCM_TAG_SIZE, ciphertext, ciphertext_len);
    if (fwrite(blob, 1, total_len, stdout) != total_len)
    {
        free(blob);
        return -1; // error al escribir
    }
    free(blob);
    return 0;
};

/* Punto de entrada: obtiene el UID real, cifra y devuelve el blob. */
int main(void)
{
    uid_t uid = getuid();
    char seed[SECRET_B32_MAX] = {0};
    unsigned char master_key[MASTER_KEY_SIZE] = {0};
    unsigned char aad[sizeof(uint32_t) + 1] = {0};
    size_t aad_len = 0;
    unsigned char nonce[GCM_NONCE_SIZE] = {0};
    unsigned char tag[GCM_TAG_SIZE] = {0};
    unsigned char ciphertext[SECRET_B32_MAX] = {0};
    size_t ciphertext_len = 0;

    if (geteuid() != 0 || uid == 0)
    {
        fprintf(stderr, "tsi-seed-crypto: requiere setuid-root y un usuario no root\n");
        goto cleanup;
    }
    if (!gcry_check_version("1.8.0")) goto cleanup;
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    if (read_seed_from_stdin(seed) != 0)
    {
        fprintf(stderr, "tsi-seed-crypto: error al leer el seed\n");
        goto cleanup;
    }
    if (validate_seed(seed) != 0)
    {
        fprintf(stderr, "tsi-seed-crypto: seed no válido\n");
        goto cleanup;
    }
    if (read_master_key(master_key) != 0)
    {
        fprintf(stderr, "tsi-seed-crypto: error al leer la clave maestra\n");
        goto cleanup;
    }

    if (build_aad(uid, aad, sizeof(aad), &aad_len) != 0)
    {
        fprintf(stderr, "tsi-seed-crypto: error al construir AAD\n");
        goto cleanup;
    }
    if (encrypt_seed(seed, master_key, aad, aad_len,
                     nonce, tag, ciphertext, sizeof(ciphertext), &ciphertext_len) != 0)
    {
        fprintf(stderr, "tsi-seed-crypto: error al cifrar el seed\n");
        goto cleanup;
    }
    if (write_encrypted_blob(nonce, tag, ciphertext, ciphertext_len) != 0)
    {
        fprintf(stderr, "tsi-seed-crypto: error al escribir el blob cifrado\n");
        goto cleanup;
    }

    explicit_bzero(seed, sizeof(seed));
    explicit_bzero(master_key, sizeof(master_key));
    explicit_bzero(ciphertext, sizeof(ciphertext));
    return EXIT_SUCCESS;
cleanup:
    explicit_bzero(seed, sizeof(seed));
    explicit_bzero(master_key, sizeof(master_key));
    explicit_bzero(ciphertext, sizeof(ciphertext));
    return EXIT_FAILURE;
}
