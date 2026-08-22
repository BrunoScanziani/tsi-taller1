#define _GNU_SOURCE

#include "tsi_authenticator.h"
#include <cotp.h>
#include <time.h>
#include <string.h>
#include <gcrypt.h>
#include <pwd.h>
#include <sys/types.h>
#include <limits.h> /* Para el tamanio del nombre de usuario cuando voy a leer */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#define ISSUER "TSI"
#define URI_MAX 256
#define GCRYPT_MIN_VERSION "1.8.0"

/* Funcion que valida un código TOTP.
 *valid = 1 si el código coincide con alguno. Devuelve 0 si ejecutó, -1 si hubo error. */
int validate_token(const char *secret_b32, const char *code, unsigned window, int *valid)
{
    /* Comienzo pesimista */
    *valid = 0;

    long now = (long)time(NULL);       /* Tiempo actual */
    long block = now / DEFAULT_PERIOD; /* Bloque de 30 s en el que estamos */
    int half = window / 2;             /* cant de bloques hacia atrás y adelante */

    /* Recorro cada bloque de la ventana */
    for (int i = -half; i <= half; i++)
    {

        /* Timestamp representativo del bloque (block + i) */
        long timestamp = (block + i) * (long)DEFAULT_PERIOD;

        /* Calculo el código de ese bloque*/
        cotp_error_t err;
        char *calculated_code = get_totp_at(secret_b32, timestamp, DEFAULT_DIGITS, DEFAULT_PERIOD, COTP_SHA1, &err);

        /* Error de libcotp, salgo con error */
        if (calculated_code == NULL || err != NO_ERROR)
        {
            if (calculated_code)
            {
                free(calculated_code);
            }
            return -1;
        }

        /* Comparo con el código ingresado */
        if (strcmp(code, calculated_code) == 0)
        {
            /* Si coincide libero y salgo */
            explicit_bzero(calculated_code, strlen(calculated_code));
            free(calculated_code);
            *valid = 1;
            return 0;
        }

        /* si no coincide libero y sigo con el próximo bloque */
        explicit_bzero(calculated_code, strlen(calculated_code));
        free(calculated_code);
    }

    /* Recorri toda la ventana sin coincidencia *valid queda en 0 y salgo sin error */
    return 0;
}

/* Funcion encargada de generar un secreto de largo SECRET_BITS_NUMBER retorna 0 si ok, -1 si error */
int generate_secret(char *secret_b32, size_t secret_bytes_len, size_t secret_b32_len)
{

    /* Vamos a usar libgcrypt para generar el secreto,
        le ponemos GCRY_VERY_STRONG_RANDOM para generar
        una clave de calidad */

    uint8_t key[secret_bytes_len];
    gcry_randomize(key, secret_bytes_len, GCRY_VERY_STRONG_RANDOM);

    /* Pasar el secreto a base32 */
    cotp_error_t err;
    char *base32 = base32_encode(key, secret_bytes_len, &err);

    if (base32 == NULL)
    {
        /* Si hubo algun error limpio memoria y salgo con error */
        explicit_bzero(key, secret_bytes_len);
        return -1;
    }

    /* Si no hubo error pongo en secret_b32 el resultado, cheqeuo tamanios */
    if (strlen(base32) >= secret_b32_len)
    {
        /* No entra en el buffer */
        explicit_bzero(key, secret_bytes_len);
        explicit_bzero(base32, strlen(base32));
        free(base32);
        return -1;
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

int build_otpauth_uri(char *uri_out, size_t uri_size, const char *issuer, const char *user, const char *secret_b32, unsigned digits, unsigned period)
{

    int n = snprintf(uri_out, uri_size, "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%u&period=%u", issuer, user, secret_b32, issuer, digits, period);

    /* snprintf devuelve cuántos caracteres escribio (no cuenta el \0)
       Si ese número es negativo o >= uri_size hubo algun problema */
    if (n < 0 || (size_t)n >= uri_size)
        return -1;

    return 0;
}

/* Recibe el URI ya armado y lo muestra como QR en la terminal. 0 OK, -1 error. */
int generate_qr(const char *uri)
{

    /* Abro qrencode */
    FILE *qr = popen("qrencode -t ANSIUTF8 -o -", "w");
    if (qr == NULL)
        return -1;

    /* Le escribo el uri por su stdin */
    fprintf(qr, "%s\n", uri);

    /* Cierro qrencode pclose devuelve el estado de salida del comando */
    int status = pclose(qr);
    if (status != 0)
        return -1;

    return 0;
}

/* Obtiene el nombre del usuario actual (para el label del URI). 0 OK, -1 error. */
int get_current_username(char *user_out, size_t user_size)
{
    /* Estructura donde voy a obtener la info */
    struct passwd pw, *res = NULL;

    /* Esta es la forma de obtener el tamaño de buffer para leer de passwd, cosas de linux */
    long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);

    /* Si anduvo mal le pongo un valor yo */
    if (bufsize <= 0)
    {
        bufsize = 4096;
    }

    /* Guardo espacio para leer datos del archivo */
    char *buf = malloc(bufsize);
    if (!buf)
    {
        return -1;
    }

    /* Obtengo infomracion identificado por el uid del usuario que ejecuta el binario */
    if (getpwuid_r(getuid(), &pw, buf, bufsize, &res) != 0 || res == NULL)
    {
        free(buf);
        return -1;
    }

    /* Si el largo del nombre es mayor al que yo reserve salgo con error*/
    if (strlen(pw.pw_name) >= user_size)
    {
        free(buf);
        return -1;
    }

    /* Si todo anduvo bien, obtengo el nombre, libero memoria y salgo */
    strcpy(user_out, pw.pw_name);
    free(buf);
    return 0;
}

/* Construye <home>/SECRET_FILENAME para guardar el secreto. 0 OK, -1 error. */
int build_secret_path(char *path_out, size_t path_size)
{
    /* Estructura donde voy a obtener la info */
    struct passwd pw, *res = NULL;

    /* Lo mismo que en la funcion de obtener el nombre de usuario */
    long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize <= 0)
    {
        bufsize = 4096;
    }

    char *buf = malloc(bufsize);
    if (!buf)
        return -1;

    /* Obtengo el directrio home del usuario */
    if (getpwuid_r(getuid(), &pw, buf, bufsize, &res) != 0 || res == NULL)
    {
        free(buf);
        return -1;
    }

    /* Control de errores, chequeo que no sea null y que comienze con /, desde la raiz */
    if (!pw.pw_dir || pw.pw_dir[0] != '/')
    {
        free(buf);
        return -1;
    }

    /* Escribo en path_out la ruta con el nuevo archivo */
    int n = snprintf(path_out, path_size, "%s/%s", pw.pw_dir, SECRET_FILENAME);
    free(buf);
    if (n < 0 || (size_t)n >= path_size)
    {
        return -1;
    }

    return 0;
}

/* Funcion que guarda el secreto en el home del usuario, crea el archivo */
int save_secret(const char *path, const char *secret_b32, unsigned window, unsigned rate_limit)
{
    /* Creo el archivo en el home. Los parametron son para:
        O_WEONLY: abrir en modo escritura solamente
        O_CREATE: crear el archivo si no existe
        O_TRUNC: borra todo lo que habia antes, si es que habia (como lo estoy creando no deberia)
        O_NOFOLLOW: esto es para no seguir links a otros archivos, por seguridad
        O_CLOEXEC: cerrar este archivo inmediatamente si este bianrio ejecuta exec para crear un nuevo programa, seguridad
        0600 los permisos, solo el usuario dueño tiene rw-, el resto grupo y otros no tienen nada */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
    {
        return -1;
    }

    /* Esto es para asegurar que los permisos sean efecitvamente 0600, aunque la unmask que el sistema
        usa en el open haya tenido valores raros */
    if (fchmod(fd, 0600) != 0)
    {
        close(fd);
        return -1;
    }

    /* El fdopen es para escribir con fprintf, mas facil escribir los valores */
    FILE *f = fdopen(fd, "w");
    if (!f)
    {
        close(fd);
        return -1;
    }

    /* Escribo los valores en el archivo */
    int n = fprintf(f, "%s=%s\n%s=%u\n%s=%u\n",
                    SECRET_KEY, secret_b32,
                    WINDOW_KEY, window,
                    RATE_LIMIT_KEY, rate_limit);

    /* Chequeo si se escrbio bien */
    if (n < 0)
    {
        fclose(f);
        return -1;
    }

    /* fclose ya cierra el open del principip tambien, chequeo que cierre bien */
    if (fclose(f) != 0)
    {
        return -1;
    }

    return 0;
}

/* Borra el archivo del secreto 0 OK, -1 error. */
int delete_secret(const char *path)
{
    if (unlink(path) != 0)
    {
        if (errno == ENOENT)
        {
            return 0; /* no existia el objeto, no devuelvo error */
        }
        return -1; /* hubo un error */
    }
    return 0;
}
