/*
    pam_tsi_authenticator.c
    Módulo PAM de segundo factor (TOTP) para el Taller de Seguridad Informática.
    Autores: Bruno Scanziani, Agustín Manganelli
*/

#define _GNU_SOURCE /* Obtener mas funciones como explicit_bzero para borrar datos de la    \
                       ram y que el compilador no lo optimice,                              \
                       O_NOFOLLOW para fallar si intento abrir un archivo que apunta a otro \
                       archivo/carpeta (util para cuando lea el secreto),                   \
                       seteuid/setegid para bajar privilegios temporalmente */

/* Necesito tipos y funciones que vienen de estos includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

/* pam modules para las funciones que hay que implementar, pam_ext para el log y la conversacion */
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "pam_tsi_authenticator.h"

/* ESTO PODRIA NO IR CREO */
#include "tsi_authenticator.h"

/* Parsea los argumentos hacia Params.
   Devuelve 0 si OK, -1 si hay argumentos desconocidos. */
static int parse_args(pam_handle_t *pamh, int argc, const char **argv, Params *params)
{
    for (int i = 0; i < argc; ++i)
    {
        if (strcmp(argv[i], "debug") == 0)
        {
            params->debug = 1;
        }
        else if (strcmp(argv[i], "nullok") == 0)
        {
            params->nullok = NULLOK;
        }
        else if (strncmp(argv[i], "secret=", 7) == 0)
        {
            params->secret_filename = argv[i] + 7;
        }
        else if (strncmp(argv[i], "digits=", 7) == 0)
        {
            params->digits = atoi(argv[i] + 7);
        }
        else if (strncmp(argv[i], "period=", 7) == 0)
        {
            params->period = atoi(argv[i] + 7);
        }
        else if (strncmp(argv[i], "window=", 7) == 0)
        {
            params->window = atoi(argv[i] + 7);
        }
        else
        {
            pam_syslog(pamh, LOG_ERR, "Argumento desconocido: %s", argv[i]);
            return -1;
        }
    }
    return 0;
}

/* Registra mensajes de diagnóstico que no contienen credenciales ni rutas sensibles. */
static void debug_log(pam_handle_t *pamh, const Params *params, const char *message)
{
    if (params->debug)
    {
        pam_syslog(pamh, LOG_DEBUG, "%s", message);
    }
}

/* Obtiene el uid y gid del usuario que se esta intentando autenticar 0 OK, -1 error. */
static int get_uid_gid(pam_handle_t *pamh, uid_t *uid, gid_t *gid)
{
    const char *username;
    const struct passwd *pwd;

    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS)
    {
        pam_syslog(pamh, LOG_ERR, "Error al obtener el nombre de usuario");
        return -1;
    }
    pwd = getpwnam(username);
    if (!pwd)
    {
        pam_syslog(pamh, LOG_ERR, "Usuario no encontrado: %s", username);
        return -1;
    }
    *uid = pwd->pw_uid;
    *gid = pwd->pw_gid;
    return 0;
}

/* Construye la ruta del archivo del secreto a partir del uid.
   Usa el override 'secret=' si se hY, si no <home>/SECRET_FILENAME. 0 OK, -1 error. */
static int get_secret_path(uid_t uid, const Params *params, char **path_out)
{
    if (params->secret_filename != NULL)
    {
        *path_out = strdup(params->secret_filename);
        return (*path_out != NULL) ? 0 : -1;
    }
    struct passwd *pwd;
    int len;

    pwd = getpwuid(uid);
    if (!pwd)
    {
        return -1;
    }
    len = strlen(pwd->pw_dir) + 1 + strlen(SECRET_FILENAME) + 1;
    *path_out = malloc(len);
    if (*path_out == NULL)
    {
        return -1;
    }
    snprintf(*path_out, len, "%s/%s", pwd->pw_dir, SECRET_FILENAME);
    return 0;
}

/* Baja la identidad de filesystem al usuario para no hacer cosas con root innecesariamente
   Guarda los valores previos para poder restaurar. 0 OK, -1 error. */
static int decrease_privileges(gid_t gid, uid_t uid, gid_t *old_gid, uid_t *old_uid)
{
    *old_gid = getegid();
    *old_uid = geteuid();

    if (setegid(gid) != 0)
    {
        return -1;
    }
    if (seteuid(uid) != 0)
    {
        (void)setegid(*old_gid);
        return -1;
    }
    return 0;
}

/* Restaura la identidad de filesystem previa */
static int restore_privileges(gid_t old_gid, uid_t old_uid)
{
    /* Primero recupera root; recién entonces puede restaurar el grupo. */
    if (seteuid(old_uid) != 0)
    {
        return -1;
    }
    if (setegid(old_gid) != 0)
    {
        return -1;
    }
    return 0;
}

/* Lee el secreto desde 'path'.
   found = 1 si el archivo existía y tenía contenido, 0 si no
   0 OK (incluso si no existe el archivo pero se deja pasar a los que no lo tengas), -1 error . */
static int get_secret_file(const char *path, char *secret_out, size_t out_size, int *found)
{
    FILE *file = fopen(path, "r");
    if (!file)
    {
        *found = 0;
        return 0; // No hay error, solo que no se encontró el archivo
    }

    *found = 1;
    if (fgets(secret_out, out_size, file) == NULL)
    {
        fclose(file);
        return -1;
    }
    char *p = strchr(secret_out, '=');
    if (p == NULL)
    {
        fclose(file);
        return -1;
    }

    memmove(secret_out, p + 1, strlen(p + 1) + 1);
    secret_out[strcspn(secret_out, "\r\n")] = '\0';
    fclose(file);
    return 0;
}

/* Le solicita al usuario que ingrese el token y lo almacena en digits
    0 OK, -1 error.*/
static int ask_for_token(pam_handle_t *pamh, Params *params, char *digits)
{
    (void)params;

    char *token = NULL;
    int rc = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &token, "Ingrese el token de 2FA: ");

    if (rc != PAM_SUCCESS || token == NULL)
        return -1;

    if (strlen(token) != DEFAULT_DIGITS)
    {
        explicit_bzero(token, strlen(token));
        free(token);
        return -1;
    }
    for (size_t i = 0; i < DEFAULT_DIGITS; ++i)
    {
        if (!isdigit((unsigned char)token[i]))
        {
            explicit_bzero(token, strlen(token));
            free(token);
            return -1;
        }
    }

    memcpy(digits, token, DEFAULT_DIGITS + 1);
    explicit_bzero(token, strlen(token));
    free(token);
    return 0;
}

/* Valida el codigo ingresado por el usuario. valid = 1 si el TOTP es correcto.
    0 OK (ejecuto, no implica valid = 1), -1 error. */
static int validate_pam_token(const Params *params, const char *secret_b32, const char *code, int *valid)
{
    return validate_token(secret_b32, code, (unsigned)params->window, valid);
}

/* Funcion principal que resuelve la autenticacion */
int tsi_authenticator(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags;
    (void)argc;
    (void)argv;

    Params params = {
        .debug = 0,
        .nullok = NULLERR,
        .secret_filename = NULL,
        .digits = DEFAULT_DIGITS,
        .period = DEFAULT_PERIOD,
        .window = DEFAULT_WINDOW};

    gid_t gid;
    uid_t uid;
    gid_t old_gid;
    uid_t old_uid;
    char *secret_path = NULL;
    char secret_b32[SECRET_B32_MAX] = {0};
    char code[DEFAULT_DIGITS + 1] = {0};
    int found = 0;
    int valid = 0;
    int validation_rc;
    int privileges_lowered = 0;
    int result = PAM_AUTH_ERR;

    if (parse_args(pamh, argc, argv, &params) != 0)
    {
        return PAM_AUTH_ERR;
    }
    debug_log(pamh, &params, "Argumentos del módulo procesados");

    if (get_uid_gid(pamh, &uid, &gid) != 0)
    {
        return PAM_AUTH_ERR;
    }
    debug_log(pamh, &params, "Usuario PAM resuelto correctamente");

    if (decrease_privileges(gid, uid, &old_gid, &old_uid) != 0)
    {
        pam_syslog(pamh, LOG_ERR, "No se pudieron reducir los privilegios efectivos");
        goto cleanup;
    }
    privileges_lowered = 1;
    debug_log(pamh, &params, "Privilegios efectivos reducidos para leer la configuración");

    if (get_secret_path(uid, &params, &secret_path) != 0)
    {
        debug_log(pamh, &params, "No se pudo construir la ruta de configuración");
        goto cleanup;
    }
    if (get_secret_file(secret_path, secret_b32, sizeof(secret_b32), &found) != 0)
    {
        debug_log(pamh, &params, "No se pudo leer la configuración TOTP");
        goto cleanup;
    }
    debug_log(pamh, &params, found ? "Configuración TOTP encontrada" : "Configuración TOTP no encontrada");

    if (restore_privileges(old_gid, old_uid) != 0)
    {
        pam_syslog(pamh, LOG_ERR, "No se pudieron restaurar los privilegios efectivos");
        goto cleanup;
    }
    privileges_lowered = 0;
    debug_log(pamh, &params, "Privilegios efectivos restaurados");

    if (!found)
    {
        if (params.nullok == NULLERR)
        {
            pam_syslog(pamh, LOG_ERR, "Usuario sin secreto y nullok = NULLERR, denegando acceso");
        }
        else
        {
            debug_log(pamh, &params, "Acceso permitido por nullok");
            result = PAM_SUCCESS;
        }
        goto cleanup;
    }

    debug_log(pamh, &params, "Solicitando código TOTP");
    if (ask_for_token(pamh, &params, code) != 0)
    {
        debug_log(pamh, &params, "No se recibió un código TOTP válido");
        goto cleanup;
    }
    debug_log(pamh, &params, "Código TOTP recibido");

    validation_rc = validate_pam_token(&params, secret_b32, code, &valid);
    if (validation_rc != 0)
    {
        debug_log(pamh, &params, "Error interno durante la validación TOTP");
        goto cleanup;
    }
    if (!valid)
    {
        debug_log(pamh, &params, "Código TOTP rechazado");
        goto cleanup;
    }

    debug_log(pamh, &params, "Código TOTP aceptado");
    result = PAM_SUCCESS;

cleanup:
    if (privileges_lowered && restore_privileges(old_gid, old_uid) != 0)
    {
        pam_syslog(pamh, LOG_ERR, "No se pudieron restaurar los privilegios durante la limpieza");
        result = PAM_AUTH_ERR;
    }
    free(secret_path);
    explicit_bzero(secret_b32, sizeof(secret_b32));
    explicit_bzero(code, sizeof(code));
    return result;
}

/* Funciones auth de pam */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return tsi_authenticator(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
