/*
    pam_tsi_authenticator.c
    Módulo PAM de segundo factor (TOTP) para el Taller de Seguridad Informática.
    Autores: Bruno Scanziani, Agustín Manganelli
*/

#define _GNU_SOURCE /* Obtener mas funciones como explicit_bzero para borrar datos de la    \
                       ram y que el compilador no lo optimice,                              \
                       O_NOFOLLOW para fallar si intento abrir un archivo que apunta a otro \
                       archivo/carpeta (util para cuando lea el secreto),                   \
                       setfsuid/setfsgid  para bajar privilegios de uso de file system*/

/* Necesito tipos y funciones que vienen de estos includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fsuid.h>
#include <syslog.h>

/* pam modules para las funciones que hay que implementar, pam_ext para el log y la conversacion */
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "pam_tsi_authenticator.h"

/* ESTO PODRIA NO IR CREO */
#include "tsi_authenticator.h"

/* Tamanio de buffer recomendado para getpw*_r, queda en 4096 si no hay valor. */
static long pw_bufsize(void)
{
    long n = sysconf(_SC_GETPW_R_SIZE_MAX); /* Tamanio sugerido para obtener datos del archov etc/passwd
                                                teniendo en cuenta problemas de hilos */
    return (n <= 0) ? 4096 : n;
}

/* Parsea los argumentos hacia Params.
   Devuelve 0 si OK, -1 si hay argumentos desconocidos. */
static int parse_args(pam_handle_t *pamh, int argc, const char **argv, Params *params)
{
    for (int i = 0; i < argc; ++i)
    {
        if (strncmp(argv[i], "debug") == 0)
        {
            params->debug = 1;
        }
        else if (strncmp(argv[i], "nullok") == 0)
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
    pwd_t *pwd;
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
    *old_gid = getgid();
    *old_uid = getuid();
    return setresgid(gid, gid, gid) == 0 && setresuid(uid, uid, uid) == 0 ? 0 : -1;
}

/* Restaura la identidad de filesystem previa */
static void restore_privileges(gid_t old_gid, uid_t old_uid)
{
    setresgid(old_gid, old_gid, old_gid);
    setresuid(old_uid, old_uid, old_uid);
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
    fclose(file);
    return 0;
}

/* Le solicita al usuario que ingrese el token y lo almacena en digits
    0 OK, -1 error.
*/
static int ask_for_token(pam_handle_t *pamh, Params *params, uint8_t *digits)
{
    return pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, NULL, "Ingrese el token de 2FA: ") == PAM_SUCCESS ? 0 : -1;
};

/* Valida el codigo ingresado por el usuario. valid = 1 si el TOTP es correcto.
    0 OK (ejecuto, no implica valid = 1), -1 error. */
static int validate_token(pam_handle_t *pamh, const Params *params, const char *secret_b32, uint8_t *code, int *valid)
{
    return validate_token(secret_b32, code, params->window, valid);
}

/* Funcion principal que resuelve la autenticacion */
int tsi_authenticator(pam_handle_t *pamh, int flags, int argc, const char **argv)
{

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
    char *secret_path;
    char secret_b32[SECRET_B32_MAX];
    int found;
    int valid;
    uint8_t code[DEFAULT_DIGITS];

    if (parse_args(pamh, argc, argv, &params) != 0)
    {
        return PAM_AUTH_ERR;
    }

    if (get_uid_gid(pamh, &uid, &gid) != 0)
    {
        return PAM_AUTH_ERR;
    }

    if (decrease_privileges(gid, uid, &old_gid, &old_uid) != 0)
    {
        return PAM_AUTH_ERR;
    }

    if (get_secret_path(uid, &params, &secret_path) != 0)
    {
        restore_privileges(old_gid, old_uid);
        return PAM_AUTH_ERR;
    }

    if (get_secret_file(secret_path, secret_b32, sizeof(secret_b32), &found) != 0)
    {
        restore_privileges(old_gid, old_uid);
        return PAM_AUTH_ERR;
    }

    restore_privileges(old_gid, old_uid);

    if (!found && params.nullok == NULLERR)
    {
        pam_syslog(pamh, LOG_ERR, "Usuario sin secreto y nullok = NULLERR, denegando acceso");
        return PAM_AUTH_ERR;
    }

    if (ask_for_token(pamh, &params, code) != 0)
    {
        return PAM_AUTH_ERR;
    }

    if (validate_token(pamh, &params, secret_b32, code, &valid) != 0 || !valid)
    {
        return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;
}

/* Funciones auth de pam */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return tsi_authenticator(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}