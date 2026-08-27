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
#include <time.h>

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
        else if (strncmp(argv[i], "statedir=", 9) == 0)
        {
            params->state_dir = argv[i] + 9;
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

/* Construye la ruta del archivo root-only de config+estado: <statedir>/<uid>_tsi_config.
   Usa el override 'statedir=' si se dio, si no TSI_STATE_DIR. 0 OK, -1 error. */
static int get_state_path(uid_t uid, const Params *params, char **path_out)
{
    const char *dir = params->state_dir ? params->state_dir : TSI_STATE_DIR;

    int len = snprintf(NULL, 0, "%s/%u%s", dir, (unsigned)uid, STATE_FILE_SUFFIX) + 1;
    if (len <= 0) {
        return -1;
    }
    *path_out = malloc((size_t)len);
    if (*path_out == NULL) {
        return -1;
    }
    snprintf(*path_out, (size_t)len, "%s/%u%s", dir, (unsigned)uid, STATE_FILE_SUFFIX);
    return 0;
}

/* Asegura que exista el directorio root-only del estado, con permisos 0700.
   0 OK (ya existia o se creo), -1 error. */
static int ensure_state_dir(const char *dir)
{
    if (mkdir(dir, 0700) == 0) {
        return 0;
    }
    return (errno == EEXIST) ? 0 : -1;
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

/* Reescribe (o crea) el archivo root-only de config+estado del usuario:
   - conserva las lineas de config (WINDOW, RATE_LIMIT, LOCK_TIME, etc.),
   - reescribe FAIL_COUNT y LOCKED_UNTIL con los valores de 'state',
   - conserva solo las entradas USED_CODE vigentes (dentro de CODE_MAX_AGE), acotadas a
     MAX_USED_ENTRIES (descarta las mas viejas),
   - si 'new_used_code' != NULL, lo agrega como USED_CODE con el timestamp actual (No-Replay).
   Si el archivo no existe todavia lo crea, volcando WINDOW/RATE_LIMIT/LOCK_TIME desde 'state'
   (los defaults) para que el admin los vea y edite.
   La reescritura es atomica: se escribe un archivo temporal y se hace rename sobre el original.
   Devuelve 0 si OK, -1 si hubo error. */
static int persist_auth_state(const char *path, const AuthState *state, const char *new_used_code) {
    if (path == NULL || state == NULL) {
        return -1;
    }

    time_t now = time(NULL);
    const size_t used_key_len = strlen(USED_CODE_KEY);

    /* Buffers para las lineas que se conservan (sin el salto de linea final). */
    char config_lines[MAX_CONFIG_LINES][USED_LINE_SIZE];
    int  n_config = 0;
    char used_lines[MAX_USED_ENTRIES][USED_LINE_SIZE];
    int  n_used = 0;

    int result = -1;
    int creating = 0;
    char *tmp_path = NULL;
    FILE *out = NULL;
    FILE *in = NULL;

    /* Leo el archivo actual y clasifico sus lineas. Si no existe, lo creo desde cero. */
    int fd_in = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd_in < 0) {
        if (errno == ENOENT) {
            creating = 1;   /* primer uso: escribo un archivo nuevo con los defaults */
        } else {
            /* ELOOP (symlink) u otro error: no reescribo nada. */
            return -1;
        }
    } else {
        in = fdopen(fd_in, "r");
        if (!in) {
            close(fd_in);
            return -1;
        }
    }

    char line[USED_LINE_SIZE];
    while (in != NULL && fgets(line, sizeof(line), in) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';   /* quito el salto de linea */

        /* Las lineas de estado del rate-limit las reescribo desde 'state', no las conservo. */
        if (strncmp(line, FAIL_COUNT_KEY "=", strlen(FAIL_COUNT_KEY) + 1) == 0 ||
            strncmp(line, LOCKED_UNTIL_KEY "=", strlen(LOCKED_UNTIL_KEY) + 1) == 0) {
            continue;
        }

        int is_used = (strncmp(line, USED_CODE_KEY "=", used_key_len + 1) == 0);

        if (!is_used) {
            /* Linea de config (WINDOW/RATE_LIMIT/LOCK_TIME/...): la conservo verbatim.
               Si no hay espacio, aborto antes que perder config del admin. */
            if (n_config >= MAX_CONFIG_LINES) {
                goto cleanup;
            }
            /* La linea entra seguro: 'line' salio de un buffer del mismo tamanio. */
            strcpy(config_lines[n_config], line);
            n_config++;
            continue;
        }

        /* Linea USED_CODE=timestamp:codigo. Descarto las mal formadas o vencidas. */
        const char *value = line + used_key_len + 1;
        if (strchr(value, ':') == NULL) {
            continue;   /* sin ':' esta mal formada */
        }
        long ts = atol(value);   /* atol corta en el ':' porque no es digito */
        if (now - (time_t)ts > CODE_MAX_AGE) {
            continue;   /* vencida: ya no puede ser un replay */
        }

        /* Vigente: la conservo. Si llegue al tope, descarto la mas vieja (la primera). */
        if (n_used == MAX_USED_ENTRIES) {
            memmove(used_lines[0], used_lines[1],
                    (size_t)(MAX_USED_ENTRIES - 1) * USED_LINE_SIZE);
            n_used--;
        }
        strcpy(used_lines[n_used], line);
        n_used++;
    }
    if (in != NULL) {
        fclose(in);
        in = NULL;
    }

    /* Dejo lugar para la entrada nueva respetando el tope global. */
    if (n_used == MAX_USED_ENTRIES) {
        memmove(used_lines[0], used_lines[1],
                (size_t)(MAX_USED_ENTRIES - 1) * USED_LINE_SIZE);
        n_used--;
    }

    /* Escribo el contenido en un temporal en el mismo directorio */
    size_t tmp_len = strlen(path) + sizeof(".XXXXXX");
    tmp_path = malloc(tmp_len);
    if (!tmp_path) {
        goto cleanup;
    }
    snprintf(tmp_path, tmp_len, "%s.XXXXXX", path);

    int fd_out = mkstemp(tmp_path);   /* crea un archivo nuevo y unico (0600 en glibc) */
    if (fd_out < 0) {
        goto cleanup;
    }
    /* Refuerzo permisos por si la implementacion no garantiza 0600. */
    if (fchmod(fd_out, 0600) != 0) {
        close(fd_out);
        goto cleanup;
    }
    out = fdopen(fd_out, "w");
    if (!out) {
        close(fd_out);
        goto cleanup;
    }

    /* Archivo nuevo: vuelco la config (defaults) para que el admin la vea y edite. */
    if (creating) {
        if (fprintf(out, "%s=%u\n", WINDOW_KEY, state->window) < 0 ||
            fprintf(out, "%s=%u\n", RATE_LIMIT_KEY, state->rate_limit) < 0 ||
            fprintf(out, "%s=%u\n", LOCK_TIME_KEY, state->lock_time) < 0) {
            goto cleanup;
        }
    }
    /* Archivo existente: conservo la config verbatim (respeta lo que edito el admin). */
    for (int i = 0; i < n_config; i++) {
        if (fprintf(out, "%s\n", config_lines[i]) < 0) {
            goto cleanup;
        }
    }
    /* Estado del rate-limit (siempre presente y actualizado). */
    if (fprintf(out, "%s=%u\n", FAIL_COUNT_KEY, state->fail_count) < 0) {
        goto cleanup;
    }
    if (fprintf(out, "%s=%ld\n", LOCKED_UNTIL_KEY, state->locked_until) < 0) {
        goto cleanup;
    }
    for (int i = 0; i < n_used; i++) {
        if (fprintf(out, "%s\n", used_lines[i]) < 0) {
            goto cleanup;
        }
    }
    /* Entrada nueva opcional: USED_CODE=timestamp:codigo (solo en autenticacion exitosa). */
    if (new_used_code != NULL) {
        if (fprintf(out, "%s=%ld:%s\n", USED_CODE_KEY, (long)now, new_used_code) < 0) {
            goto cleanup;
        }
    }

    if (fflush(out) != 0) {
        goto cleanup;
    }
    if (fclose(out) != 0) {
        out = NULL;   /* ya no debo cerrarlo de nuevo en cleanup */
        goto cleanup;
    }
    out = NULL;

    /* Reemplazo atomico*/
    if (rename(tmp_path, path) != 0) {
        goto cleanup;
    }

    result = 0;   /* exito: el temporal ya no existe, no hay que borrarlo */

cleanup:
    if (in) {
        fclose(in);
    }
    if (out) {
        fclose(out);
    }
    if (tmp_path) {
        if (result != 0) {
            unlink(tmp_path);   /* limpio el temporal si algo fallo */
        }
        free(tmp_path);
    }
    /* Limpio los buffers de la ram por prolijidad (este archivo no tiene el secreto). */
    explicit_bzero(config_lines, sizeof(config_lines));
    explicit_bzero(used_lines, sizeof(used_lines));
    explicit_bzero(line, sizeof(line));
    return result;
}


/* Lee el SECRET del archivo del home del usuario
   found = 1 si el archivo existía y tenía el SECRET, 0 si no existe.
   0 OK (incluso si no existe), -1 error. */
static int read_home_secret(const char *path, char *secret_out, size_t out_size, int *found)
{
    *found = 0;

    /* open con O_NOFOLLOW si el ultimo componente es un symlink, falla.
       O_CLOEXEC no heredar el fd si se hace exec. */
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT || errno == ELOOP) {
            /* ENOENT no existe (no es error). ELOOP: era un symlink, lo rechazamos. */
            return 0;
        }
        return -1;
    }

    FILE *file = fdopen(fd, "r");
    if (!file) {
        close(fd);
        return -1;
    }

    char line[SECRET_B32_MAX + 32];   /* holgado para "CLAVE=valor\n" */
    int have_secret = 0;

    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';

        char *eq = strchr(line, '=');
        if (eq == NULL) {
            continue;
        }
        *eq = '\0';
        const char *key = line;
        const char *value = eq + 1;

        if (strcmp(key, SECRET_KEY) == 0) {
            if (strlen(value) >= out_size) {   /* no entra en el buffer */
                explicit_bzero(line, sizeof(line));
                fclose(file);
                return -1;
            }
            strcpy(secret_out, value);
            have_secret = 1;
        }
    }

    explicit_bzero(line, sizeof(line));   /* la linea contuvo el secreto */
    fclose(file);

    *found = have_secret;
    return 0;
}

/* Lee la config y el estado del rate-limit desde el archivo root-only hacia 'state':
   WINDOW, RATE_LIMIT, LOCK_TIME (config) y FAIL_COUNT, LOCKED_UNTIL (estado).
   Cada campo se sobrescribe solo si la clave está presente; si falta o el archivo no
   existe todavia, se conserva el default que traia 'state'. 0 OK, -1 error. */
static int read_state_file(const char *path, AuthState *state)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT || errno == ELOOP) {
            return 0;   /* sin archivo: se usan los defaults */
        }
        return -1;
    }

    FILE *file = fdopen(fd, "r");
    if (!file) {
        close(fd);
        return -1;
    }

    char line[USED_LINE_SIZE];
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';

        char *eq = strchr(line, '=');
        if (eq == NULL) {
            continue;
        }
        *eq = '\0';
        const char *key = line;
        const char *value = eq + 1;

        if (strcmp(key, WINDOW_KEY) == 0) {
            int w = atoi(value);
            if (w > 0) {
                state->window = (unsigned)w;
            }
        } else if (strcmp(key, RATE_LIMIT_KEY) == 0) {
            int r = atoi(value);
            if (r > 0) {
                state->rate_limit = (unsigned)r;
            }
        } else if (strcmp(key, LOCK_TIME_KEY) == 0) {
            int t = atoi(value);
            if (t > 0) {
                state->lock_time = (unsigned)t;
            }
        } else if (strcmp(key, FAIL_COUNT_KEY) == 0) {
            int f = atoi(value);
            if (f > 0) {
                state->fail_count = (unsigned)f;
            }
        } else if (strcmp(key, LOCKED_UNTIL_KEY) == 0) {
            long l = atol(value);
            if (l > 0) {
                state->locked_until = l;
            }
        }
    }

    fclose(file);
    return 0;
}

/* Revisa si 'code' ya figura entre los USED_CODE recientes del archivo (No-Replay).
   Solo considera entradas con timestamp dentro de CODE_MAX_AGE segundos.
   replayed = 1 si se encontró una coincidencia vigente, 0 si no.
   Devuelve 0 si ejecutó (incluso si el archivo no existe), -1 si hubo error. */
static int check_code_replay(const char *path, const char *code, int *replayed)
{
    *replayed = 0;

    if (path == NULL || code == NULL) {
        return -1;
    }

    /* Mismas protecciones que al leer el secreto: O_NOFOLLOW no seguir symlinks,
       O_CLOEXEC no heredar el fd. */
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT || errno == ELOOP) {
            /* Sin archivo (o era symlink) no hay historial: no hay replay. */
            return 0;
        }
        return -1;
    }

    FILE *file = fdopen(fd, "r");
    if (!file) {
        close(fd);
        return -1;
    }

    char line[SECRET_B32_MAX + 32];   /* holgado para "CLAVE=timestamp:codigo\n" */
    time_t now = time(NULL);

    while (fgets(line, sizeof(line), file) != NULL) {
        /* quito el salto de linea */
        line[strcspn(line, "\r\n")] = '\0';

        char *eq = strchr(line, '=');
        if (eq == NULL) {
            continue;   /* linea sin = la ignoro */
        }
        *eq = '\0';                 /* parto en clave y valor */
        const char *key = line;
        char *value = eq + 1;

        if (strcmp(key, USED_CODE_KEY) != 0) {
            continue;   /* solo me interesan las lineas USED_CODE */
        }

        /* value tiene el formato timestamp:codigo */
        char *colon = strchr(value, ':');
        if (colon == NULL) {
            continue;   /* linea mal formada la ignoro */
        }
        *colon = '\0';
        const char *ts_str = value;
        const char *used_code = colon + 1;

        /* Descarto las entradas viejas: fuera de la ventana ya no son un replay. */
        long ts = atol(ts_str);
        if (now - (time_t)ts > CODE_MAX_AGE) {
            continue;
        }

        if (strcmp(used_code, code) == 0) {
            *replayed = 1;
            break;
        }
    }

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

    /* Config y estado desde el archivo; arranca con los defaults. */
    AuthState state = {
        .window = (unsigned)params.window,
        .rate_limit = RATE_LIMIT,
        .lock_time = TIEMPO_RATE_LIMIT,
        .fail_count = 0,
        .locked_until = 0};

    gid_t gid;
    uid_t uid;
    gid_t old_gid;
    uid_t old_uid;
    char *secret_path = NULL;
    char *state_path = NULL;
    char secret_b32[SECRET_B32_MAX] = {0};
    char code[DEFAULT_DIGITS + 1] = {0};
    int found = 0;
    int valid = 0;
    int replayed = 0;
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

    if (get_secret_path(uid, &params, &secret_path) != 0)
    {
        debug_log(pamh, &params, "No se pudo construir la ruta del secreto");
        goto cleanup;
    }
    if (get_state_path(uid, &params, &state_path) != 0)
    {
        debug_log(pamh, &params, "No se pudo construir la ruta del estado");
        goto cleanup;
    }

    /* Leo el SECRET bajando privilegios al usuario (el archivo esta en su home). */
    if (decrease_privileges(gid, uid, &old_gid, &old_uid) != 0)
    {
        pam_syslog(pamh, LOG_ERR, "No se pudieron reducir los privilegios efectivos");
        goto cleanup;
    }
    privileges_lowered = 1;
    debug_log(pamh, &params, "Privilegios efectivos reducidos para leer el secreto");

    if (read_home_secret(secret_path, secret_b32, sizeof(secret_b32), &found) != 0)
    {
        debug_log(pamh, &params, "No se pudo leer el secreto del usuario");
        goto cleanup;
    }

    if (restore_privileges(old_gid, old_uid) != 0)
    {
        pam_syslog(pamh, LOG_ERR, "No se pudieron restaurar los privilegios efectivos");
        goto cleanup;
    }
    privileges_lowered = 0;
    debug_log(pamh, &params, found ? "Secreto encontrado" : "Secreto no encontrado");

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

    /* Leo la config y el estado del rate-limit del archivo root-only (como root). */
    if (read_state_file(state_path, &state) != 0)
    {
        pam_syslog(pamh, LOG_ERR, "No se pudo leer el estado del rate-limit");
        goto cleanup;
    }

    /* Rate-limit: si el usuario esta bloqueado, deniego sin pedir el codigo. */
    if (state.locked_until != 0)
    {
        time_t now = time(NULL);
        if (now < state.locked_until)
        {
            long remaining = (long)(state.locked_until - now);
            pam_syslog(pamh, LOG_WARNING, "Acceso bloqueado por rate-limit, faltan %ld segundos", remaining);
            pam_error(pamh, "Demasiados intentos fallidos. Reintente en %ld segundos.", remaining);
            goto cleanup;   /* result permanece en PAM_AUTH_ERR */
        }
    }

    debug_log(pamh, &params, "Solicitando código TOTP");
    if (ask_for_token(pamh, &params, code) != 0)
    {
        debug_log(pamh, &params, "No se recibió un código TOTP válido");
        goto cleanup;
    }
    debug_log(pamh, &params, "Código TOTP recibido");

    validation_rc = validate_token(secret_b32, code, state.window, &valid);
    if (validation_rc != 0)
    {
        debug_log(pamh, &params, "Error interno durante la validación TOTP");
        goto cleanup;
    }

    /* El archivo de estado es root-only: lo leo/escribo como root, sin bajar privilegios.
       Me aseguro de que el directorio exista. */
    if (ensure_state_dir(params.state_dir ? params.state_dir : TSI_STATE_DIR) != 0)
    {
        pam_syslog(pamh, LOG_ERR, "No se pudo preparar el directorio de estado");
        goto cleanup;
    }

    /* No-Replay: un codigo TOTP correcto pero ya usado se trata como intento fallido. */
    if (valid && check_code_replay(state_path, code, &replayed) != 0)
    {
        pam_syslog(pamh, LOG_ERR, "Error al verificar el reuso del codigo (No-Replay)");
        goto cleanup;
    }

    if (valid && !replayed)
    {
        /* Exito: reseteo el rate-limit y registro el codigo usado. */
        state.fail_count = 0;
        state.locked_until = 0;
        if (persist_auth_state(state_path, &state, code) != 0)
        {
            pam_syslog(pamh, LOG_ERR, "Error al persistir el estado tras autenticacion exitosa");
            goto cleanup;   /* si no puedo registrar el codigo usado, deniego */
        }
        result = PAM_SUCCESS;
        debug_log(pamh, &params, "Código TOTP aceptado");
    }
    else
    {
        /* Fallo (codigo incorrecto o replay): sumo el intento y aplico el rate-limit. */
        if (replayed)
        {
            pam_syslog(pamh, LOG_WARNING, "Codigo TOTP ya utilizado recientemente, posible replay, denegando acceso");
        }
        else
        {
            debug_log(pamh, &params, "Código TOTP rechazado");
        }

        state.fail_count += 1;
        if (state.fail_count >= state.rate_limit)
        {
            state.locked_until = (long)time(NULL) + (long)state.lock_time;
            state.fail_count = 0;   /* reinicio el contador tras activar el bloqueo */
            pam_syslog(pamh, LOG_WARNING, "RATE_LIMIT alcanzado, bloqueando el acceso por %u segundos", state.lock_time);
        }

        /* Si esto falla igual denegamos; solo lo registramos. */
        if (persist_auth_state(state_path, &state, NULL) != 0)
        {
            pam_syslog(pamh, LOG_ERR, "Error al persistir el estado del rate-limit");
        }
        /* result permanece en PAM_AUTH_ERR */
    }

cleanup:
    if (privileges_lowered && restore_privileges(old_gid, old_uid) != 0)
    {
        pam_syslog(pamh, LOG_ERR, "No se pudieron restaurar los privilegios durante la limpieza");
        result = PAM_AUTH_ERR;
    }
    free(secret_path);
    free(state_path);
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
