/*
    pam_tsi_authenticator.h
    Header del modulo PAM de segundo factor (TOTP) para el Taller de Seguridad Informatica.
    Autores: Bruno Scanziani, Agustin Manganelli
*/

#ifndef PAM_TSI_AUTHENTICATOR_H
#define PAM_TSI_AUTHENTICATOR_H

#include <stddef.h> /* size_t */

#define MODULE_NAME "pam_tsi_authenticator"  /* etiqueta para pam_syslog */
#define SECRET_FILENAME ".tsi_authenticator" /* archivo del secreto en el home (dueño: usuario) */
#define TSI_STATE_DIR "/var/lib/tsi_authenticator" /* dir root-only de config+estado por usuario */
#define STATE_FILE_SUFFIX "_tsi_config"      /* archivo por usuario: <uid>_tsi_config */
#define DEFAULT_DIGITS 8                     /* digitos del código TOTP */
#define DEFAULT_PERIOD 30                    /* timestep en segundos */
#define DEFAULT_WINDOW 3                     /* cantidad de codigos validos */
#define SECRET_B32_MAX 64                    /* buffer del secreto en Base32 */
#define USED_LINE_SIZE (SECRET_B32_MAX + 32)  /* holgado para "CLAVE=timestamp:codigo\n" */
#define MAX_CONFIG_LINES 16                    /* lineas de config (SECRET/WINDOW/...) a conservar */

/* Struct con los parametros que obtendremos */
typedef struct Params
{
    int debug; /* activa loggin para debug */
    enum
    {
        NULLERR = 0,
        NULLOK
    } nullok;                    /* permitir o no usuarios sin secreto */
    unsigned digits;             /* cantidad de digitos del codigo */
    unsigned period;             /* timestep en segundos */
    size_t window;               /* tamanio de la ventana de tolerancia */
    const char *secret_filename; /* override por 'secret=' del archivo del home, o NULL */
    const char *state_dir;       /* override por 'statedir=' del dir root-only, o NULL */
} Params;

/* Config y estado que viven en el archivo root-only <TSI_STATE_DIR>/<uid>_tsi_config.
   window/rate_limit/lock_time los fija el admin (con defaults);
   fail_count/locked_until los gestiona el modulo (rate-limit).
   El SECRET vive aparte, en el home del usuario. */
typedef struct AuthState
{
    unsigned window;       /* codigos validos simultaneos (tolerancia de reloj) */
    unsigned rate_limit;   /* fallos consecutivos permitidos antes de bloquear */
    unsigned lock_time;    /* segundos de bloqueo al alcanzar rate_limit */
    unsigned fail_count;   /* estado: fallos consecutivos acumulados */
    long     locked_until; /* estado: epoch hasta el que el acceso esta bloqueado (0 = libre) */
} AuthState;

#endif /* PAM_TSI_AUTHENTICATOR_H */