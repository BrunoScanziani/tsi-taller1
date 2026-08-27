/*
    pam_tsi_authenticator.h
    Header del modulo PAM de segundo factor (TOTP) para el Taller de Seguridad Informatica.
    Autores: Bruno Scanziani, Agustin Manganelli
*/

#ifndef PAM_TSI_AUTHENTICATOR_H
#define PAM_TSI_AUTHENTICATOR_H

#include <stddef.h> /* size_t */

#include "tsi_authenticator.h" /* AuthState, TSI_STATE_DIR, STATE_FILE_SUFFIX, claves */

#define MODULE_NAME "pam_tsi_authenticator"  /* etiqueta para pam_syslog */
#define SECRET_FILENAME ".tsi_authenticator" /* archivo del secreto en el home (dueño: usuario) */
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
    size_t window;               /* default de la ventana de tolerancia (arg 'window=') */
    unsigned rate_limit;         /* default de fallos antes de bloquear (arg 'rate_limit=') */
    unsigned lock_time;          /* default de segundos de bloqueo (arg 'lock_time=') */
    const char *secret_filename; /* override por 'secret=' del archivo del home, o NULL */
    const char *state_dir;       /* override por 'statedir=' del dir root-only, o NULL */
} Params;

#endif /* PAM_TSI_AUTHENTICATOR_H */