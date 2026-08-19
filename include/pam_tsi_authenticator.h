/*
    pam_tsi_authenticator.h
    Header del modulo PAM de segundo factor (TOTP) para el Taller de Seguridad Informatica.
    Autores: Bruno Scanziani, Agustin Manganelli
*/

#ifndef PAM_TSI_AUTHENTICATOR_H
#define PAM_TSI_AUTHENTICATOR_H

#include <stddef.h>   /* size_t */


#define MODULE_NAME       "pam_tsi_authenticator"   /* etiqueta para pam_syslog */
#define SECRET_FILENAME   ".tsi_authenticator"      /* nombre del archivo en el home */
#define DEFAULT_DIGITS    6                         /* digitos del código TOTP */
#define DEFAULT_PERIOD    30                        /* timestep en segundos */
#define DEFAULT_WINDOW    3                         /* cantidad de codigos validos */
#define SECRET_B32_MAX    64                        /* buffer del secreto en Base32 */

/* Struct con los parametros que obtendremos */
typedef struct Params {
    int      debug;                                 /* activa loggin para debug */
    enum { NULLERR = 0, NULLOK } nullok;            /* permitir o no usuarios sin secreto */
    unsigned digits;                                /* cantidad de digitos del codigo */
    unsigned period;                                /* timestep en segundos */
    size_t   window;                                /* tamanio de la ventana de tolerancia */
    const char *secret_filename;                    /* override por 'secret=', o NULL */
} Params;


#endif /* PAM_TSI_AUTHENTICATOR_H */