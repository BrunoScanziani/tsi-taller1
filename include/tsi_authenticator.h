/*
    tsi_authenticator.h
    Header del script engargado de generar el código y su configuración inicial.
    Autores: Bruno Scanziani, Agustin Manganelli
*/

#ifndef TSI_AUTHENTICATOR_H
#define TSI_AUTHENTICATOR_H

#include <stddef.h>   /* size_t */

#define SECRET_FILENAME     ".tsi_authenticator"      /* nombre del archivo en el home */
#define SECRET_BITS_NUMBER  160                       /* Cantidad de bits del secreto */
#define DEFAULT_DIGITS      6                         /* digitos del código TOTP */
#define DEFAULT_PERIOD      30                        /* timestep en segundos */
#define DEFAULT_WINDOW      3                         /* cantidad de codigos validos */
#define SECRET_B32_MAX      64                        /* buffer del secreto en Base32 */

/* Funcion encargada de generar un secreto de largo SECRET_BITS_NUMBER */
int generate_secret(char *secret_b32, size_t secret_b32_len);

/* Funcion encargada de pasar a QR el secreto generado */
int generate_qr(const char *secret_b32, size_t secret_b32_len);

#endif /* TSI_AUTHENTICATOR_H */