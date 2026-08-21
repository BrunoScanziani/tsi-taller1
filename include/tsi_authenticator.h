/*
    tsi_authenticator.h
    Header del script engargado de generar el código y su configuración inicial.
    Autores: Bruno Scanziani, Agustin Manganelli
*/

#ifndef TSI_AUTHENTICATOR_H
#define TSI_AUTHENTICATOR_H

#include <stddef.h>   /* size_t */

/* Claves del archivo de configuración para guardar los valores importantes */
#define SECRET_KEY      "SECRET"
#define WINDOW_KEY      "WINDOW"
#define RATE_LIMIT_KEY  "RATE_LIMIT"

#define SECRET_FILENAME     ".tsi_authenticator"      /* nombre del archivo en el home */
#define SECRET_BITS_NUMBER  160                       /* Cantidad de bits del secreto */
#define DEFAULT_DIGITS      8                         /* digitos del código TOTP */
#define DEFAULT_PERIOD      30                        /* timestep en segundos */
#define DEFAULT_WINDOW      3                         /* cantidad de codigos validos */
#define SECRET_B32_MAX      64                        /* buffer del secreto en Base32 */
#define RATE_LIMIT          3                         /* cantidad de intentos incorrectos antes de abortar */

/* Funcion encargada de validar un código TOTP */
int validate_token(const char *secret_b32, const char *code, unsigned window, int *valid);

/* Funcion encargada de generar un secreto de largo SECRET_BITS_NUMBER */
int generate_secret(char *secret_b32, size_t secret_bytes_len, size_t secret_b32_len);

/* Construye el URI otpauth:// en 'uri_out'. 0 OK, -1 error. */
int build_otpauth_uri(char *uri_out, size_t uri_size,
                      const char *issuer, const char *user,
                      const char *secret_b32, unsigned digits, unsigned period);

/* Recibe el URI ya armado y lo muestra como QR en la terminal. 0 OK, -1 error. */
int generate_qr(const char *uri);

/* Obtiene el nombre del usuario actual  0 OK, -1 error. */
int get_current_username(char *user_out, size_t user_size); 

/* Construye <home>/SECRET_FILENAME para guardar el secreto. 0 OK, -1 error. */
int build_secret_path(char *path_out, size_t path_size);

/* Funcion que guarda el secreto en el home del usuario, crea el archivo */
int save_secret(const char *path, const char *secret_b32, unsigned window, unsigned rate_limit);

/* Funcion que borra el archivo de path, en este caso sera el secreto*/
int delete_secret(const char *path);

#endif /* TSI_AUTHENTICATOR_H */