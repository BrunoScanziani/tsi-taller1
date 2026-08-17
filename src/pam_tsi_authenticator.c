/*
    pam_tsi_authenticator.c
    Módulo PAM de segundo factor (TOTP) para el Taller de Seguridad Informática.
    Autores: Bruno Scanziani, Agustín Manganelli
*/

#define _GNU_SOURCE          /* Obtener mas funciones como explicit_bzero para borrar datos de la 
                                ram y que el compilador no lo optimice, 
                                O_NOFOLLOW para fallar si intento abrir un archivo que apunta a otro
                                archivo/carpeta (util para cuando lea el secreto), 
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
static long pw_bufsize(void) {
    long n = sysconf(_SC_GETPW_R_SIZE_MAX); /* Tamanio sugerido para obtener datos del archov etc/passwd 
                                                teniendo en cuenta problemas de hilos */
    return (n <= 0) ? 4096 : n;
}

/* Parsea los arguemntos hacia Params.
   Devuelve 0 si OK, -1 si hay argumentos desconocidos. */
static int parse_args(pam_handle_t *pamh, int argc, const char **argv, Params *params) {
}

/* Obtiene el uid y gid del usuario que se esta intentando autenticar 0 OK, -1 error. */
static int get_uid_gid(pam_handle_t *pamh, uid_t *uid, gid_t *gid) {
}

/* Construye la ruta del archivo del secreto a partir del uid.
   Usa el override 'secret=' si se hY, si no <home>/SECRET_FILENAME. 0 OK, -1 error. */
static int get_secret_path(uid_t uid, const Params *params, char **path_out) {
}

/* Baja la identidad de filesystem al usuario para no hacer cosas con root innecesariamente
   Guarda los valores previos para poder restaurar. 0 OK, -1 error. */
static int decrease_privileges(gid_t gid, uid_t uid, gid_t *old_gid, uid_t *old_uid) {
}

/* Restaura la identidad de filesystem previa */
static void restore_privileges(gid_t old_gid, uid_t old_uid) {
}

/* Lee el secreto desde 'path'.
   found = 1 si el archivo existía y tenía contenido, 0 si no
   0 OK (incluso si no existe el archivo pero se deja pasar a los que no lo tengas), -1 error . */
static int get_secret_file(const char *path, char *secret_out, size_t out_size, int *found) {
}

/* Le solicita al usuario que ingrese el token y lo almacena en digits */
static ask_for_token(pam_handle_t *pamh, Params *params, uint8_t *digits) {

};

/* Valida el codigo ingresado por el usuari. valid = 1 si el TOTP es correcto. 
    0 OK (ejecuto, no implica valid = 1), -1 error. */
static int validate_token(pam_handle_t *pamh, const Params *params, const char *secret_b32, uint8_t *code, int *valid) {
}

/* Funcion principal que resuelve la autenticacion */
int tsi_authenticator(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    /* Para probar si compila */
    return PAM_SUCCESS;
}

/* Funciones auth de pam */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return tsi_authenticator(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}