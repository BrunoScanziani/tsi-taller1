/*
    test_pam.c
    Suite de integracion del modulo PAM pam_tsi_authenticator.

    Carga el .so REAL mediante libpam (pam_start_confdir, sin root ni /etc/pam.d)
    y ejecuta cada escenario con una conversacion propia que inyecta el codigo.
    Los codigos validos se calculan con el mismo get_totp_at que usa el modulo.

    Uso: ./test_pam <ruta_absoluta_al_.so>
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <limits.h>

#include <security/pam_appl.h>
#include <cotp.h>

#include "tsi_authenticator.h"       /* SECRET_KEY, WINDOW_KEY, DEFAULT_DIGITS, ... */
#include "pam_tsi_authenticator.h"   /* STATE_FILE_SUFFIX */

#define GREEN "\033[32m"
#define RED   "\033[31m"
#define DIM   "\033[2m"
#define RESET "\033[0m"

/* Secreto Base32 fijo y valido para todos los tests. */
#define TEST_SECRET "JBSWY3DPEHPK3PXP"

static int g_pass = 0;
static int g_fail = 0;

static const char *rc_name(int rc)
{
    switch (rc) {
    case PAM_SUCCESS:  return "PAM_SUCCESS";
    case PAM_AUTH_ERR: return "PAM_AUTH_ERR";
    default:           return "OTRO";
    }
}

/* Compara el rc obtenido contra el esperado e imprime PASS/FAIL. */
static void check_rc(const char *name, int got, int expected)
{
    if (got == expected) {
        printf(GREEN "PASS" RESET " %s\n", name);
        g_pass++;
    } else {
        printf(RED "FAIL" RESET " %s  " DIM "(esperado %s, obtuve %s)" RESET "\n",
               name, rc_name(expected), rc_name(got));
        g_fail++;
    }
}

/* ----- Conversacion PAM: responde cada prompt con el codigo en cola ----- */
struct conv_data {
    const char *code;   /* respuesta a devolver en los prompts (puede ser NULL) */
    int prompts;        /* cuantos prompts pidio el modulo */
};

static int conv_fn(int num_msg, const struct pam_message **msg,
                   struct pam_response **resp, void *appdata_ptr)
{
    struct conv_data *d = appdata_ptr;
    struct pam_response *r = calloc((size_t)num_msg, sizeof(*r));
    if (!r) {
        return PAM_BUF_ERR;
    }
    for (int i = 0; i < num_msg; i++) {
        int style = msg[i]->msg_style;
        if (style == PAM_PROMPT_ECHO_OFF || style == PAM_PROMPT_ECHO_ON) {
            d->prompts++;
            r[i].resp = strdup(d->code ? d->code : "");
        }
        /* PAM_ERROR_MSG / PAM_TEXT_INFO: resp queda NULL */
    }
    *resp = r;
    return PAM_SUCCESS;
}

/* Ejecuta una autenticacion contra el servicio dado, devolviendo el rc de PAM. */
static int try_auth(const char *confdir, const char *service,
                    const char *user, const char *code)
{
    struct conv_data d = { code, 0 };
    struct pam_conv conv = { conv_fn, &d };
    pam_handle_t *pamh = NULL;

    int rc = pam_start_confdir(service, user, &conv, confdir, &pamh);
    if (rc != PAM_SUCCESS) {
        fprintf(stderr, "pam_start_confdir fallo: %d\n", rc);
        if (pamh) pam_end(pamh, rc);
        return -999;
    }
    rc = pam_authenticate(pamh, 0);
    pam_end(pamh, rc);
    return rc;
}

/* ----- Helpers de fixtures ----- */

/* Escribe el archivo del home con SOLO el secreto (como hace tsi-enroll). */
static void write_home_secret(const char *path, const char *secret)
{
    FILE *f = fopen(path, "w");
    if (!f) { perror("fopen secret"); exit(2); }
    fprintf(f, "%s=%s\n", SECRET_KEY, secret);
    fclose(f);
    chmod(path, 0600);
}

/* Escribe el archivo root-only de config+estado (para fijar RATE_LIMIT/LOCK_TIME del test). */
static void write_state_file(const char *path, unsigned window, unsigned rate_limit, unsigned lock_time)
{
    FILE *f = fopen(path, "w");
    if (!f) { perror("fopen state"); exit(2); }
    fprintf(f, "%s=%u\n%s=%u\n%s=%u\n",
            WINDOW_KEY, window,
            RATE_LIMIT_KEY, rate_limit,
            LOCK_TIME_KEY, lock_time);
    fclose(f);
    chmod(path, 0600);
}

/* Escribe un archivo de servicio PAM en confdir: apunta al .so, al secreto y al statedir. */
static void write_service(const char *confdir, const char *service, const char *so_abs,
                          const char *secret_path, const char *state_dir, int nullok)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", confdir, service);
    FILE *f = fopen(path, "w");
    if (!f) { perror("fopen service"); exit(2); }
    fprintf(f, "auth required %s secret=%s statedir=%s%s\n",
            so_abs, secret_path, state_dir, nullok ? " nullok" : "");
    fclose(f);
}

/* Devuelve el codigo TOTP valido en este instante (el llamador hace free). */
static char *current_code(const char *secret)
{
    cotp_error_t err = NO_ERROR;
    char *c = get_totp_at(secret, (long)time(NULL), DEFAULT_DIGITS, DEFAULT_PERIOD, COTP_SHA1, &err);
    if (!c || err != NO_ERROR) {
        fprintf(stderr, "get_totp_at fallo (err=%d)\n", err);
        exit(2);
    }
    return c;
}

/* Devuelve un codigo con formato valido pero garantizado incorrecto. */
static char *wrong_code(const char *secret)
{
    char *c = current_code(secret);
    c[0] = (c[0] == '0') ? '1' : '0';   /* altero un digito: ya no coincide */
    return c;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <ruta_al_.so>\n", argv[0]);
        return 2;
    }

    /* Ruta absoluta del modulo (PAM la exige para cargarlo directo). */
    char so_abs[PATH_MAX];
    if (!realpath(argv[1], so_abs)) {
        perror("realpath del modulo");
        return 2;
    }

    /* Usuario actual: get_uid_gid del modulo lo resuelve con getpwnam. */
    struct passwd *pw = getpwuid(getuid());
    if (!pw) { perror("getpwuid"); return 2; }
    const char *user = pw->pw_name;

    /* Preflight: el secreto de prueba debe ser Base32 valido. */
    { char *c = current_code(TEST_SECRET); free(c); }

    /* Directorio de trabajo temporal (confdir + secretos). */
    char workdir[] = "/tmp/tsi_test_XXXXXX";
    if (!mkdtemp(workdir)) { perror("mkdtemp"); return 2; }

    /* El parser de config de PAM separa por espacios: si la ruta del .so tiene
       espacios (p.ej. "Taller 1"), no lo encuentra. Uso un symlink sin espacios. */
    char module_link[PATH_MAX];
    snprintf(module_link, sizeof(module_link), "%s/module.so", workdir);
    if (symlink(so_abs, module_link) != 0) { perror("symlink modulo"); return 2; }

    char secret_ok[PATH_MAX], secret_rl[PATH_MAX], secret_none[PATH_MAX];
    snprintf(secret_ok,   sizeof(secret_ok),   "%s/.sec_ok", workdir);
    snprintf(secret_rl,   sizeof(secret_rl),   "%s/.sec_rl", workdir);
    snprintf(secret_none, sizeof(secret_none), "%s/.sec_none", workdir);   /* no existe */

    /* El modulo guarda el estado en <statedir>/<uid>_tsi_config. Uso el workdir como statedir;
       lo borro entre escenarios para aislarlos (todos comparten el mismo uid). */
    char state_path[PATH_MAX];
    snprintf(state_path, sizeof(state_path), "%s/%u%s", workdir, (unsigned)getuid(), STATE_FILE_SUFFIX);

    printf(DIM "modulo:  %s\n" RESET, so_abs);
    printf(DIM "usuario: %s\n" RESET, user);
    printf(DIM "workdir: %s\n\n" RESET, workdir);

    /* ============ 1) Codigo correcto ============ */
    printf("== Casos correctos ==\n");
    unlink(state_path);   /* estado limpio */
    write_home_secret(secret_ok, TEST_SECRET);
    write_service(workdir, "ok", module_link, secret_ok, workdir, 0);
    {
        char *code = current_code(TEST_SECRET);
        int rc = try_auth(workdir, "ok", user, code);
        check_rc("codigo correcto => SUCCESS", rc, PAM_SUCCESS);
        free(code);
    }

    /* ============ 2) Codigo incorrecto ============ */
    printf("\n== Casos incorrectos ==\n");
    unlink(state_path);   /* estado limpio */
    {
        char *code = wrong_code(TEST_SECRET);
        int rc = try_auth(workdir, "ok", user, code);
        check_rc("codigo incorrecto => AUTH_ERR", rc, PAM_AUTH_ERR);
        free(code);
    }
    /* formato invalido (muy corto) */
    {
        int rc = try_auth(workdir, "ok", user, "12");
        check_rc("codigo mal formado => AUTH_ERR", rc, PAM_AUTH_ERR);
    }

    /* ============ 3) Replay ============ */
    printf("\n== No-Replay ==\n");
    unlink(state_path);   /* estado limpio */
    {
        char *code = current_code(TEST_SECRET);
        int rc1 = try_auth(workdir, "ok", user, code);
        check_rc("replay: 1er uso del codigo => SUCCESS", rc1, PAM_SUCCESS);
        int rc2 = try_auth(workdir, "ok", user, code);
        check_rc("replay: 2do uso del MISMO codigo => AUTH_ERR", rc2, PAM_AUTH_ERR);
        free(code);
    }

    /* ============ 4) Rate limit ============ */
    printf("\n== Rate limit (RATE_LIMIT=3, LOCK_TIME=2s) ==\n");
    write_home_secret(secret_rl, TEST_SECRET);
    write_service(workdir, "rl", module_link, secret_rl, workdir, 0);
    unlink(state_path);
    write_state_file(state_path, DEFAULT_WINDOW, 3, 2);   /* LOCK_TIME=2 para test rapido */
    {
        char *wc = wrong_code(TEST_SECRET);
        int rc1 = try_auth(workdir, "rl", user, wc);
        int rc2 = try_auth(workdir, "rl", user, wc);
        int rc3 = try_auth(workdir, "rl", user, wc);
        check_rc("fallo 1/3 => AUTH_ERR", rc1, PAM_AUTH_ERR);
        check_rc("fallo 2/3 => AUTH_ERR", rc2, PAM_AUTH_ERR);
        check_rc("fallo 3/3 (activa bloqueo) => AUTH_ERR", rc3, PAM_AUTH_ERR);
        free(wc);

        /* Bloqueado: aun con codigo CORRECTO debe denegar. */
        char *good = current_code(TEST_SECRET);
        int rc_locked = try_auth(workdir, "rl", user, good);
        check_rc("bloqueado: codigo correcto => AUTH_ERR", rc_locked, PAM_AUTH_ERR);
        free(good);

        /* Tras expirar LOCK_TIME debe autoliberar. */
        printf(DIM "  esperando a que expire el bloqueo (3s)...\n" RESET);
        sleep(3);
        char *good2 = current_code(TEST_SECRET);
        int rc_unlock = try_auth(workdir, "rl", user, good2);
        check_rc("desbloqueado tras LOCK_TIME: correcto => SUCCESS", rc_unlock, PAM_SUCCESS);
        free(good2);
    }

    /* ============ 5) Sin secreto (nullok) ============ */
    printf("\n== Usuario sin secreto ==\n");
    unlink(state_path);
    write_service(workdir, "nonull", module_link, secret_none, workdir, 0);
    write_service(workdir, "nullok", module_link, secret_none, workdir, 1);
    {
        int rc_deny = try_auth(workdir, "nonull", user, "00000000");
        check_rc("sin secreto y sin nullok => AUTH_ERR", rc_deny, PAM_AUTH_ERR);
        int rc_allow = try_auth(workdir, "nullok", user, "00000000");
        check_rc("sin secreto y con nullok => SUCCESS", rc_allow, PAM_SUCCESS);
    }

    /* ----- Limpieza ----- */
    unlink(module_link);
    unlink(secret_ok); unlink(secret_rl);
    unlink(state_path);
    { char p[PATH_MAX];
      const char *svc[] = { "ok", "rl", "nonull", "nullok" };
      for (size_t i = 0; i < sizeof(svc)/sizeof(*svc); i++) {
          snprintf(p, sizeof(p), "%s/%s", workdir, svc[i]); unlink(p);
      }
    }
    rmdir(workdir);

    /* ----- Resumen ----- */
    printf("\n==============================\n");
    printf("Total: %d   " GREEN "PASS: %d" RESET "   %sFAIL: %d" RESET "\n",
           g_pass + g_fail, g_pass, g_fail ? RED : DIM, g_fail);
    return g_fail ? 1 : 0;
}
