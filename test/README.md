# Tests — pam_tsi_authenticator

Suite de integración que carga el `.so` **real** vía libpam (`pam_start_confdir`,
sin root ni `/etc/pam.d`) y ejecuta cada escenario con una conversación propia que
inyecta el código. Los códigos válidos se calculan con el mismo `get_totp_at` del
módulo, así que no dependen de `oathtool` ni del reloj de pared.

## Requisitos

- libpam ≥ 1.4 (`pam_start_confdir`), libcotp, headers de desarrollo.
- No requiere root.

## Correr

```bash
make test
```

Compila el módulo y la suite, y la ejecuta. Sale con código ≠ 0 si algún test falla.

## Casos cubiertos

| Escenario | Esperado |
|---|---|
| Código correcto | `PAM_SUCCESS` |
| Código incorrecto | `PAM_AUTH_ERR` |
| Código mal formado (largo/dígitos) | `PAM_AUTH_ERR` |
| Replay: 1er uso del código | `PAM_SUCCESS` |
| Replay: 2do uso del mismo código | `PAM_AUTH_ERR` |
| 3 fallos con `RATE_LIMIT=3` | `PAM_AUTH_ERR` (activa bloqueo) |
| Bloqueado: código correcto | `PAM_AUTH_ERR` |
| Tras expirar `LOCK_TIME`: código correcto | `PAM_SUCCESS` |
| Sin secreto, sin `nullok` | `PAM_AUTH_ERR` |
| Sin secreto, con `nullok` | `PAM_SUCCESS` |

## Detalle

`test_pam.c` crea un directorio temporal en `/tmp`, escribe ahí los archivos de
secreto y de servicio PAM, y referencia el módulo mediante un symlink sin espacios
(el parser de config de PAM separa por espacios). Cada `pam_authenticate` simula un
login independiente, ejercitando la persistencia de estado entre invocaciones.
