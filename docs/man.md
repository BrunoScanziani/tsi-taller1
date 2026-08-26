# pam_tsi_authenticator — Manual del administrador

Taller de Seguridad Informática — Bruno Scanziani, Agustín Manganelli

---

## NAME

**pam_tsi_authenticator** — módulo PAM de segundo factor TOTP (RFC 6238).

**tsi-enroll** — genera y registra el secreto TOTP de un usuario.

---

## SYNOPSIS

```
auth    required    pam_tsi_authenticator.so [debug] [nullok] [window=N]
```

```
tsi-enroll
```

---

## DESCRIPTION

Provee un segundo factor TOTP para servicios PAM (típicamente SSH). Implementa el grupo `auth`. En cada autenticación:

1. Resuelve el usuario.
2. Reduce privilegios efectivos a los del usuario.
3. Lee el secreto y el estado (`~/.tsi_authenticator`).
4. Restaura privilegios.
5. **Rate-limit:** si el usuario está bloqueado (`LOCKED_UNTIL` en el futuro), deniega sin pedir el código.
6. Solicita el código TOTP (sin eco).
7. Calcula los códigos válidos dentro de la ventana de tolerancia y compara.
8. **No-Replay:** un código correcto pero ya usado se trata como intento fallido.
9. **Éxito:** resetea el contador de fallos, registra el código usado y devuelve `PAM_SUCCESS`.
10. **Fallo:** incrementa `FAIL_COUNT`; al alcanzar `RATE_LIMIT` fija un bloqueo de `LOCK_TIME` segundos y devuelve `PAM_AUTH_ERR`.

### Parámetros del esquema (fijos)

- **Algoritmo:** HMAC-SHA1.
- **Dígitos:** 8.
- **Período:** 30 s.
- **Ventana de tolerancia:** 3 códigos (actual, anterior, posterior).

---

## OPTIONS

- **debug** — mensajes de diagnóstico a syslog (sin secretos ni códigos).
- **nullok** — permite el acceso a usuarios sin secreto configurado. Sin esta opción, se rechazan. Usar solo durante el despliegue gradual.
- **window=N** — ventana por defecto si el archivo del usuario no define `WINDOW`.

---

## FILES

**`~/.tsi_authenticator`** — secreto y configuración por usuario. Permisos `0600`, propiedad del usuario. Formato clave-valor:

```
SECRET=<Base32>
WINDOW=3
RATE_LIMIT=3
LOCK_TIME=300
FAIL_COUNT=0
LOCKED_UNTIL=0
USED_CODE=<timestamp>:<codigo>
```

Config (fijada por el admin; si falta, se usa el default):

- `SECRET` — secreto TOTP en Base32. **No divulgar.**
- `WINDOW` — códigos válidos simultáneos (tolerancia de reloj). Default 3.
- `RATE_LIMIT` — fallos consecutivos permitidos antes de bloquear. Default 3.
- `LOCK_TIME` — segundos de bloqueo tras alcanzar `RATE_LIMIT`. Default 300.

Estado gestionado por el módulo (**no editar**):

- `FAIL_COUNT` — fallos consecutivos acumulados.
- `LOCKED_UNTIL` — epoch hasta el que el acceso está bloqueado (0 = libre).
- `USED_CODE` — códigos usados recientemente (No-Replay).

Otras rutas:

- **`pam_tsi_authenticator.so`** — Ubuntu: `/usr/lib/x86_64-linux-gnu/security/`; Rocky: `/usr/lib64/security/`.
- **`/etc/pam.d/sshd`** — activación del módulo para SSH.
- **`/etc/ssh/sshd_config`** (o `sshd_config.d/`) — flujo interactivo de SSH.

---

## ADMINISTRATION

### Habilitar 2FA para un usuario

El usuario ejecuta `tsi-enroll` (sin `sudo`), escanea el QR con una app de 8 dígitos (Aegis, FreeOTP, Raivo, 2FAS) y confirma con un código.

### Deshabilitar 2FA para un usuario

```bash
rm ~/.tsi_authenticator
```

Sin `nullok`, el usuario queda sin acceso hasta re-enrolarse; con `nullok`, accede solo con el primer factor.

### Ajustar la política de un usuario enrolado

Editar en `~/.tsi_authenticator` (no requiere re-enrolar):

- `WINDOW` — tolerancia de reloj.
- `RATE_LIMIT` — fallos consecutivos antes de bloquear.
- `LOCK_TIME` — duración del bloqueo en segundos.

Para desbloquear a un usuario bloqueado de inmediato, poner `LOCKED_UNTIL=0` (o borrar la línea).

### Parámetros fijos

Dígitos (8), período (30 s) y algoritmo (SHA1) quedan codificados en el QR al enrolar. Cambiarlos exige re-enrolar; no son configurables por archivo.

---

## EXAMPLES

Configurar SSH para exigir el segundo factor.

**1. PAM** — colocar el módulo en el stack que ejecuta PAM para la autenticación SSH.

Ubuntu, en `/etc/pam.d/sshd`:

```
@include common-auth
auth    required    pam_tsi_authenticator.so

```

Rocky, en `/etc/pam.d/sshd`:

```
auth    substack    password-auth
auth    required    pam_tsi_authenticator.so
auth    include     postlogin
```

**2. Servidor SSH** — habilitar el flujo interactivo y desactivar la contraseña plana.

Ubuntu, en `/etc/ssh/sshd_config`:

```
UsePAM yes
KbdInteractiveAuthentication yes
PasswordAuthentication no
```

Rocky, en `/etc/ssh/sshd_config.d/50-tsi-2fa.conf`:

```bash
sudo tee /etc/ssh/sshd_config.d/50-tsi-2fa.conf > /dev/null << 'EOF'
UsePAM yes
KbdInteractiveAuthentication yes
PasswordAuthentication no
EOF
```

**3. Validar y reiniciar:**

```bash
sudo sshd -t
sudo systemctl restart sshd     # en Ubuntu puede ser 'ssh'
```

> La autenticación por clave pública omite el stack `auth` de PAM y no pide el código; para exigir 2FA, autenticarse con contraseña.

---

## SECURITY CONSIDERATIONS

- **No-Replay.** Un código válido no puede reutilizarse mientras siga vigente: el módulo guarda los códigos usados en `~/.tsi_authenticator` y rechaza cualquier repetición. Las entradas vencidas se purgan automáticamente y el archivo se reescribe de forma atómica (temporal + `rename`).
- **Rate-limit.** Tras `RATE_LIMIT` fallos consecutivos el acceso se bloquea `LOCK_TIME` segundos; durante el bloqueo se deniega sin pedir el código. El estado (`FAIL_COUNT`, `LOCKED_UNTIL`) se guarda en `~/.tsi_authenticator`, que es del usuario: mitiga fuerza bruta **remota** (el atacante SSH no tiene acceso local al archivo), pero un usuario con shell local podría resetear su propio contador. Un replay cuenta como intento fallido.
- **Protección del secreto.** Se almacena en claro con permisos `0600`; solo el usuario propietario y root pueden leerlo.
- **Reducción de privilegios.** El módulo opera con la identidad del usuario al acceder a su archivo, no como root.
- **Higiene de memoria.** Secretos y códigos se sobrescriben con `explicit_bzero`.
- **Manejo de symlinks.** Los archivos se abren con `O_NOFOLLOW`; un `~/.tsi_authenticator` que sea symlink se rechaza.
- **Resistencia a fuerza bruta.** 8 dígitos (10^8) y ventana 3 ⇒ probabilidad 3/10^8 por intento. Depende además de los controles del servidor.
- **Comparación no constante en tiempo.** Usa `strcmp`; riesgo bajo por la rotación de 30 s, documentado como limitación.
- **Vías que omiten el 2FA.** La clave pública omite el stack `auth`. Para exigir el segundo factor, forzar contraseña o usar `AuthenticationMethods`.

---

## DIAGNOSTICS

Con `debug`, registra el progreso en syslog (`/var/log/auth.log` en Ubuntu, `/var/log/secure` en Rocky):

- *"Usuario PAM resuelto correctamente"*
- *"Configuración TOTP encontrada" / "no encontrada"*
- *"Acceso bloqueado por rate-limit, faltan N segundos"*
- *"Codigo TOTP ya utilizado recientemente, posible replay, denegando acceso"*
- *"RATE_LIMIT alcanzado, bloqueando el acceso por N segundos"*
- *"Código TOTP aceptado" / "rechazado"*

---

## SEE ALSO

`pam.conf`(5), `pam_sm_authenticate`(3), `sshd_config`(5), `oathtool`(1), RFC 6238 (TOTP), RFC 4226 (HOTP).
