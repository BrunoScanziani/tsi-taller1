# Instalación — TSI Authenticator (2FA TOTP para PAM)

Taller de Seguridad Informática — Bruno Scanziani, Agustín Manganelli

Productos:

- **`pam_tsi_authenticator.so`** — módulo PAM que verifica el código TOTP.
- **`tsi-enroll`** — genera y registra el secreto del usuario.
- **`tsi-config-init`** — helper setuid root que crea el archivo de config root-only del usuario.
- **`tsi-seed-crypto`** — helper setuid root que cifra el seed con la clave maestra.
- **`tsi-key-init`** — crea la clave maestra; lo corre `make install` una vez, como root.

---

## 1. Dependencias para Compilar

- `gcc`, `make`, `cmake`, `git`
- PAM (headers de desarrollo)
- libgcrypt (headers de desarrollo)
- libcotp **≥ 4.0.0** (se compila desde el fuente; versiones previas no compilan por `COTP_SHA1`)
- `qrencode` (solo en tiempo de ejecución de `tsi-enroll`)

---

## 2. Ubuntu Server (26.04 LTS)

```bash
sudo apt update
sudo apt install build-essential cmake git libpam0g-dev libgcrypt20-dev qrencode
```

Módulo destino: `/usr/lib/x86_64-linux-gnu/security/`.

---

## 3. Rocky Linux (9/10)

```bash
sudo dnf install epel-release          # si falla: sudo dnf config-manager --set-enabled crb
sudo dnf install gcc make cmake git pam-devel libgcrypt-devel qrencode
# Solo si SELinux está activo (por defecto lo está):
sudo dnf install selinux-policy-devel policycoreutils-python-utils
```

Módulo destino: `/usr/lib64/security/`.

---

## 4. Compilar libcotp desde el fuente

```bash
git clone https://github.com/paolostivanin/libcotp.git
cd libcotp && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
make
sudo make install
sudo ldconfig
cd ../..
```

---

## 5. Compilar e instalar el proyecto 

```bash
make
sudo make install
```

`make install`:

- Instala el módulo en la ruta PAM de la distro.
- Instala los helpers `tsi-config-init` y `tsi-seed-crypto` **setuid root** (`4755`) en `/usr/local/bin/`, y `tsi-key-init` en `/usr/local/sbin/`.
- Corre `tsi-key-init`, que genera la clave maestra en `/etc/tsi_authenticator/master.key` (`0400`, root) si no existe.
- Crea el directorio root-only `/var/lib/tsi_authenticator/` (`0700`).
- **Si SELinux está activo**, compila e instala el módulo de política `tsi_authenticator`, etiqueta la clave y el estado, y aplica `restorecon`. Aborta con un mensaje si faltan `selinux-policy-devel` o `policycoreutils-python-utils`.

---

## 6. Verificar la instalación

```bash
# Ubuntu
ls -l /usr/lib/x86_64-linux-gnu/security/pam_tsi_authenticator.so
# Rocky
ls -l /usr/lib64/security/pam_tsi_authenticator.so

nm -D <ruta>/pam_tsi_authenticator.so | grep pam_sm   # deben aparecer pam_sm_authenticate y pam_sm_setcred
```

---

## 7. Vincular un usuario

Cada usuario lo ejecuta para sí mismo:

```bash
./tsi-enroll
```

1. Genera un seed de 160 bits.
2. Muestra el QR (requiere `qrencode`) y el seed en texto.
3. Pide un código para confirmar; si falla, no guarda nada.
4. Al confirmar: guarda el seed **cifrado** en `~/.tsi_authenticator` (`0600`, vía `tsi-seed-crypto`) y crea el config root-only (vía `tsi-config-init`). Ambos helpers deben estar instalados setuid (ver sección 5).

> **8 dígitos.** Google Authenticator no los soporta. Usar **Aegis** o **FreeOTP** (Android), **Raivo** / **2FAS** (iOS). Prueba sin teléfono:
> `oathtool --totp -b --digits=8 <SECRETO_BASE32>`.

Verificar (el home tiene el seed cifrado, no texto legible):

```bash
ls -l ~/.tsi_authenticator     # -rw------- (0600), dueño = usuario
file ~/.tsi_authenticator      # data (blob binario AES-256-GCM)
```

La clave maestra que descifra ese blob está en `/etc/tsi_authenticator/master.key` (`0400`, root).

La **config y el estado** viven aparte, en un archivo **root-only** que crea `tsi-enroll` al enrolar (vía el helper setuid):

```bash
sudo cat /var/lib/tsi_authenticator/$(id -u)_tsi_config
```

```
WINDOW=3                          # config (admin)
RATE_LIMIT=3                      # config (admin): fallos antes de bloquear
LOCK_TIME=300                     # config (admin): segundos de bloqueo
FAIL_COUNT=0                      # estado (módulo)
LOCKED_UNTIL=0                    # estado (módulo): epoch de fin de bloqueo, 0 = libre
USED_CODE=<timestamp>:<codigo>    # estado (módulo): aparece tras el primer login (No-Replay)
```

`WINDOW`, `RATE_LIMIT` y `LOCK_TIME` los ajusta el admin (como root). El resto lo gestiona el módulo; no editarlo (salvo `LOCKED_UNTIL=0` para desbloquear a un usuario). El usuario no tiene acceso a este archivo. Re-enrolar conserva este archivo (no resetea el bloqueo ni la política).

---

## 8. Configurar PAM y SSH

### 8.1. Añadir el módulo (antes del factor de contraseña)

**Ubuntu** — `/etc/pam.d/sshd`, antes de `@include common-auth`:

```
auth    required    pam_tsi_authenticator.so
@include common-auth
```

**Rocky** — `/etc/pam.d/sshd`, antes de `substack password-auth`:

```
auth    required    pam_tsi_authenticator.so
auth    substack    password-auth
auth    include     postlogin
```

Argumentos opcionales: `debug`, `nullok`, `window=N`, `rate_limit=N`, `lock_time=N`.

### 8.2. Servidor SSH

**Rocky** — `/etc/ssh/sshd_config.d/50-tsi-2fa.conf`:

```bash
sudo tee /etc/ssh/sshd_config.d/50-tsi-2fa.conf > /dev/null << 'EOF'
UsePAM yes
KbdInteractiveAuthentication yes
PasswordAuthentication no
EOF
```

**Ubuntu** — en `/etc/ssh/sshd_config`:

```
UsePAM yes
KbdInteractiveAuthentication yes
PasswordAuthentication no
```

> La autenticación por **clave pública** omite el stack `auth` de PAM y **no** pide el código. Para exigir 2FA, autenticarse con contraseña.

### 8.3. Validar y reiniciar

```bash
sudo sshd -t
sudo sshd -T | grep -Ei 'usepam|kbdinteractive|passwordauthentication'
sudo systemctl restart sshd     # en Ubuntu puede ser 'ssh'
```

> Mantener una sesión abierta como rescate antes de reiniciar y probar el login en una sesión nueva.

---

## 9. Rocky: SELinux

Con SELinux en enforcing, sin política la sesión SSH no puede leer la clave maestra ni el estado, y el login falla sin error claro. `make install` instala el módulo de política `tsi_authenticator` y etiqueta la clave (`tsi_auth_key_t`) y el estado (`tsi_auth_state_t`); requiere `selinux-policy-devel` y `policycoreutils-python-utils`.

La política solo habilita el dominio de SSH (`sshd_session_t`). Otros servicios PAM (login local, `sudo`) correrían en otro dominio y darían denegaciones.

Diagnóstico:

```bash
sudo ausearch -m avc -ts recent          # ver denegaciones
ls -Z /etc/tsi_authenticator/master.key /var/lib/tsi_authenticator   # verificar etiquetas
sudo restorecon -Rv /etc/tsi_authenticator /var/lib/tsi_authenticator # reetiquetar
```

---

## 10. Sincronización horaria (crítico)

Un desfase de reloj hace que **ningún código coincida**.

```bash
timedatectl                       # "System clock synchronized: yes"
sudo timedatectl set-ntp true
# Rocky:
sudo systemctl enable --now chronyd
sudo chronyc makestep
```

---

## 11. Diagnóstico

```bash
# Logs (con 'debug' activo)
sudo tail -f /var/log/auth.log    # Ubuntu
sudo tail -f /var/log/secure      # Rocky

# Probar el módulo aislado
sudo tee /etc/pam.d/tsi-test > /dev/null << 'EOF'
auth required pam_tsi_authenticator.so debug
EOF
pamtester tsi-test $USER authenticate
```

| Síntoma | Causa | Solución |
|---|---|---|
| El código siempre se rechaza | Reloj desincronizado | `chronyc makestep` / NTP |
| Rechazo sin error claro (Rocky) | SELinux | `restorecon`, revisar AVC |
| No aparece el prompt del código | `KbdInteractiveAuthentication no` | Corregir `sshd_config` |
| Entra sin pedir código | Login por clave pública | Autenticarse con contraseña |
| Login siempre denegado tras enrolar | Falta el config root-only (helper no instalado o falló) | Re-enrolar con `tsi-config-init` instalado setuid; ver log del módulo |
| Denegado tras enrolar, con AVC de la clave/estado (Rocky) | Falta o mal etiquetada la política SELinux | Reinstalar política; `restorecon` (sección 9) |
| Denegado y "no se pudo leer/descifrar" | Falta `master.key` o quedó ilegible | Verificar `/etc/tsi_authenticator/master.key` (`0400`, root); re-enrolar si se perdió |
| Código válido rechazado al reintentar | No-Replay (código ya usado) | Esperar el siguiente código |
| "Demasiados intentos fallidos" | Rate-limit activo | Esperar `LOCK_TIME`, o `LOCKED_UNTIL=0` en `/var/lib/tsi_authenticator/<uid>_tsi_config` (root) |
| El QR no aparece | Falta `qrencode` | Instalar `qrencode` |

---

## 12. Desinstalación

```bash
sudo make uninstall     # quita el .so, los helpers, /var/lib/tsi_authenticator y la política SELinux
make remove             # además de uninstall, borra los binarios locales (equivale a uninstall + clean)
```

`uninstall` elimina el módulo, los helpers, `/var/lib/tsi_authenticator/` (config/estado de todos los usuarios) y la política SELinux. **No** borra la clave maestra `/etc/tsi_authenticator/master.key` ni los secretos en cada `~/.tsi_authenticator`; borrarlos por separado si se desea.
