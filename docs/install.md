# Instalación — TSI Authenticator (2FA TOTP para PAM)

Taller de Seguridad Informática — Bruno Scanziani, Agustín Manganelli

Productos:

- **`pam_tsi_authenticator.so`** — módulo PAM que verifica el código TOTP.
- **`tsi-enroll`** — genera y registra el secreto del usuario.

---

## 1. Dependencias para Compilar

- `gcc`, `make`, `cmake`, `git`
- PAM (headers de desarrollo)
- libgcrypt (headers de desarrollo)
- libcotp **≥ 4.0.0** (se compila desde el fuente; versiones previas no compilan por `COTP_SHA1`)
- `qrencode` (solo en tiempo de ejecución de `tsi-enroll`)

---

## 2. Ubuntu (24.04 LTS)

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

`make install` detecta la ruta de módulos PAM según la distro.

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

1. Genera un secreto de 160 bits en `~/.tsi_authenticator` (permisos `0600`).
2. Muestra el QR (requiere `qrencode`) y el secreto en texto.
3. Pide un código para confirmar; si falla, elimina el secreto.

> **8 dígitos.** Google Authenticator no los soporta. Usar **Aegis** o **FreeOTP** (Android), **Raivo** / **2FAS** (iOS). Prueba sin teléfono:
> `oathtool --totp -b --digits=8 <SECRETO_BASE32>`.

Verificar:

```bash
ls -l ~/.tsi_authenticator     # -rw------- (0600)
cat ~/.tsi_authenticator
```

Formato del archivo:

```
SECRET=<Base32>
WINDOW=3                          # config (admin)
RATE_LIMIT=3                      # config (admin): fallos antes de bloquear
LOCK_TIME=300                     # config (admin): segundos de bloqueo
FAIL_COUNT=0                      # estado (módulo)
LOCKED_UNTIL=0                    # estado (módulo): epoch de fin de bloqueo, 0 = libre
USED_CODE=<timestamp>:<codigo>    # estado (módulo): No-Replay
```

`WINDOW`, `RATE_LIMIT` y `LOCK_TIME` los puede ajustar el admin. `FAIL_COUNT`, `LOCKED_UNTIL` y `USED_CODE` los gestiona el módulo automáticamente; no editarlos (salvo poner `LOCKED_UNTIL=0` para desbloquear a un usuario).

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

Argumentos opcionales: `debug`, `nullok`, `window=N`.

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

```bash
sudo ausearch -m avc -ts recent          # buscar denegaciones del módulo
restorecon -v ~/.tsi_authenticator       # corregir contexto
sudo setenforce 0                         # permisivo (temporal, solo para pruebas)
sudo setenforce 1                         # volver a enforcing
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
| Código válido rechazado al reintentar | No-Replay (código ya usado) | Esperar el siguiente código |
| "Demasiados intentos fallidos" | Rate-limit activo | Esperar `LOCK_TIME`, o `LOCKED_UNTIL=0` en el archivo |
| El QR no aparece | Falta `qrencode` | Instalar `qrencode` |

---

## 12. Desinstalación

```bash
sudo make uninstall
```

No borra los `~/.tsi_authenticator` de cada usuario; eliminarlos por separado si se desea.
