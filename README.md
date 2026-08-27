# tsi-taller1
Código y documentación correspondiente al taller 1 del curso TSI

## 1. Dependencias para Compilar

- `gcc`, `make`, `cmake`, `git`
- PAM (headers de desarrollo)
- libgcrypt (headers de desarrollo)
- libcotp **≥ 4.0.0** (se compila desde el fuente; versiones previas no compilan por `COTP_SHA1`)
- `qrencode` (solo en tiempo de ejecución de `tsi-enroll`)

---

## 2. Ubuntu (26.04 LTS)

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

`make install` detecta la ruta de módulos PAM según la distro y crea el directorio root-only `/var/lib/tsi_authenticator/` (`0700`), donde el módulo guarda la config y el estado de cada usuario.

---
