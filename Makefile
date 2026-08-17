# Makefile — Módulo PAM TSI Authenticator
# Taller de Seguridad Informática

CC      := gcc
CFLAGS  := -fPIC -Wall -Wextra -Iinclude
LDFLAGS := -shared
LIBS    := -lpam

MODULE  := pam_tsi_authenticator.so
SRC     := src/pam_tsi_authenticator.c

# Ruta de instalación de módulos PAM: difiere entre distros.
# Se puede sobrescribir: make install SECURITYDIR=/otra/ruta
SECURITYDIR ?= $(shell test -d /usr/lib64/security && echo /usr/lib64/security || echo /usr/lib/x86_64-linux-gnu/security)

# --- Targets ---

all: $(MODULE)

$(MODULE): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC) $(LIBS)

install: $(MODULE)
	install -m 0755 $(MODULE) $(SECURITYDIR)/

uninstall:
	rm -f $(SECURITYDIR)/$(MODULE)

clean:
	rm -f $(MODULE) src/*.o

.PHONY: all install uninstall clean