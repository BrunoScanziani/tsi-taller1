# Makefile — TSI Authenticator (módulo PAM + app de enrolamiento)
# Taller de Seguridad Informática

CC      := gcc
CFLAGS  := -Wall -Wextra -Iinclude

# La biblioteca compartida por ambos productos
LIBSRC  := src/tsi_authenticator.c

# Módulo PAM
#MODULE      := pam_tsi_authenticator.so
#MODULE_SRC  := src/pam_tsi_authenticator.c
#MODULE_LIBS := -lpam -lcotp -lgcrypt

# App de enrolamiento
ENROLL      := tsi-enroll
ENROLL_SRC  := src/enroll.c
ENROLL_LIBS := -lcotp -lgcrypt

# Ruta de instalación de módulos PAM: difiere entre distros.
# Se puede sobrescribir: make install SECURITYDIR=/otra/ruta
SECURITYDIR ?= $(shell test -d /usr/lib64/security && echo /usr/lib64/security || echo /usr/lib/x86_64-linux-gnu/security)

# --- Targets ---

all: $(ENROLL) #$(MODULE)

# El módulo se compila como objeto compartido: -fPIC -shared
#$(MODULE): $(MODULE_SRC) $(LIBSRC)
#	$(CC) $(CFLAGS) -fPIC -shared -o $@ $(MODULE_SRC) $(LIBSRC) $(MODULE_LIBS)

# El enrolamiento es un ejecutable normal: sin -fPIC ni -shared
$(ENROLL): $(ENROLL_SRC) $(LIBSRC)
	$(CC) $(CFLAGS) -o $@ $(ENROLL_SRC) $(LIBSRC) $(ENROLL_LIBS)

install: $(ENROLL) 
	install -m 0755 $(ENROLL) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(ENROLL)

clean:
	rm -f $(ENROLL) src/*.o

.PHONY: all install uninstall clean