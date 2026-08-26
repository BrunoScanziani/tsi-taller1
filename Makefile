# Makefile — TSI Authenticator (módulo PAM + app de enrolamiento)
# Taller de Seguridad Informática

CC      := gcc
CFLAGS  := -Wall -Wextra -Iinclude

# La biblioteca compartida por ambos productos
LIBSRC  := src/tsi_authenticator.c

# Módulo PAM
MODULE      := pam_tsi_authenticator.so
MODULE_SRC  := src/pam_tsi_authenticator.c
MODULE_LIBS := -lpam -lcotp -lgcrypt

# App de enrolamiento
ENROLL      := tsi-enroll
ENROLL_SRC  := src/enroll.c
ENROLL_LIBS := -lcotp -lgcrypt

# Suite de tests (integracion contra el .so real via libpam)
TEST_BIN    := test/test_pam
TEST_SRC    := test/test_pam.c
TEST_LIBS   := -lpam -lcotp

# Ruta de instalación de módulos PAM: difiere entre distros.
# Se puede sobrescribir: make install SECURITYDIR=/otra/ruta
SECURITYDIR ?= $(shell test -d /usr/lib64/security && echo /usr/lib64/security || echo /usr/lib/x86_64-linux-gnu/security)

# --- Targets ---

all: $(ENROLL) $(MODULE)

# El módulo se compila como objeto compartido: -fPIC -shared
$(MODULE): $(MODULE_SRC) $(LIBSRC)
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $(MODULE_SRC) $(LIBSRC) $(MODULE_LIBS)

# El enrolamiento es un ejecutable normal: sin -fPIC ni -shared
$(ENROLL): $(ENROLL_SRC) $(LIBSRC)
	$(CC) $(CFLAGS) -o $@ $(ENROLL_SRC) $(LIBSRC) $(ENROLL_LIBS)

# Compila el modulo y corre la suite de tests contra el .so recien construido.
$(TEST_BIN): $(TEST_SRC) $(MODULE)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRC) $(TEST_LIBS)

test: $(TEST_BIN)
	./$(TEST_BIN) "$(abspath $(MODULE))"

install: $(ENROLL) $(MODULE)
	install -m 0755 $(ENROLL) /usr/local/bin/
	install -d $(SECURITYDIR)
	install -m 0644 $(MODULE) $(SECURITYDIR)/$(MODULE)

uninstall:
	rm -f /usr/local/bin/$(ENROLL)
	rm -f $(SECURITYDIR)/$(MODULE)

clean:
	rm -f $(ENROLL) $(MODULE) $(TEST_BIN) src/*.o

.PHONY: all install uninstall clean test
