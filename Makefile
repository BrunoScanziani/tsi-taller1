# Makefile — TSI Authenticator (módulo PAM + app de enrolamiento)
# Taller de Seguridad Informática

CC      := gcc
CFLAGS  := -Wall -Wextra -Iinclude

# La biblioteca compartida por ambos productos
LIBSRC  := src/tsi_authenticator.c

# Funciones de estado (sin crypto): las comparte el helper setuid
STATESRC := src/tsi_state.c

# Módulo PAM
MODULE      := pam_tsi_authenticator.so
MODULE_SRC  := src/pam_tsi_authenticator.c
MODULE_LIBS := -lpam -lcotp -lgcrypt

# App de enrolamiento
ENROLL      := tsi-enroll
ENROLL_SRC  := src/enroll.c
ENROLL_LIBS := -lcotp -lgcrypt

# Helper setuid-root que crea el archivo de config root-only del usuario
HELPER      := tsi-config-init
HELPER_SRC  := src/tsi_config_init.c

# Suite de tests (integracion contra el .so real via libpam)
TEST_BIN    := test/test_pam
TEST_SRC    := test/test_pam.c
TEST_LIBS   := -lpam -lcotp

# Ruta de instalación de módulos PAM: difiere entre distros.
# Se puede sobrescribir: make install SECURITYDIR=/otra/ruta
SECURITYDIR ?= $(shell test -d /usr/lib64/security && echo /usr/lib64/security || echo /usr/lib/x86_64-linux-gnu/security)

# --- Targets ---

all: $(ENROLL) $(MODULE) $(HELPER)

# El módulo se compila como objeto compartido: -fPIC -shared
$(MODULE): $(MODULE_SRC) $(LIBSRC) $(STATESRC)
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $(MODULE_SRC) $(LIBSRC) $(STATESRC) $(MODULE_LIBS)

# El enrolamiento es un ejecutable normal: sin -fPIC ni -shared
$(ENROLL): $(ENROLL_SRC) $(LIBSRC) $(STATESRC)
	$(CC) $(CFLAGS) -o $@ $(ENROLL_SRC) $(LIBSRC) $(STATESRC) $(ENROLL_LIBS)

# Helper minimo: solo linkea tsi_state.c (sin crypto) para reducir la superficie setuid
$(HELPER): $(HELPER_SRC) $(STATESRC)
	$(CC) $(CFLAGS) -o $@ $(HELPER_SRC) $(STATESRC)

# Compila el modulo y corre la suite de tests contra el .so recien construido.
$(TEST_BIN): $(TEST_SRC) $(MODULE)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRC) $(TEST_LIBS)

test: $(TEST_BIN)
	./$(TEST_BIN) "$(abspath $(MODULE))"

# Directorio root-only donde el modulo guarda config+estado por usuario (<uid>_tsi_config)
STATEDIR ?= /var/lib/tsi_authenticator

install: $(ENROLL) $(MODULE) $(HELPER)
	install -m 0755 $(ENROLL) /usr/local/bin/
	install -m 4755 $(HELPER) /usr/local/bin/
	install -d $(SECURITYDIR)
	install -m 0644 $(MODULE) $(SECURITYDIR)/$(MODULE)
	install -d -m 0700 $(STATEDIR)

# Deja el sistema limpio de todo lo que puso 'make install'
uninstall:
	rm -f /usr/local/bin/$(ENROLL)
	rm -f /usr/local/bin/$(HELPER)
	rm -f $(SECURITYDIR)/$(MODULE)
	rm -rf $(STATEDIR)

clean:
	rm -f $(ENROLL) $(MODULE) $(HELPER) $(TEST_BIN) src/*.o

# Limpieza total: desinstala del sistema y borra los binarios locales
remove: uninstall clean

.PHONY: all install uninstall remove clean test
