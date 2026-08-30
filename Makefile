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

KEY_INIT      := tsi-key-init
KEY_INIT_SRC  := src/tsi_key_init.c
KEY_INIT_LIBS := -lgcrypt

SEED_CRYPTO      := tsi-seed-crypto
SEED_CRYPTO_SRC  := src/tsi_seed_crypto.c
SEED_CRYPTO_LIBS := -lgcrypt

# Politica necesaria cuando SELinux esta activo (Rocky/RHEL/Fedora).
SELINUX_POLICY := tsi_authenticator
SELINUX_DIR    := selinux
SELINUX_MAKE   := /usr/share/selinux/devel/Makefile
KEYDIR         := /etc/tsi_authenticator

# Ruta de instalación de módulos PAM: difiere entre distros.
# Se puede sobrescribir: make install SECURITYDIR=/otra/ruta
SECURITYDIR ?= $(shell test -d /usr/lib64/security && echo /usr/lib64/security || echo /usr/lib/x86_64-linux-gnu/security)

# --- Targets ---

all: $(ENROLL) $(MODULE) $(HELPER) $(KEY_INIT) $(SEED_CRYPTO)

# El módulo se compila como objeto compartido: -fPIC -shared
$(MODULE): $(MODULE_SRC) $(LIBSRC) $(STATESRC)
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $(MODULE_SRC) $(LIBSRC) $(STATESRC) $(MODULE_LIBS)

# El enrolamiento es un ejecutable normal: sin -fPIC ni -shared
$(ENROLL): $(ENROLL_SRC) $(LIBSRC) $(STATESRC)
	$(CC) $(CFLAGS) -o $@ $(ENROLL_SRC) $(LIBSRC) $(STATESRC) $(ENROLL_LIBS)

# Helper minimo: solo linkea tsi_state.c (sin crypto) para reducir la superficie setuid
$(HELPER): $(HELPER_SRC) $(STATESRC)
	$(CC) $(CFLAGS) -o $@ $(HELPER_SRC) $(STATESRC)

$(KEY_INIT): $(KEY_INIT_SRC)
	$(CC) $(CFLAGS) -o $@ $(KEY_INIT_SRC) $(KEY_INIT_LIBS)

$(SEED_CRYPTO): $(SEED_CRYPTO_SRC)
	$(CC) $(CFLAGS) -o $@ $(SEED_CRYPTO_SRC) $(SEED_CRYPTO_LIBS)

# Directorio root-only donde el modulo guarda config+estado por usuario (<uid>_tsi_config)
STATEDIR ?= /var/lib/tsi_authenticator

install: $(ENROLL) $(MODULE) $(HELPER) $(KEY_INIT) $(SEED_CRYPTO)
	install -m 0755 $(ENROLL) /usr/local/bin/
	install -m 4755 $(HELPER) /usr/local/bin/
	install -m 4755 $(SEED_CRYPTO) /usr/local/bin/
	install -m 0755 $(KEY_INIT) /usr/local/sbin/
	/usr/local/sbin/$(KEY_INIT)
	install -d $(SECURITYDIR)
	install -m 0644 $(MODULE) $(SECURITYDIR)/$(MODULE)
	install -d -m 0700 $(STATEDIR)
	@if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then \
		if [ ! -f "$(SELINUX_MAKE)" ] || ! command -v semanage >/dev/null 2>&1; then \
			echo "Error: SELinux esta activo. Instale selinux-policy-devel y policycoreutils-python-utils."; \
			exit 1; \
		fi; \
		$(MAKE) -f "$(SELINUX_MAKE)" -C "$(SELINUX_DIR)" "$(SELINUX_POLICY).pp" || exit 1; \
		semodule -i "$(SELINUX_DIR)/$(SELINUX_POLICY).pp" || exit 1; \
		semanage fcontext -a -t tsi_auth_state_t '$(STATEDIR)(/.*)?' 2>/dev/null || \
			semanage fcontext -m -t tsi_auth_state_t '$(STATEDIR)(/.*)?' || exit 1; \
		semanage fcontext -a -t tsi_auth_key_t '$(KEYDIR)/master\.key' 2>/dev/null || \
			semanage fcontext -m -t tsi_auth_key_t '$(KEYDIR)/master\.key' || exit 1; \
		restorecon -R "$(STATEDIR)" "$(KEYDIR)" || exit 1; \
	fi

# Deja el sistema limpio de todo lo que puso 'make install'
uninstall:
	@if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled && \
		command -v semanage >/dev/null 2>&1; then \
		semanage fcontext -d '$(STATEDIR)(/.*)?' 2>/dev/null || true; \
		semanage fcontext -d '$(KEYDIR)/master\.key' 2>/dev/null || true; \
		restorecon -R "$(KEYDIR)" 2>/dev/null || true; \
		semodule -r "$(SELINUX_POLICY)" 2>/dev/null || true; \
	fi
	rm -f /usr/local/bin/$(ENROLL)
	rm -f /usr/local/bin/$(HELPER)
	rm -f /usr/local/bin/$(SEED_CRYPTO)
	rm -f /usr/local/sbin/$(KEY_INIT)
	rm -f $(SECURITYDIR)/$(MODULE)
	rm -rf $(STATEDIR)

clean:
	rm -f $(ENROLL) $(MODULE) $(HELPER) $(KEY_INIT) $(SEED_CRYPTO) src/*.o
	rm -f $(SELINUX_DIR)/$(SELINUX_POLICY).pp $(SELINUX_DIR)/$(SELINUX_POLICY).cil
	rm -f $(SELINUX_DIR)/tmp/*.tmp $(SELINUX_DIR)/tmp/*.te $(SELINUX_DIR)/tmp/*.mod

# Limpieza total: desinstala del sistema y borra los binarios locales
remove: uninstall clean

.PHONY: all install uninstall remove clean
