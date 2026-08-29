#ifndef TSI_KEY_INIT_H
#define TSI_KEY_INIT_H

#include <unistd.h>
#include <fcntl.h>
#include <gcrypt.h>

#define MASTER_KEY_SIZE 32
#define TSI_KEY_DIR "/etc/tsi_authenticator"
#define MASTER_KEY_PATH TSI_KEY_DIR "/master.key"

#endif /* TSI_KEY_INIT_H */
