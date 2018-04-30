#ifndef _HW_AES_H_
#define _HW_AES_H_

#include <string.h>
#include "mbedtls/aes.h"
#include "hwcrypto/aes.h"
#include "soc/dport_reg.h"
#include "soc/hwcrypto_reg.h"
#include <sys/lock.h>
#include <freertos/FreeRTOS.h>
#include "soc/cpu.h"
#include <stdio.h>

static portMUX_TYPE aes_spinlock = portMUX_INITIALIZER_UNLOCKED;

void esp_aes_hw_acquire_hardware(void);
void esp_aes_hw_release_hardware(void);
void esp_aes_hw_init(esp_aes_context *);
void esp_aes_hw_free(esp_aes_context *);
int esp_aes_hw_setkey(esp_aes_context *, const unsigned char *, unsigned int);
static inline void esp_aes_hw_setkey_hardware(esp_aes_context *, int);
static inline void esp_aes_hw_block(const void *, void *);
void esp_aes_hw_hexDump(unsigned char *, uint16_t);
uint8_t esp_aes_hw_multiple_blocks(int, unsigned char *, unsigned char *, unsigned char *, uint16_t);
int esp_aes_hw_crypt_cbc(int, size_t, unsigned char[16], const unsigned char *, const unsigned char *, unsigned char *);
int esp_aes_hw_crypt_cfb8(int, size_t, unsigned char[16], const unsigned char *, const unsigned char *, unsigned char *);
#endif

