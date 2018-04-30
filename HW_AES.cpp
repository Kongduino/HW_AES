#include <Arduino.h>
#include "HW_AES.h"

/*
        HARDWARE HELPER FUNCTIONS
*/

void esp_aes_hw_acquire_hardware(void) {
  /* newlib locks lazy initialize on ESP-IDF */
  portENTER_CRITICAL(&aes_spinlock);
  DPORT_STALL_OTHER_CPU_START();
  {
    /* Enable AES hardware */
    _DPORT_REG_SET_BIT(DPORT_PERI_CLK_EN_REG, DPORT_PERI_EN_AES);
    /* Clear reset on digital signature & secure boot units,
       otherwise AES unit is held in reset also. */
    _DPORT_REG_CLR_BIT(
      DPORT_PERI_RST_EN_REG,
      DPORT_PERI_EN_AES
      | DPORT_PERI_EN_DIGITAL_SIGNATURE
      | DPORT_PERI_EN_SECUREBOOT
    );
  }
  DPORT_STALL_OTHER_CPU_END();
}

void esp_aes_hw_release_hardware(void) {
  DPORT_STALL_OTHER_CPU_START();
  {
    /* Disable AES hardware */
    _DPORT_REG_SET_BIT(DPORT_PERI_RST_EN_REG, DPORT_PERI_EN_AES);
    /* Don't return other units to reset, as this pulls
       reset on RSA & SHA units, respectively. */
    _DPORT_REG_CLR_BIT(DPORT_PERI_CLK_EN_REG, DPORT_PERI_EN_AES);
  }
  DPORT_STALL_OTHER_CPU_END();
  portEXIT_CRITICAL(&aes_spinlock);
}

void esp_aes_hw_init(esp_aes_context *ctx) {
  if (ctx == NULL) {
    Serial.println("ctx is NULL!");
    while (1);
  }
}

void esp_aes_hw_free(esp_aes_context *ctx) {
  if (ctx == NULL) return;
  bzero(ctx, sizeof(esp_aes_context));
}

/*
   AES key schedule (same for encryption or decryption, as hardware handles schedule)
*/
int esp_aes_hw_setkey(esp_aes_context *ctx, const unsigned char *key, unsigned int keybits) {
  if (keybits != 128 && keybits != 192 && keybits != 256) return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
  ctx->key_bytes = keybits / 8;
  memcpy(ctx->key, key, ctx->key_bytes);
  return 0;
}

/*
   Helper function to copy key from esp_aes_context buffer
   to hardware key registers.

   Call only while holding esp_aes_hw_acquire_hardware().
*/
static inline void esp_aes_hw_setkey_hardware(esp_aes_context *ctx, int mode) {
  const uint32_t MODE_DECRYPT_BIT = 4;
  unsigned mode_reg_base = (mode == ESP_AES_ENCRYPT) ? 0 : MODE_DECRYPT_BIT;
  memcpy((uint32_t *)AES_KEY_BASE, ctx->key, ctx->key_bytes);
  DPORT_REG_WRITE(AES_MODE_REG, mode_reg_base + ((ctx->key_bytes / 8) - 2));
}

/* Run a single 16 byte block of AES, using the hardware engine.

   Call only while holding esp_aes_hw_acquire_hardware().
*/
static inline void esp_aes_hw_block(const void *input, void *output) {
  const uint32_t *input_words = (const uint32_t *)input;
  uint32_t *output_words = (uint32_t *)output;
  uint32_t *mem_block = (uint32_t *)AES_TEXT_BASE;
  for (int i = 0; i < 4; i++) {
    mem_block[i] = input_words[i];
  }
  DPORT_REG_WRITE(AES_START_REG, 1);
  DPORT_STALL_OTHER_CPU_START();
  {
    while (_DPORT_REG_READ(AES_IDLE_REG) != 1) { }
    for (int i = 0; i < 4; i++) {
      output_words[i] = mem_block[i];
    }
  }
  DPORT_STALL_OTHER_CPU_END();
}

void esp_aes_hw_hexDump(unsigned char *buf, uint16_t len) {
  String s = "|", t = "| |";
  Serial.println(F("+------------------------------------------------+ +----------------+"));
  for (uint16_t i = 0; i < len; i += 16) {
    for (uint8_t j = 0; j < 16; j++) {
      if (i + j >= len) {
        s = s + "   "; t = t + " ";
      } else {
        char c = buf[i + j];
        if (c < 16) s = s + "0";
        s = s + String(c, HEX) + " ";
        if (c < 32 || c > 127) t = t + ".";
        else t = t + (char)c;
      }
    }
    Serial.println(s + t + "|");
    s = "|"; t = "| |";
  }
  Serial.println(F("+------------------------------------------------+ +----------------+"));
}

/*
        AES FUNCTIONS
*/

/*
   AES-ECB buffer encryption/decryption
*/
int esp_aes_hw_crypt_ecb(
  int mode, size_t length, unsigned char iv[16], const unsigned char *key,
  const unsigned char *input, unsigned char *output
) {
  int i;
  uint32_t *output_words = (uint32_t *)output;
  const uint32_t *input_words = (const uint32_t *)input;
  uint32_t *iv_words = (uint32_t *)iv;
  unsigned char temp[16];
  esp_aes_context ctx;
  esp_aes_hw_init(&ctx);
  esp_aes_hw_setkey(&ctx, key, 256);
  if (length % 16) return (ERR_ESP_AES_INVALID_INPUT_LENGTH);
  esp_aes_hw_setkey(&ctx, key, 256);
  esp_aes_hw_acquire_hardware();
  esp_aes_hw_setkey_hardware(&ctx, mode);
  for (i = 0; i < length; i += 16)
    esp_aes_crypt_ecb(&ctx, mode, &input[i], &output[i]);
  esp_aes_hw_release_hardware();
  return 0;
}

/*
   AES-CBC buffer encryption/decryption
*/
int esp_aes_hw_crypt_cbc(
  int mode, size_t length, unsigned char iv[16], const unsigned char *key,
  const unsigned char *input, unsigned char *output
) {
  int i;
  uint32_t *output_words = (uint32_t *)output;
  const uint32_t *input_words = (const uint32_t *)input;
  uint32_t *iv_words = (uint32_t *)iv;
  unsigned char temp[16];
  esp_aes_context ctx;
  esp_aes_hw_init(&ctx);
  esp_aes_hw_setkey(&ctx, key, 256);
  if (length % 16) return (ERR_ESP_AES_INVALID_INPUT_LENGTH);
  esp_aes_hw_setkey(&ctx, key, 256);
  esp_aes_hw_acquire_hardware();
  esp_aes_hw_setkey_hardware(&ctx, mode);
  if (mode == ESP_AES_DECRYPT) {
    while (length > 0) {
      memcpy(temp, input_words, 16);
      esp_aes_hw_block(input_words, output_words);
      for (i = 0; i < 4; i++) output_words[i] = output_words[i] ^ iv_words[i];
      memcpy(iv_words, temp, 16);
      input_words += 4;
      output_words += 4;
      length -= 16;
    }
  } else { // ESP_AES_ENCRYPT
    while (length > 0) {
      for (i = 0; i < 4; i++) output_words[i] = input_words[i] ^ iv_words[i];
      esp_aes_hw_block(output_words, output_words);
      memcpy(iv_words, output_words, 16);
      input_words  += 4;
      output_words += 4;
      length -= 16;
    }
  }
  esp_aes_hw_release_hardware();
  return 0;
}

uint8_t esp_aes_hw_multiple_blocks(
  int mode, unsigned char *key, unsigned char *input,
  unsigned char *output, uint16_t len
) {
  uint16_t i = 0;
  esp_aes_context ctx;
  if (len % 16 != 0) {
    if (len < 16) return 16 - len;
    else return (uint8_t)(16 - (len % 16));
    // warn the user that we can't proceed
    // returning the required extra length
  }
  esp_aes_hw_init(&ctx);
  esp_aes_hw_setkey(&ctx, key, 256);
  esp_aes_hw_acquire_hardware();
  esp_aes_hw_setkey_hardware(&ctx, mode);
  for (i = 0; i < len; i += 16) esp_aes_hw_block(&input[i], &output[i]); // 16 bytes
  esp_aes_hw_release_hardware();
  esp_aes_hw_free(&ctx);
  return 0;
}

/*
 * AES-CFB8 buffer encryption/decryption
 */
int esp_aes_hw_crypt_cfb8(
  int mode, size_t length, unsigned char iv[16], const unsigned char *key,
  const unsigned char *input, unsigned char *output
) {
  unsigned char c;
  unsigned char ov[17];
  uint16_t i = 0;
  esp_aes_context ctx;
  esp_aes_hw_init(&ctx);
  esp_aes_hw_setkey(&ctx, key, 256);
  if (length % 16) return (ERR_ESP_AES_INVALID_INPUT_LENGTH);
  esp_aes_hw_setkey(&ctx, key, 256);
  esp_aes_hw_acquire_hardware();
  esp_aes_hw_setkey_hardware(&ctx, mode);
  while (length--) {
    memcpy(ov, iv, 16);
    esp_aes_hw_block(iv, iv);
    if (mode == ESP_AES_DECRYPT) ov[16] = *input;
    c = *output++ = (unsigned char)(iv[0] ^ *input++);
    if (mode == ESP_AES_DECRYPT) ov[16] = c;
    memcpy(iv, ov + 1, 16);
  }
  esp_aes_hw_release_hardware();
  esp_aes_hw_free(&ctx);
  return 0;
}
