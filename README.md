# HW_AES
Sample ESP32/Arduino IDE code demonstrating the basics of hardware-accelerated AES

Basic functions ripped from hwcrypto/aes.c.

# Functions:

- void esp_aes_hw_hexDump(unsigned char *, uint16_t);
  Hex dump of a buffer.
- uint8_t esp_aes_hw_multiple_blocks(int, unsigned char *, unsigned char *, unsigned char *, uint16_t);
- int esp_aes_hw_crypt_cbc(int, size_t, unsigned char[16], const unsigned char *, const unsigned char *, unsigned char *);
- int esp_aes_hw_crypt_cfb8(int, size_t, unsigned char[16], const unsigned char *, const unsigned char *, unsigned char 

# Installation:

- Put the HW_AES folder into the Arduino/libraries folder.

The Diffie-Hellman_Key_Exchange.ino sketch is a proof of concept for key exchange.
