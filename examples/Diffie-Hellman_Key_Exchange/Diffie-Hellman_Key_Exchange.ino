#include <WiFi.h>
#include "HW_AES.h"

// ripped from
// https://gist.github.com/cloudwu/8838724
// adapted for ESP32 to use esp_random();
// which requires WiFi or BLE to be turned on.

boolean checkConnection() {
  int count = 0;
  Serial.print("Waiting for Wi-Fi connection");
  while (count < 30) {
    if (WiFi.status() == WL_CONNECTED) {
      Serial.println("\nConnected!");
      return (true);
    }
    delay(500);
    Serial.print(".");
    count++;
  }
  Serial.println("Timed out.");
  return false;
}


// The biggest 64bit prime
#define P 0xffffffffffffffc5ull
#define G 5

// calc a * b % p , avoid 64bit overflow
static inline uint64_t mul_mod_p(uint64_t a, uint64_t b) {
  uint64_t m = 0;
  while (b) {
    if (b & 1) {
      uint64_t t = P - a;
      if ( m >= t) {
        m -= t;
      } else {
        m += a;
      }
    }
    if (a >= P - a) {
      a = a * 2 - P;
    } else {
      a = a * 2;
    }
    b >>= 1;
  }
  return m;
}

static inline uint64_t pow_mod_p(uint64_t a, uint64_t b) {
  if (b == 1) {
    return a;
  }
  uint64_t t = pow_mod_p(a, b >> 1);
  t = mul_mod_p(t, t);
  if (b % 2) {
    t = mul_mod_p(t, a);
  }
  return t;
}

// calc a^b % p
uint64_t powmodp(uint64_t a, uint64_t b) {
  if (a > P)
    a %= P;
  return pow_mod_p(a, b);
}

uint64_t randomint64() {
  uint64_t a = esp_random();
  uint64_t b = esp_random();
  uint64_t c = esp_random();
  uint64_t d = esp_random();
  return a << 48 | b << 32 | c << 16 | d;
}

static void test() {
  unsigned char buf[32];
  uint64_t a[4];
  uint64_t b[4], A[4], B[4], secret1, secret2;
  uint8_t i;

  for (i = 0; i < 4; i++) {
    a[i] = randomint64();
    b[i] = randomint64();
    A[i] = powmodp(G, a[i]);
    B[i] = powmodp(G, b[i]);
    secret1 = powmodp(B[i], a[i]);
    secret2 = powmodp(A[i], b[i]);

    if (secret1 != secret2) {
      Serial.println("\nBig fail! [" + String(i) + "]");
      return;
    }
    memcpy(buf + (i * 8), &secret1, 8);
  }
  Serial.println(" passed!");
  Serial.println("Secret:");
  esp_aes_hw_hexDump(buf, 32);

  Serial.println("a:");
  for (i = 0; i < 4; i++) memcpy(buf + (i * 8), &a[i], 8);
  esp_aes_hw_hexDump(buf, 32);

  Serial.println("A:");
  for (i = 0; i < 4; i++) memcpy(buf + (i * 8), &A[i], 8);
  esp_aes_hw_hexDump(buf, 32);

  Serial.println("b:");
  for (i = 0; i < 4; i++) memcpy(buf + (i * 8), &b[i], 8);
  esp_aes_hw_hexDump(buf, 32);

  Serial.println("B:");
  for (i = 0; i < 4; i++) memcpy(buf + (i * 8), &B[i], 8);
  esp_aes_hw_hexDump(buf, 32);
}

void setup() {
  Serial.begin(115200);

  for (uint8_t t = 4; t > 0; t--) {
    Serial.printf("[SETUP] WAIT %d...\n", t);
    Serial.flush();
    delay(1000);
  }
  String wifi_ssid = "YOUR_SSID";
  String wifi_password = "YOUR_PWD";
  Serial.print("WIFI-SSID: ");
  Serial.println(wifi_ssid);
  Serial.print("WIFI-PASSWD: ");
  Serial.println(wifi_password);

  WiFi.begin(wifi_ssid.c_str(), wifi_password.c_str());
  bool x = false;
  while (!x) {
    Serial.write(' ');
    x = checkConnection();
  }
  Serial.println(WiFi.softAPIP());

  int i;
  for (i = 0; i < 10; i++) {
    Serial.print("\nTest " + String(i));
    test();
  }
}

void loop() {
}

