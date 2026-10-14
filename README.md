# ALIEN-ESP

WiFi and BLE toolkit for the ESP32-WROOM-32. One OLED, one button, no SD card, no PC tether. Everything runs from the menu, and firmware updates come in over WiFi.

Started as a weekend experiment to see how much a ₹500 board could actually do. Turned into a full toolkit that fits in your pocket.

---

## Features

**Recon**
- `WiFi Scan` — nearby APs with SSID, channel, RSSI
- `Probe Sniff` — passive capture of probe requests
- `Packet Mon` — 802.11 frame counter, hops channels
- `Hidden SSID` — reveals networks that broadcast without an SSID
- `Congestion` — channel activity graph, quiet channels stand out

**WiFi tests** *(authorized use only)*
- `Auto Attack` — scans, picks the strongest WPA2 AP, fires deauth, grabs PMKID and EAPOL handshake
- `PMKID` — manual target, hops channels, auto-deauth
- `Deauth` — broadcast deauthentication flood
- `Targeted Deauth` — locks one client, kicks only that device

**Captive portals** *(authorized use only)*
- `Karma Portal` — open AP with a login page
- `Rogue AP` — clones the strongest nearby SSID, same portal
- `2FA Portal` — two stages: email/password, then a 6-digit OTP page

**Bluetooth**
- `BLE Spam` — cycles Apple / Samsung / Microsoft pairing ad patterns

**2.4 GHz**
- `RF Sweep` — [nRF24L01+ required] transmits across the 2.4 GHz band. For congestion testing on your own equipment.

**Utility**
- `Info` — RAM, uptime, chip temperature, nRF24 status, saved capture counts
- `OTA Update` — over-the-air firmware updates, no cable needed

---

## Hardware

- ESP32-WROOM-32 dev board (any 30-pin board with a CH340 works)
- 0.96" SSD1306 OLED, I2C, 128×64, address `0x3C` or `0x3D`
- nRF24L01+ PA+LNA — optional, only for RF Sweep
- A push button — the onboard BOOT button (GPIO 0) works

Use the adapter breakout board with the nRF24. The bare module browns out under WiFi load without the onboard capacitor.

---

## Wiring

OLED:

```
GND  →  GND
VCC  →  3V3
SDA  →  GPIO 21
SCL  →  GPIO 22
```

nRF24 (optional):

```
GND  →  GND
VCC  →  3V3  (through the adapter board)
CE   →  GPIO 27
CSN  →  GPIO 26
SCK  →  GPIO 18
MOSI →  GPIO 23
MISO →  GPIO 19
IRQ  →  leave empty
```

---

## Flashing

**Prebuilt**

Grab the latest `.bin` from the `firmware/` folder in this repo. Flash the four files at these offsets with ESP32_Flasher, esptool, or the Espressif tool:

| file | offset |
|---|---|
| `ALIEN-ESP.ino.bootloader.bin` | `0x1000` |
| `ALIEN-ESP.ino.partitions.bin` | `0x8000` |
| `boot_app0.bin` | `0xe000` |
| `ALIEN-ESP.ino.bin` | `0x10000` |

Or use the merged bin if there is one — flash at `0x0`.

**From source**

You need `arduino-cli`, ESP32 core 3.x, and four libraries.

```
arduino-cli config init
arduino-cli config add board_manager.additional_urls https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
arduino-cli core update-index
arduino-cli core install esp32:esp32
arduino-cli lib install "Adafruit SSD1306"
arduino-cli lib install "Adafruit GFX Library"
arduino-cli lib install "Adafruit BusIO"
arduino-cli lib install "RF24"
arduino-cli compile --fqbn esp32:esp32:esp32:PartitionScheme=min_spiffs ALIEN-ESP/ALIEN-ESP.ino
```

The `min_spiffs` partition scheme is required. It provides the two OTA slots the update system uses.

---

## Using it

Menu navigation is on the onboard **BOOT** button.

- Short press — next item
- Hold ~0.6s — enter the selected feature
- Hold inside a feature — exit back to the menu

Live stats show on the OLED. Everything else — hashes, captured credentials, scan output — goes to serial at **115200**. Keep a serial terminal open while you work.

---

## OTA updates

Menu → `OTA Update`.

1. OLED shows the AP name and IP
2. Connect to WiFi **ALIEN-OTA**, password **12345678**
3. Turn off mobile data on your phone so it doesn't hop networks
4. Open `http://192.168.4.1`
5. Upload the new `.bin`
6. It reboots into the new firmware

That's the normal update path. USB is only needed the first time.

---

## Captures and cracking

PMKID and EAPOL output print to serial in **hashcat 22000** format:

```
WPA*01*<pmkid>*<ap_mac>*<sta_mac>*<ssid_hex>***
WPA*02*<mic>*<ap_mac>*<sta_mac>*<ssid_hex>*<anonce>*<eapol>*02
```

Save any line to a `.22000` file and crack offline:

```
hashcat -m 22000 capture.22000 wordlist.txt
```

Everything also gets written to SPIFFS on the chip, so captures survive reboots. Counts show up on the `Info` screen.

---

## Legal

This project is for **educational purposes and authorized security testing** only. That means testing on networks and devices you own, or that you have explicit written permission to test.

Using any of these features against infrastructure, networks, or devices without authorization is illegal in most jurisdictions, including under the Indian Information Technology Act, 2000 (Sections 43, 65, 66), and equivalent laws worldwide.

The author provides this software for learning and for authorized assessments. **The author assumes no responsibility or liability for misuse, damages, or legal consequences resulting from use of this software.** If you're not certain a target is in scope, it isn't. Get permission or point it at your own gear.

---

## How this was made

The project was designed, wired, tested, and debugged by me on real hardware over several weeks. Every feature choice, every menu item, and every fix was directed and verified by hand.

The C++ source was written with AI assistance, in the same way many developers now use code assistants to draft and iterate on code. The architecture, feature set, hardware integration, and testing were all mine — the AI was a tool in the workflow, not the author.

If you use AI in your own projects and someone gives you grief about it, tell them to touch grass. It's 2026.

---

## Credits

- [Espressif](https://github.com/espressif/arduino-esp32) — ESP32 core
- [Adafruit](https://github.com/adafruit) — SSD1306 and GFX libraries
- [TMRh20](https://github.com/nRF24/RF24) — RF24 library
- [justcallmekoko](https://github.com/justcallmekoko/ESP32Marauder) — inspiration for the project

---

## License

GPLv3. See [LICENSE](LICENSE).
