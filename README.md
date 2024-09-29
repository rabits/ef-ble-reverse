# ef-ble-reverse

Independent DIY repository contains a set of experiments and scripts to connect to your ecoflow
devices through bluetooth and monitor their status / control parameters.

Devices:
* Smart Home Panel 2 (EF-HD3####, FW Version: 4.0.0.122, WiFi Version: 2.0.1.20)
* Delta Pro Ultra (EF-YJ####, FW Version: 5.0.0.25, WiFi Version: 2.0.2.4)

The whole process of RE took ~1 month evenings, I've solved a numerous challenges on the way, but
quite sure missed something - so will be glad if you can add to the information we have or help in
some other way.

## Goal

To develop a local solution to control ecoflow devices via homeassistant automation. Here is just
tools & experiments to share with community.

* Home Assistant integration: https://github.com/rabits/ha-ef-ble

## WARNING: Support & Warranty

Sorry, no support no warranty - you on your own and I take no responsibility for any of your
actions. We all grown-ups here and know that we deal with quite dangerous voltages and storage
devices that could injure or cause death. So make sure you know what you doing for each and every
step - otherwise you can't use the provided information in this repository.

In case you see some issues with your device after using this repo - ecoflow support could be
unable to help you. Author of the repo is not connected to ecoflow anyhow and they can't support
anything you will find here.

## Usage

You can start with reading of `connect.py` script - it allows to scan and connect (with proper
UserID and defined address) to auth and monitor the received packets.

You will need to do the next steps to use the script:
0. You have BLE adapter, Linux OS, python 3, pip, venv, bluez and knowledge how to use them
1. Setup the environment:
   ```sh
   $ python3 -m venv .venv
   $ . .venv/bin/activate
   (.venv)$ pip install -r requirements.txt
   ```
2. Generate login key - it will create file `login_key.bin`:
   ```sh
   (.venv)$ ./util/login_key_gen.py
   ```
3. Please make sure you read the connect.py
4. Run `connect.py`:
   ```sh
   (.venv)$ ./connect.py
   ```
5. If you did not change the script - it will list the available devices
6. Everything else is for the ones who read the script

## Example output

Next outputs shows parsed data from the receiving streams, they are repeating with updates:

### Smart Home Panel 2

```
...
<BT_ADDRESS>: DEBUG: autoAuthenticationHandler data: '00'
<BT_ADDRESS>: INFO: listenForData: Listening for data from device
<BT_ADDRESS>: ParseEncPackets: '5a 5a 10 01 e2 00 a3 bc e8 47 47 5f 27 fa 38 00 47 d4 07 ea a4 0f 20 42 ba 5c 38 81 fe a5 fe f1 e0 d8 fd 6d 49 4a 47 82 36 12 26 97 74 0a 1d 65 d6 cf c3 cf b6 e0 68 a1 4d 6c 86 e7 2d d8 36 cb e4 cd 45 62 60 7e c3 4e c9 4e 99 ec 13 4f f2 80 cb d5 f7 79 83 d5 f6 b0 79 17 ef ac 99 12 23 2d 4c ef 38 8f 02 e1 88 8a cd fa e6 6e c2 ed c2 47 b6 7e 70 53 7b 21 91 7a 3f 37 b2 a8 9b ce ea 5f 6e 01 ac 9f 23 a0 d6 79 89 55 eb c7 8b 60 b7 b0 a7 fc b8 aa 38 7f 0d 09 e0 f6 7e a5 b1 78 4a 12 96 6a 79 93 b9 c9 c4 61 5d 4b c9 55 ca a2 b4 fd 68 99 d9 8f e2 e3 a1 09 7e d6 b9 5e ad 58 b7 46 68 61 48 7c 43 b7 0e 6e 67 78 f9 df 61 dd 8d 39 57 7e 5c 74 ba 67 5b 4d 21 8f 4a 2f 67 7b 21 d7 9f f9 a4 ce 78 12 0d 4a 5a 5a 10 01 62 01 60 44 a9 8d cc a7 e0 0c 78 4a f7 de 16 62 c7 9e 06 61 92 8d ee 04 96 df 4b f1 30 c0 e0 6c 1a 36 66 59 3a 1a 62 5c 27 a9 6d e6 5c 55 1c a1 c7 1e f4 7b 5b ba 8e 1e 1a 5d 85 19 7f 7b db 31 21 10 bc c9 33 f5 c9 c8 50 83 17 57 90 5f a7 4b cb d4 e1 b0 ee 97 52 24 00 2d 86 10 c3 5d 3b 07 25 ad 78 eb 29 68 b7 a6 56 db aa 0d 62 85 4f 48 dc 2d d4 e0 ff 7f 5e 54 b4 70 d3 81 cd 7e ef 02 be 26 28 93 4a ec fa 4a 37 51 2a 63 21 b4 7c 07 ae fa fc 19 e5 96 4c 1f 2c 53 1a a6 4d e7 af ec d5 66 7a b5 43 68 32 02 a4 db 64 66 c4 ae 67 13 10 e7 3d 9c 20 62 c4 a4 7f f0 6d 29 2f 77 a5 24 a5 ca 65 1f d6 5b ed e1 f5 9b d6 c4 07 10 c2 2a 7c c0 d7 10 45 d0 92 a7 a0 7a 66 ef 6b 94 e6 0b c7 50 0b 66 63 74 7a e3 b4 9d ef 59 17 41 5c f6 7e bb dc 4c 18 1c 8a a0 75 64 27 ab 4e f2 fd c5 9e 87 b9 77 f2'
<BT_ADDRESS>: ParseEncPackets: decrypted payload: 'aa 13 c2 00 bb 01 01 00 00 00 04 30 0b 21 01 00 0c 01 0a 15 10 9f 06 22 10 41 6d 65 72 69 63 61 2f 4e 65 77 5f 59 6f 72 6b 12 64 0a 30 00 00 00 00 00 00 a0 41 00 00 ae 42 00 00 22 43 00 00 60 41 00 00 00 00 00 00 40 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 b7 43 12 30 d1 90 d8 3d 19 2e fa 3f 36 aa 92 3f a8 75 34 40 11 45 1d 3e 4f 7a ce 3d 00 a7 ed 3d 00 00 00 00 73 5f 6d 3e 00 00 00 00 8f 1f cd 3e d3 8a 67 40 1a 25 0a 0c 00 00 00 00 d9 09 ac c3 27 76 93 c3 10 be 08 aa 01 07 08 ff e4 08 10 a7 09 b2 01 07 08 ff e4 08 10 a3 09 22 14 5a 0c 00 00 00 00 d9 09 ac c3 27 76 93 c3 ad 01 00 40 29 44 2a 06 08 04 18 02 20 12 bb bb'
master_info {
  sys_timezone: -400
  timezone_id: "America/New_York"
}
load_info {
  hall1_watt: 0
  hall1_watt: 20
  hall1_watt: 87
  hall1_watt: 162
  hall1_watt: 14
  hall1_watt: 0
  hall1_watt: 12
  hall1_watt: 0
  hall1_watt: 0
  hall1_watt: 0
  hall1_watt: 0
  hall1_watt: 366
  hall1_curr: 0.105744965
  hall1_curr: 1.95453179
  hall1_curr: 1.14581943
  hall1_curr: 2.81968117
  hall1_curr: 0.15358378
  hall1_curr: 0.100819223
  hall1_curr: 0.116041183
  hall1_curr: 0
  hall1_curr: 0.231809422
  hall1_curr: 0
  hall1_curr: 0.400631398
  hall1_curr: 3.61784816
}
backup_info {
  ch_watt: 0
  ch_watt: -344.076935
  ch_watt: -294.923065
  backup_discharge_time: 1086
  energy_2 {
    charge_time: 143999
    discharge_time: 1191
  }
  energy_3 {
    charge_time: 143999
    discharge_time: 1187
  }
}
watt_info {
  ch_watt: 0
  ch_watt: -344.076935
  ch_watt: -294.923065
  all_hall_watt: 677
}
master_ver_info {
  app_main_ver: 4
  app_dbg_ver: 2
  app_test_ver: 18
}

<BT_ADDRESS>: ParseEncPackets: '5a 5a 10 01 62 01 60 44 a9 8d cc a7 e0 0c 78 4a f7 de 16 62 c7 9e 06 61 92 8d ee 04 96 df 4b f1 30 c0 e0 6c 1a 36 66 59 3a 1a 62 5c 27 a9 6d e6 5c 55 1c a1 c7 1e f4 7b 5b ba 8e 1e 1a 5d 85 19 7f 7b db 31 21 10 bc c9 33 f5 c9 c8 50 83 17 57 90 5f a7 4b cb d4 e1 b0 ee 97 52 24 00 2d 86 10 c3 5d 3b 07 25 ad 78 eb 29 68 b7 a6 56 db aa 0d 62 85 4f 48 dc 2d d4 e0 ff 7f 5e 54 b4 70 d3 81 cd 7e ef 02 be 26 28 93 4a ec fa 4a 37 51 2a 63 21 b4 7c 07 ae fa fc 19 e5 96 4c 1f 2c 53 1a a6 4d e7 af ec d5 66 7a b5 43 68 32 02 a4 db 64 66 c4 ae 67 13 10 e7 3d 9c 20 62 c4 a4 7f f0 6d 29 2f 77 a5 24 a5 ca 65 1f d6 5b ed e1 f5 9b d6 c4 07 10 c2 2a 7c c0 d7 10 45 d0 92 a7 a0 7a 66 ef 6b 94 e6 0b c7 50 0b 66 63 74 7a e3 b4 9d ef 59 17 41 5c f6 7e bb dc 4c 18 1c 8a a0 75 64 27 ab 4e f2 fd c5 9e 87 b9 77 f2 0f d1 8e cd d8 e3 65 54 bd 3e ce a1 50 0b 9e 6e 19 d8 7e 18 6d d6 7b 8c c4 70 c0 44 1c 46 a2 b0 09 93 1a 43 62 b2 5c 0e 59 4d 7f d6 90 e6 65 51 4f 3b 75 e4 83 87 cc 78 eb 9a 7c 58 15 52 e3 ff a0 91 21 2c 57 db 8d 89 f2 97 03 27 ac 9c fb cf ba 74 83 3f fb 59 a9 86 a8 39 69 29 12 cb 59'
<BT_ADDRESS>: ParseEncPackets: decrypted payload: 'aa 13 48 01 88 01 02 00 00 00 04 30 0b 21 01 00 0c 20 82 05 c4 02 0a c8 01 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 e2 03 0e 08 00 10 00 18 00 20 07 28 07 30 00 38 00 ea 03 10 08 01 10 01 18 00 20 9f 01 28 9f 01 30 00 38 1d f2 03 10 08 01 10 01 18 00 20 c5 01 28 c5 01 30 00 38 1d 10 f5 85 01 18 2e 25 85 eb 85 46 2d 00 00 3a 42 82 05 2f 0a 02 10 51 10 00 18 00 20 00 28 00 30 00 38 00 40 00 4d 00 00 00 00 50 00 58 00 60 00 68 00 70 00 78 00 80 01 00 88 01 00 90 01 00 98 01 00 bb bb'
backup_incre_info {
  errcode {
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
    err_code: "\000\000\000\000\000\000\000\000"
  }
  backup_full_cap: 17141
  backup_bat_per: 46
  backup_discharge_rmain_bat_cap: 17141.7598
  cur_discharge_soc: 46.5
  ch1_info {
    backup_is_ready: false
    ctrl_sta: BACKUP_CH_OFF
    force_charge_sta: FORCE_CHARGE_OFF
    backup_rly1_cnt: 7
    backup_rly2_cnt: 7
    wake_up_charge_sta: 0
    energy_5p8_type: 0
  }
  ch2_info {
    backup_is_ready: true
    ctrl_sta: BACKUP_CH_DISCHARGE
    force_charge_sta: FORCE_CHARGE_OFF
    backup_rly1_cnt: 159
    backup_rly2_cnt: 159
    wake_up_charge_sta: 0
    energy_5p8_type: 29
  }
  ch3_info {
    backup_is_ready: true
    ctrl_sta: BACKUP_CH_DISCHARGE
    force_charge_sta: FORCE_CHARGE_OFF
    backup_rly1_cnt: 197
    backup_rly2_cnt: 197
    wake_up_charge_sta: 0
    energy_5p8_type: 29
  }
  Energy1_info {
    dev_info {
      type: 81
    }
    is_enable: 0
    is_connect: 0
    is_ac_open: 0
    is_power_output: 0
    is_grid_charge: 0
    is_mppt_charge: 0
    battery_percentage: 0
    output_power: 0
    oil_pack_num: 0
    mult_pack_num: 0
    ems_chg_flag: 0
    hw_connect: 0
    ems_bat_temp: 0
    lcd_input_watts: 0
    pv_charge_watts: 0
    pv_low_charge_watts: 0
    pv_height_charge_watts: 0
    error_code_num: 0
  }
}
...
```

### Delta Pro Ultra

```
...
...
```

## Reverse

In order to understand the protocol I used multiple tools and openly available data:
* ecoflow android app - received through
  * [JADX](https://github.com/skylot/jadx) - reverse engineering tool for APKs java bytecode
  * [Ghidra](https://ghidra-sre.org/) - to understand the internals of native libs
  * [protod](https://github.com/valaphee/protod) - to decode protobuf descriptor
  * [apktool](https://apktool.org/) - to recompile the APK with modified data
* btsnoop log from rooted android
  * [Wireshark](https://www.wireshark.org/)
* Common sense

Thanks all the authors for their hard work to make my work easier and possible!

## Legal

This repository is not for sale.

The work was done in order to localize devices and make them available / controllable in disaster
situations (unavailability of internet or cut-off the ecoflow servers). The official application
allows to connect via bluetooth, but to do that you have to login to the server. No server is here
and you screwed.

The requests to ecoflow usually ends up in support department and generally ignored, so there is no
way to get support from them. That gave me right to take it in my own hands and use my knowledge &
time to make my own way. There is no intention to harm any people anyhow - just to make sure you
will be safe in emergency situation, which is critical for such a product.
