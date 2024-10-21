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
...
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
<BT_ADDRESS>: ParseEncPackets: decrypted payload: 'aa 13 5c 01 8b 01 13 00 00 00 04 30 0b 21 01 00 0c 20 92 05 8b 02 0a c8 01 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 10 01 18 7c 20 3c 28 3d 30 8c 01 38 8d 01 80 01 00 f5 01 20 ac f9 42 fd 01 df 66 fa 42 80 02 b3 01 8d 02 14 63 f8 42 95 02 3b 58 f7 42 98 02 b4 01 a5 02 dd 2f 79 40 ad 02 b6 7c 1f 40 b0 02 00 08 78 10 3c 18 01 8a 01 34 55 6e 69 74 65 64 20 53 74 61 74 65 73 20 43 6c 65 72 6d 6f 6e 74 2c 2c 2d 38 31 2e 37 38 30 30 36 35 39 39 39 39 39 39 39 39 2c 32 38 2e 34 39 37 33 32 39 c8 02 00 28 00 30 64 38 e8 07 40 00 48 00 50 64 bb bb'
grid_vol: 120
grid_freq: 60
product_tpye: GRID_CONNECTED_LOAD12
eps_mode_info: false
foce_charge_hight: 100
charge_watt_power: 1000
disc_lower: 0
power_sta: LOAD_CH_EG_POWER
master_cur: 100
area: "United States [REDACTED CITY NAME],,[REDACTED FLOAT LONGITUDE],[REDACTED FLOAT LATITUDE]"
ntc_over_temp_err: 0
master_incre_info {
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
  grid_sta: 1
  grid_vol: 124
  master_rly1_cnt: 60
  master_rly2_cnt: 61
  master_rly3_cnt: 140
  master_rly4_cnt: 141
  master_rly_err_flg: 0
  backup_vol_L1_safe_data: 124.788818
  backup_vol_L2_safe_data: 125.158936
  backup_phase_diff_safe_data: 179
  load_vol_L1_safe_data: 124.15567
  load_vol_L2_safe_data: 123.626518
  load_phase_diff_safe_data: 180
  master_vol_L1_safe_data: 3.88180113
  master_vol_L2_safe_data: 2.51024342
  master_phase_diff_safe_data: 0
}
...
<BT_ADDRESS>: ParseEncPackets: decrypted payload: 'aa 13 fa 00 ea 01 0a 00 00 00 04 30 0b 21 01 00 0c 20 92 05 1e f5 01 cd 2f fb 42 fd 01 4d a7 fb 42 8d 02 fb ad f9 42 95 02 e0 d7 f8 42 ad 02 c8 d0 21 40 58 00 60 00 80 01 00 90 01 00 98 01 00 a0 01 00 a8 01 00 b0 01 00 b8 01 00 c0 01 00 c8 01 00 d0 01 00 e8 03 02 f0 03 01 f8 03 32 98 04 64 b0 04 00 b8 04 b8 17 d0 05 00 d8 05 00 e0 05 09 e8 05 02 f0 05 02 f8 05 02 78 01 d8 01 00 f2 01 4c 08 01 20 32 2a 04 08 01 10 01 2a 04 08 01 10 02 2a 04 08 01 10 03 2a 04 08 01 10 04 2a 04 08 01 10 05 2a 04 08 01 10 06 2a 04 08 01 10 07 2a 04 08 01 10 08 2a 04 08 01 10 09 2a 04 08 01 10 0a 2a 04 08 01 10 0b 2a 04 08 01 10 0c 80 06 02 88 06 0c 90 06 00 98 06 00 a0 06 32 c0 06 b4 01 fa 01 00 82 02 00 8a 02 00 92 02 00 9a 02 00 a2 02 00 aa 02 00 b2 02 00 ba 02 00 c2 02 00 80 04 83 94 c1 b8 06 95 04 00 00 80 c0 bb bb'
is_set_oil_engine: false
oil_engine_watt: 0
has_config_done: true
is_area_err: false
ch1_force_charge: FORCE_CHARGE_OFF
ch2_force_charge: FORCE_CHARGE_OFF
ch3_force_charge: FORCE_CHARGE_OFF
storm_is_enable: false
storm_end_timestamp: 0
in_storm_mode: false
ch1_enable_set: 0
ch2_enable_set: 0
ch3_enable_set: 0
oil_engine_to_back_charge_persent: 0
LoadStrategyCfg {
  is_cfg: 1
  mid_priority_ch_discharge_low: 50
  hall1_ch_info {
    load_is_enable: true
    load_priority: 1
  }
  hall1_ch_info {
    load_is_enable: true
    load_priority: 2
  }
  hall1_ch_info {
    load_is_enable: true
    load_priority: 3
  }
  hall1_ch_info {
    load_is_enable: true
    load_priority: 4
  }
  hall1_ch_info {
    load_is_enable: true
    load_priority: 5
  }
  hall1_ch_info {
    load_is_enable: true
    load_priority: 6
  }
  hall1_ch_info {
    load_is_enable: true
    load_priority: 7
  }
  hall1_ch_info {
    load_is_enable: true
    load_priority: 8
  }
  hall1_ch_info {
    load_is_enable: true
    load_priority: 9
  }
  hall1_ch_info {
    load_is_enable: true
    load_priority: 10
  }
  hall1_ch_info {
    load_is_enable: true
    load_priority: 11
  }
  hall1_ch_info {
    load_is_enable: true
    load_priority: 12
  }
}
TimeTaskCfg_1 {
}
TimeTaskCfg_2 {
}
TimeTaskCfg_3 {
}
TimeTaskCfg_4 {
}
TimeTaskCfg_5 {
}
TimeTaskCfg_6 {
}
TimeTaskCfg_7 {
}
TimeTaskCfg_8 {
}
TimeTaskCfg_9 {
}
TimeTaskCfg_10 {
}
smart_backup_mode: 2
backup_reserve_enable: 1
backup_reserve_soc: 50
localTime: 1729120771
time_zone: -4
solar_backup_reserve_soc: 100
oil_type: 0
oil_max_output_watt: 3000
master_incre_info {
  backup_vol_L1_safe_data: 125.593361
  backup_vol_L2_safe_data: 125.826759
  load_vol_L1_safe_data: 124.839806
  load_vol_L2_safe_data: 124.421631
  master_vol_L2_safe_data: 2.528368
}
storm_request_flag: 0
storm_cur_time_stop_flag: 0
sys_cur_running_state: 9
rly1_real_sta: 2
rly2_real_sta: 2
rly3_real_sta: 2
rly4_real_sta: 2
cur_running_strategy: 12
reason_of_stop_dischar: 0
reason_os_stop_charge: 0
inlet_box_current: 50
phase_sub_value: 180
...
<BT_ADDRESS>: ParseEncPackets: decrypted payload: 'aa 13 67 01 e5 01 0f 00 00 00 04 30 0b 21 01 00 0c 20 92 05 18 f5 01 b5 34 fb 42 fd 01 fe b1 fb 42 8d 02 0f ac f9 42 95 02 5b d3 f8 42 8a 05 c8 02 0a c5 02 0a 88 01 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 08 00 00 00 00 00 00 00 00 0a 00 0a 00 0a 00 0a 00 0a 00 0a 00 0a 00 0a 00 18 00 20 00 12 00 f2 01 17 0a 04 08 00 10 00 10 3c 18 01 22 09 43 69 72 63 75 69 74 20 31 28 02 fa 01 17 0a 04 08 00 10 00 10 3c 18 01 22 09 43 69 72 63 75 69 74 20 32 28 04 82 02 17 0a 04 08 00 10 00 10 3c 18 01 22 09 43 69 72 63 75 69 74 20 33 28 00 8a 02 17 0a 04 08 00 10 00 10 3c 18 01 22 09 43 69 72 63 75 69 74 20 34 28 00 92 02 17 0a 04 08 00 10 00 10 3c 18 01 22 09 43 69 72 63 75 69 74 20 35 28 00 9a 02 17 0a 04 08 00 10 00 10 3c 18 01 22 09 43 69 72 63 75 69 74 20 36 28 00 a2 02 15 0a 04 08 00 10 00 10 3c 18 01 22 09 43 69 72 63 75 69 74 20 37 bb bb'
load_incre_info {
  hall1_incre_info {
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
      err_code: ""
      err_code: ""
      err_code: ""
      err_code: ""
      err_code: ""
      err_code: ""
      err_code: ""
      err_code: ""
    }
    model_info {
    }
    mid_prority_discharge_time: 0
    high_prority_discharge_time: 0
    ch1_info {
      splitphase {
        link_mark: false
        link_ch: 0
      }
      set_amp: 60
      icon_num: 1
      ch_name: "Circuit 1"
      load_rly_cnt: 2
    }
    ch2_info {
      splitphase {
        link_mark: false
        link_ch: 0
      }
      set_amp: 60
      icon_num: 1
      ch_name: "Circuit 2"
      load_rly_cnt: 4
    }
    ch3_info {
      splitphase {
        link_mark: false
        link_ch: 0
      }
      set_amp: 60
      icon_num: 1
      ch_name: "Circuit 3"
      load_rly_cnt: 0
    }
    ch4_info {
      splitphase {
        link_mark: false
        link_ch: 0
      }
      set_amp: 60
      icon_num: 1
      ch_name: "Circuit 4"
      load_rly_cnt: 0
    }
    ch5_info {
      splitphase {
        link_mark: false
        link_ch: 0
      }
      set_amp: 60
      icon_num: 1
      ch_name: "Circuit 5"
      load_rly_cnt: 0
    }
    ch6_info {
      splitphase {
        link_mark: false
        link_ch: 0
      }
      set_amp: 60
      icon_num: 1
      ch_name: "Circuit 6"
      load_rly_cnt: 0
    }
    ch7_info {
      splitphase {
        link_mark: false
        link_ch: 0
      }
      set_amp: 60
      icon_num: 1
      ch_name: "Circuit 7"
    }
  }
}
master_incre_info {
  backup_vol_L1_safe_data: 125.602943
  backup_vol_L2_safe_data: 125.847641
  load_vol_L1_safe_data: 124.836052
  load_vol_L2_safe_data: 124.412804
}
...
<BT_ADDRESS>: ParseEncPackets: decrypted payload: 'aa 13 51 01 62 01 10 00 00 00 04 30 0b 21 01 00 0c 20 92 05 22 f5 01 d6 37 fb 42 fd 01 34 ac fb 42 80 02 b4 01 8d 02 c8 a9 f9 42 95 02 17 d9 f8 42 a5 02 69 ae 77 40 8a 05 a8 02 0a a5 02 a2 02 02 28 00 aa 02 17 0a 04 08 00 10 00 10 3c 18 01 22 09 43 69 72 63 75 69 74 20 38 28 00 b2 02 17 0a 04 08 00 10 00 10 3c 18 01 22 09 43 69 72 63 75 69 74 20 39 28 00 ba 02 18 0a 04 08 00 10 00 10 3c 18 01 22 0a 43 69 72 63 75 69 74 20 31 30 28 00 c2 02 18 0a 04 08 00 10 00 10 3c 18 01 22 0a 43 69 72 63 75 69 74 20 31 31 28 00 ca 02 18 0a 04 08 00 10 00 10 3c 18 01 22 0a 43 69 72 63 75 69 74 20 31 32 28 00 d2 05 0c 08 01 10 01 18 00 20 00 28 00 40 00 da 05 0c 08 01 10 01 18 00 20 00 28 00 40 00 e2 05 0c 08 01 10 01 18 00 20 00 28 00 40 00 ea 05 0c 08 01 10 01 18 00 20 00 28 00 40 00 f2 05 0c 08 01 10 01 18 00 20 00 28 00 40 00 fa 05 0c 08 01 10 01 18 00 20 00 28 00 40 00 82 06 0c 08 01 10 01 18 00 20 00 28 00 40 00 8a 06 0c 08 01 10 01 18 00 20 00 28 00 40 00 92 06 0c 08 01 10 01 18 00 20 00 28 00 40 00 9a 06 0c 08 01 10 01 18 00 20 00 28 00 40 00 a2 06 02 08 01 bb bb'
load_incre_info {
  hall1_incre_info {
    ch7_info {
      load_rly_cnt: 0
    }
    ch8_info {
      splitphase {
        link_mark: false
        link_ch: 0
      }
      set_amp: 60
      icon_num: 1
      ch_name: "Circuit 8"
      load_rly_cnt: 0
    }
    ch9_info {
      splitphase {
        link_mark: false
        link_ch: 0
      }
      set_amp: 60
      icon_num: 1
      ch_name: "Circuit 9"
      load_rly_cnt: 0
    }
    ch10_info {
      splitphase {
        link_mark: false
        link_ch: 0
      }
      set_amp: 60
      icon_num: 1
      ch_name: "Circuit 10"
      load_rly_cnt: 0
    }
    ch11_info {
      splitphase {
        link_mark: false
        link_ch: 0
      }
      set_amp: 60
      icon_num: 1
      ch_name: "Circuit 11"
      load_rly_cnt: 0
    }
    ch12_info {
      splitphase {
        link_mark: false
        link_ch: 0
      }
      set_amp: 60
      icon_num: 1
      ch_name: "Circuit 12"
      load_rly_cnt: 0
    }
    ch1_sta {
      load_sta: LOAD_CH_POWER_ON
      ctrl_mode: RLY_HAND_CTRL_MODE
      notice_set_time: 0
      notice_enble: false
      notice_action: 0
      load_ch_switch_cause: 0
    }
    ch2_sta {
      load_sta: LOAD_CH_POWER_ON
      ctrl_mode: RLY_HAND_CTRL_MODE
      notice_set_time: 0
      notice_enble: false
      notice_action: 0
      load_ch_switch_cause: 0
    }
    ch3_sta {
      load_sta: LOAD_CH_POWER_ON
      ctrl_mode: RLY_HAND_CTRL_MODE
      notice_set_time: 0
      notice_enble: false
      notice_action: 0
      load_ch_switch_cause: 0
    }
    ch4_sta {
      load_sta: LOAD_CH_POWER_ON
      ctrl_mode: RLY_HAND_CTRL_MODE
      notice_set_time: 0
      notice_enble: false
      notice_action: 0
      load_ch_switch_cause: 0
    }
    ch5_sta {
      load_sta: LOAD_CH_POWER_ON
      ctrl_mode: RLY_HAND_CTRL_MODE
      notice_set_time: 0
      notice_enble: false
      notice_action: 0
      load_ch_switch_cause: 0
    }
    ch6_sta {
      load_sta: LOAD_CH_POWER_ON
      ctrl_mode: RLY_HAND_CTRL_MODE
      notice_set_time: 0
      notice_enble: false
      notice_action: 0
      load_ch_switch_cause: 0
    }
    ch7_sta {
      load_sta: LOAD_CH_POWER_ON
      ctrl_mode: RLY_HAND_CTRL_MODE
      notice_set_time: 0
      notice_enble: false
      notice_action: 0
      load_ch_switch_cause: 0
    }
    ch8_sta {
      load_sta: LOAD_CH_POWER_ON
      ctrl_mode: RLY_HAND_CTRL_MODE
      notice_set_time: 0
      notice_enble: false
      notice_action: 0
      load_ch_switch_cause: 0
    }
    ch9_sta {
      load_sta: LOAD_CH_POWER_ON
      ctrl_mode: RLY_HAND_CTRL_MODE
      notice_set_time: 0
      notice_enble: false
      notice_action: 0
      load_ch_switch_cause: 0
    }
    ch10_sta {
      load_sta: LOAD_CH_POWER_ON
      ctrl_mode: RLY_HAND_CTRL_MODE
      notice_set_time: 0
      notice_enble: false
      notice_action: 0
      load_ch_switch_cause: 0
    }
    ch11_sta {
      load_sta: LOAD_CH_POWER_ON
    }
  }
}
master_incre_info {
  backup_vol_L1_safe_data: 125.609055
  backup_vol_L2_safe_data: 125.836334
  backup_phase_diff_safe_data: 180
  load_vol_L1_safe_data: 124.831604
  load_vol_L2_safe_data: 124.424
  master_vol_L1_safe_data: 3.87002015
}
...
<BT_ADDRESS>: ParseEncPackets: decrypted payload: 'aa 13 4d 00 ce 01 14 00 00 00 04 30 0b 21 01 00 0c 20 92 05 22 f5 01 e8 2e fb 42 fd 01 6b aa fb 42 80 02 b4 01 8d 02 64 9e f9 42 95 02 a8 c6 f8 42 ad 02 b6 7c 1f 40 8a 05 25 0a 23 9a 06 02 40 00 a2 06 0c 08 01 10 01 18 00 20 00 28 00 40 00 aa 06 0c 08 01 10 01 18 00 20 00 28 00 40 00 bb bb'
load_incre_info {
  hall1_incre_info {
    ch10_sta {
      load_ch_switch_cause: 0
    }
    ch11_sta {
      load_sta: LOAD_CH_POWER_ON
      ctrl_mode: RLY_HAND_CTRL_MODE
      notice_set_time: 0
      notice_enble: false
      notice_action: 0
      load_ch_switch_cause: 0
    }
    ch12_sta {
      load_sta: LOAD_CH_POWER_ON
      ctrl_mode: RLY_HAND_CTRL_MODE
      notice_set_time: 0
      notice_enble: false
      notice_action: 0
      load_ch_switch_cause: 0
    }
  }
}
master_incre_info {
  backup_vol_L1_safe_data: 125.591614
  backup_vol_L2_safe_data: 125.832848
  backup_phase_diff_safe_data: 180
  load_vol_L1_safe_data: 124.809357
  load_vol_L2_safe_data: 124.388
  master_vol_L2_safe_data: 2.49198675
}
```

### Delta Pro Ultra

```
<BT_ADDRESS>: ParseEncPackets: decrypted payload: 'aa134500662c14a1c602011d0221010102041e011c150c363114141494391414d4512caf2b54704c331e011c160c393114141494391414d4512cfe4154704c311e011c170c3f3114141494391414d4512cbb4454704c37f209'
YJ751 BpInfoReport: bp_info {
  bp_no: 1
  bp_soc: 34
  bp_pwr: -0
  bp_energy: 6144
  remain_time: 8123
  bp_soc_max: 100
  bp_temp: 39
}
bp_info {
  bp_no: 2
  bp_soc: 45
  bp_pwr: -0
  bp_energy: 6144
  remain_time: 10986
  bp_soc_max: 100
  bp_temp: 37
}
bp_info {
  bp_no: 3
  bp_soc: 43
  bp_pwr: -0
  bp_energy: 6144
  remain_time: 10287
  bp_soc_max: 100
  bp_temp: 35
}

<BT_ADDRESS>: ParseEncPackets: decrypted payload: 'aa13c300ae2c92ff4317061d06210100fe109a9388b39a75420b2a948239690416948a6d95b082929212ad929292d9929292929292929288b39a4815132a9482061e0c56968a6d95b0829292929292929292929292929292929288b39a4815132a948279190c56968a7c95b0829292929292929292929292929292929288b39a7310132a9482792e6551968a6d95b082929212ad929292d9929292929292929288b39a7310132a9482152e6551968a7c95b082929212ad929212d09292929292929292b082cba5a3a0c8d3d0a6a6d5a7c6a2a2aba1531b'
YJ751 APPParaHeartbeatReport: sys_word_mode: 0
sys_backup_event: 0
sys_backup_soc: 100
energy_mamage_enable: 0
backup_ratio: 30
ac_xboost: 0
ac_out_freq: 60
bms_mode_set: 1
chg_max_soc: 100
dsg_min_soc: 0
ac_often_open_flg: 0
ac_often_open_min_soc: 0
chg_5p8_set_watts: 1800
chg_c20_set_watts: 1800
power_standby_mins: 0
screen_standby_sec: 300
dc_standby_mins: 720
ac_standby_mins: 720
solar_only_flg: 0
timezone_settype: 1
sys_timezone: -400
sys_timezone_id: "America/New_York"

<BT_ADDRESS>: ParseEncPackets: decrypted payload: 'aa1349009a2c2da1c602011d022101010203252d3d2d35490d2d05331d2d15116d2c65497d2d752d4d2d45a5235da523552dad2c812fa52cfd28bd2cfd28b52c2d8d2c2c852cb22b9f2c3d6c40485f444e4c0263485a7274425f46ba5b'
YJ751 AppShowHeartbeatReport: proto_ver: 50464776
show_flag: 2560
access_type: 8
wireless_4g_on: 0
wireless_4G_sta: 0
access_5p8_in_type: 0
access_5p8_out_type: 0
wireless_4g_con: -1
wirlesss_4g_err_code: 5
sim_iccid: ""
soc: 41
bp_num: 3
pcs_type: 1
c20_chg_max_watts: 1800
para_chg_max_watts: 7200
remain_time: 14939
sys_err_code: 0
full_combo: 100
remain_combo: 30
watts_in_sum: 0
watts_out_sum: 0
out_usb1_pwr: 0
out_usb2_pwr: 0
out_typec1_pwr: 0
out_typec2_pwr: 0
out_ads_pwr: 0
out_ac_l1_1_pwr: 0
out_ac_l1_2_pwr: 0
out_ac_l2_1_pwr: 0
out_ac_l2_2_pwr: 0
out_ac_tt_pwr: 0
out_ac_l14_pwr: 0
out_ac_5p8_pwr: 0
in_ac_5p8_pwr: 0
in_ac_c20_pwr: 0
in_lv_mppt_pwr: 0
in_hv_mppt_pwr: 0
out_pr_pwr: 0
time_task_change_cnt: 0
time_task_conflict_flag: 0
chg_time_task_notice: 0
chg_time_task_type: 4294967295
chg_time_task_index: 4294967295
chg_time_task_mode: 4294967295
chg_time_task_param: 0
chg_time_task_table_0: 0
chg_time_task_table_1: 0
chg_time_task_table_2: 0
dsg_time_task_notice: 0
dsg_time_task_type: 4294967295
dsg_time_task_index: 4294967295
dsg_time_task_mode: 4294967295
dsg_time_task_param: 0
dsg_time_task_table_0: 0
dsg_time_task_table_1: 0
dsg_time_task_table_2: 0
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
