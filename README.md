# ef-ble-reverse

Independent DIY repository contains a set of experiments and scripts to connect to your ecoflow
devices through bluetooth and monitor their status / control parameters.

Devices:
* Smart Home Panel 2 (EF-HD3####)
* Delta Pro Ultra (EF-YJ####)

The whole process of RE took ~1 month evenings, I've solved a numerous challenges on the way, but
quite sure missed something - so will be glad if you can add to the information we have or help in
some other way.

## Goal

To develop a local solution to control ecoflow devices via homeassistant automation. The plugin
will be stored in another repo - here is just tools & experiments to share with community.

## WARNING: Support & Warranty

Sorry, no support no warranty - you on your own and I take no responsibility for any of your
actions. We all grown-ups here and know that we deal with quite dangerous voltages and storage
devices that could kill or cause death. So make sure you know what you doing for each and every
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
