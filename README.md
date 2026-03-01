# PIA WireGuard Config Generator

Easily generate and register pure **WireGuard** configuration files (`.conf`) for **Private Internet Access (PIA)**. 

Ever wanted to use PIA on your Unifi router, Raspberry Pi, or custom pfSense setup, but realized PIA doesn't just hand out WireGuard configuration files? This tool logs into your PIA account, generates secure native WireGuard keys locally, registers them with PIA's API, and spits out a ready-to-use `.conf` file. 

<p align="center">
  <img src="resources/icons/appIcon.png" width="128" />
</p>

## Why does this exist?
PIA officially supports OpenVPN configuration file downloads, but requires you to use their proprietary app if you want to use the much faster WireGuard protocol. This tool bridges that gap by mimicking their app's API handshake, allowing you to generate standalone WireGuard configs for any device.

## Features
- **Standalone Configs**: Creates standard `.conf` files you can import into *any* WireGuard client (routers, custom servers, etc).
- **No External Dependencies**: Generates the cryptographic Curve25519 keys entirely locally. You don't even need `wg.exe` or WireGuard installed on your machine to generate a config!
- **Global Server Support**: Automatically fetches the latest PIA v6 server regions across the world for you to choose from.
- **Advanced DNS Selection**: Lets you easily pick between PIA's internal Standard DNS, Streaming Optimized DNS, MACE (Ad-blocking), or any Custom IP.

## Usage

### Getting the App
1. Go to the [Releases](../../releases) page (if available) to download the ready-to-use executable for Windows, macOS, or Linux.
2. Launch the application.

### Running it
1. Enter your PIA `Username` (starts with 'p') and `Password`.
2. Select your desired server region from the dropdown.
3. Select your preferred DNS (Note: PIA's Streaming DNS is great for bypassing geo-blocks).
4. Click **Generate** and save the resulting `.conf` file.
5. Import that file into your router or WireGuard client, and you're good to go!

---

## How to Build from Source
If you want to compile the executable yourself:
```bash
# Clone the repository
git clone https://github.com/vonRoX/PIA-WireGuard-Generator.git
cd PIA-WireGuard-Generator

# Install Neutralinojs dependencies
npm install

# Build cross-platform binaries (Outputs to /dist)
npm run build
```

---

## Disclaimers & Safety
- **No data collection**: This app runs entirely locally. Your PIA credentials are sent *only* and *directly* to Private Internet Access (`privateinternetaccess.com`) to get an authentication token.
- **Local Storage**: It saves your token and region preferences locally on your machine for convenience (so you don't have to keep logging in).
- **Not Affiliated**: This is a community-made tool. We are not affiliated, associated, authorized, endorsed by, or in any way officially connected with Private Internet Access.

***

<div align="center">
  <i>Warning: This project was 100% <strong>Vibecoded™</strong> with AI. If it generates a config that accidentally routes your traffic through a smart toaster in Finland, I am not legally responsible.</i> 🍞🤖
</div>
