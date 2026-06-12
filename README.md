<b>AzaharPlus</b> is a fork of the Azahar 3DS emulator with extra features.

Each version is the same as the corresponding version of Azahar exept for this:
- Compatibility with all game files. If a file works with any Citra fork, it works with AzaharPlus.
- Ability to download system files from official servers. No need for an actual 3DS.
- Compatibility with older CPUs (no SSE4.2 required)
- Compatibility with Android 9
- ZipPass: A new way to exchange StreetPass data through zip files

The Azahar logo is the property of PabloMK7 and angyartanddraw
---

![Azahar Emulator](https://azahar-emu.org/resources/images/logo/azahar-name-and-logo.svg)
![Plus](https://cdn-icons-png.flaticon.com/128/226/226974.png)

![GitHub Release](https://img.shields.io/github/v/release/AzaharPlus/AzaharPlus?label=Current%20Release)
![GitHub Downloads](https://img.shields.io/github/downloads/AzaharPlus/AzaharPlus/total?logo=github&label=GitHub%20Downloads)

# Installation

### Windows / Linux

Download the latest release from [Releases](https://github.com/AzaharPlus/AzaharPlus/releases).

---

### Android

You can install the app using Obtainium:
1. Download and install Obtainium from [here](https://github.com/ImranR98/Obtainium/releases) (use the file named `app-release.apk`)
2. Open Obtainium and click 'Add App'
3. Type `https://github.com/AzaharPlus/AzaharPlus` into the 'App Source URL' section
4. Click 'Add'
5. Click 'Install'

If you wish, you can also simply install the latest APK from the [Releases](https://github.com/AzaharPlus/AzaharPlus/releases) page.

# ZipPass

ZipPass allows you to share StreetPass data in the form of zip files.<br>
On desktop it is in File > ZipPass. On android it is in the main menu.

- It can only be used when no game is running.
- It requires system files and LLE modules enabled.
- You need to enable StreetPass in your games.
- The export feature will save the StreetPass data of all your games in a xxx.pass.zip file.
- The import feature lets you pick one or several xxx.pass.zip files and will simulate StreetPass tags.
- You can pick as many files as you want for the import but every game has a limit for its queue and anything - beyond that will be ignored.
- This is all pretty experimental so in case of issues, I added a menu to disable StreetPass on every game. You won't lose anything, you will simply need to enable StreetPass again.
- I opened a topic on the github for people to share their data: [ZipPass Exchange](https://github.com/AzaharPlus/AzaharPlus/discussions/117)

# Build instructions

Please refer this repository's [wiki](https://github.com/AzaharPlus/AzaharPlus/wiki/Building-From-Source) for build instructions

# Minimum requirements
Below are the minimum requirements to run AzaharPlus:

### Desktop
```
Operating System: Windows 10 (64-bit), or modern 64-bit Linux
CPU: x86-64/ARM64 CPU (Windows for ARM not supported). Single core performance higher than 1,800 on Passmark
GPU: OpenGL 4.3 or Vulkan 1.1 support
Memory: 2GB of RAM. 4GB is recommended
```
### Android
```
Operating System: Android 9.0+ (64-bit)
CPU: Snapdragon 835 SoC or better
GPU: OpenGL ES 3.2 or Vulkan 1.1 support
Memory: 2GB of RAM. 4GB is recommended
```
