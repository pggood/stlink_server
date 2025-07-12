# STLink Server

## Overview

This project is an open-source reimplementation of the ST-Link server for interfacing with STMicroelectronics ST-Link debug probes. The original closed-source ST-Link server provided by STMicroelectronics has proven unreliable on Windows, particularly on the latest Windows 11 24H2 release. Users frequently encounter issues where the ST-Link probe is not detected, often requiring a reinstallation of the software after every Windows update. This project addresses these challenges by leveraging native Windows APIs (WinUSB, SetupAPI, and Winsock) instead of cross-platform shims, resulting in a more robust and reliable solution.

## Motivation

The closed-source ST-Link server provided by STMicroelectronics suffers from the following issues on Windows 11 24H2:
- **Unreliable Device Detection**: The server often fails to detect ST-Link probes, especially after Windows updates.
- **Frequent Reinstallation Required**: Users must reinstall the server software after nearly every Windows update, disrupting workflows.
- **Cross-Platform Shim Overhead**: The original implementation uses cross-platform abstractions that introduce compatibility issues and inefficiencies on Windows.

This open-source reimplementation resolves these problems by:
- Using **native Windows APIs** (WinUSB for USB communication, SetupAPI for device enumeration, and Winsock for potential network functionality) to ensure compatibility and reliability.
- Implementing robust hotplug detection to handle device arrival and removal seamlessly.
- Providing a command-line interface for testing and debugging ST-Link probes, with commands to blink LEDs, erase flash, read firmware versions, and enter SWD mode.
- Offering an open-source codebase that can be maintained and extended by the community.

## Features

- **Reliable Device Detection**: Consistently detects ST-Link probes using native Windows APIs.
- **Hotplug Support**: Handles device arrival and removal events without requiring software reinstallation.
- **Command-Line Interface**: Supports commands for common ST-Link operations, such as:
  - Blinking the ST-Link LED
  - Erasing target flash memory
  - Retrieving firmware version
  - Entering SWD mode
- **Windows 11 24H2 Compatibility**: Tested and verified to work seamlessly on the latest Windows 11 release.
- **Open-Source**: Licensed under [MIT License](#license) for community contributions and transparency.

## Installation

### Prerequisites
- **Operating System**: Windows 11 (tested on 24H2) or Windows 10.
- **Development Environment**: Visual Studio 2022 with C++ Desktop Development workload.
- **Libraries**: The project uses standard Windows libraries (`ws2_32.lib`, `setupapi.lib`, `winusb.lib`), which are included with Visual Studio.
- **Hardware**: An STMicroelectronics ST-Link debug probe (e.g., ST-Link/V2, ST-Link/V3).

### Build Instructions
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/stlink_server.git
   cd stlink_server
   ```
2. **Open the Solution**:
   - Open `stlink_server.sln` in Visual Studio 2022.
3. **Build the Project**:
   - Select the desired configuration (e.g., `Debug` or `Release`) and platform (`x64` or `x86`).
   - Build the solution (`Build > Build Solution`) to generate the executable.
4. **Run the Executable**:
   - The executable will be located in the `Debug` or `Release` folder (e.g., `x64/Debug/stlink_server.exe`).
   - Ensure your ST-Link probe is connected before running.
   - update the registry location to the updated version
     
 Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\STMicroelectronics\stlink_server\InstallDir]

@="C:\\ST\\stlink_server\\stlinkserver.exe"

## Usage

1. **Run the Server**:
   - Execute the compiled `stlink_server.exe` from the command prompt or PowerShell:
     ```bash
     .\x64\Debug\stlink_server.exe
     ```
   - The server will initialize and attempt to detect the ST-Link probe.

2. **Interact with the Command-Line Interface**:
   - Upon successful initialization, the server displays a menu:
     ```
     STLink Server Commands:
     1. Blink LED
     2. Erase Flash
     3. Get Firmware Version
     4. Enter SWD Mode
     5. Exit
     Enter choice (1-5):
     ```
   - Enter a number (1–5) to execute the corresponding command.
   - Example: Enter `1` to blink the ST-Link LED, or `3` to retrieve the firmware version.

3. **Hotplug Support**:
   - The server automatically detects ST-Link probe connections and disconnections, logging events to the console.
   - No reinstallation is required after Windows updates or device reconnections.  
   - you can manually run it in debug mode to check if its detecting the STLINK
     
    stlinkserver.exe --debug 5

## Project Structure

- **`stlink_server.h`**: Header file defining the `STLinkServer` class, constants, and debug interface structure.
- **`stlink_server.cpp`**: Implementation of the `STLinkServer` class, handling USB communication and ST-Link commands.
- **`main.cpp`**: Entry point with a command-line interface and Windows device notification handling.
- **`stlink_server.sln`**: Visual Studio solution file.
- **`stlink_server.vcxproj`**: Visual Studio project file (not included in this README but part of the repository).

## Contributing

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Make your changes and commit (`git commit -m "Add your feature"`).
4. Push to your branch (`git push origin feature/your-feature`).
5. Open a pull request with a description of your changes.

Please ensure your code follows the existing style and includes appropriate error handling. For major changes, open an issue first to discuss your ideas.

## License

This project is licensed under the MIT License.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Acknowledgments

- Thanks to STMicroelectronics for the original ST-Link server, which inspired this reimplementation.
- Built with native Windows APIs for maximum compatibility and performance.
