# Deadlock Anti-Cheat

![License](https://img.shields.io/github/license/deadlockhook/deadlock-anti-cheat?style=flat-square)
![Build Status](https://img.shields.io/github/actions/workflow/status/deadlockhook/deadlock-anti-cheat/build.yml?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Windows-blue?style=flat-square)

**Deadlock Anti-Cheat** is a powerful anti-cheat system designed for seamless integration into game client and server environments. It protects against various cheats while ensuring smooth gameplay and secure networking.

## Features

- 🔒 **Dynamic Cheat Detection**: Monitors game processes to detect and prevent cheats in real-time.
- ⚡ **Client-Server Synchronization**: Exchanges secure messages between the client and server to validate game logic and ensure integrity.
- 🛡️ **Engine Compatibility**: Supports integration with multiple game engines.
- 🎮 **Lightweight Design**: Minimal impact on game performance.
- 🔍 **API Integration**: Provides a robust API for developers to manage anti-cheat functions.

## Installation

### Prerequisites

- [Visual Studio 2022](https://visualstudio.microsoft.com/) (or newer) with C++ tools.
- Windows 10/11 SDK.
- Admin privileges for debugging and deployment.

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/deadlockhook/deadlock-anti-cheat.git
   cd deadlock-anti-cheat
   ```
2. Open `deadlock.sln` in Visual Studio.
3. Build the solution in Release mode.
4. Integrate the generated `.dll` file into your game’s executable directory.
5. Include the provided `.lib` file in your game server project.
6. Use the client API to manage anti-cheat operations in your game.

## Usage

### Game Client

1. Load the `.dll` file in the game executable during initialization.
2. Use the provided API from the client API files to handle anti-cheat functionality.
3. Ensure the game’s networking manager is set up for communication with the game server.

### Game Server

1. Link the `.lib` file to your game server project.
2. The `.lib` file will handle the mini game server logic.
3. Configure secure communication between the game server and the client through the game’s networking manager.

## System Architecture

- **Client Module**:
  - A `.dll` file loaded into the game executable to monitor and handle cheats.
  - Provides an API for developers to integrate anti-cheat logic.
- **Server Module**:
  - A `.lib` file included in the game server.
  - Manages mini game server logic and secure communication with the client.

## Contribution

We welcome contributions! Please follow the standard GitHub process:

1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add a descriptive commit message"
   ```
4. Push your branch:
   ```bash
   git push origin feature-name
   ```
5. Open a pull request.

## License

This project is licensed under the [MIT License](LICENSE).

## Support

For questions or support, [open an issue](https://github.com/deadlockhook/deadlock-anti-cheat/issues) or contact the project maintainer.
