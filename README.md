<div align="center">

  <a href="https://github.com/offici5l/MiUnlockTool/releases/latest">
    <img src="https://img.shields.io/badge/MiUnlockTool-%23FF6900?style=flat&logo=xiaomi&logoColor=white" alt="MiUnlockTool" style="width: 200px; vertical-align: middle;" />
  </a>

  <br><br>

  <img src="https://img.shields.io/github/v/release/offici5l/MiUnlockTool?style=flat&label=Version&labelColor=black&color=brightgreen" alt="Version" />
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="Apache 2.0 License" /></a>
  <a href="https://t.me/Offici5l_Channel"><img src="https://img.shields.io/badge/Telegram-%230077B5?style=flat&logo=telegram&logoColor=white" alt="Telegram Channel" /></a>

  <br><br>

  <p style="font-weight: bold;">
    Developed to retrieve <code>encryptData(token)</code>
    <br>
    for Xiaomi devices to unlock the bootloader.
    <br>
    Compatible with all platforms.
  </p>

  <br>

  <a href="https://rafliiar17.github.io/MiUnlockTool-Arch/docs/error_codes.html">
    <img src="https://img.shields.io/badge/📚_Error_Codes-Documentation-red?style=for-the-badge" alt="Error Codes Documentation" />
  </a>

</div>

---

## 📖 Overview

**MiUnlockTool** is a Python-based utility designed to unlock Xiaomi devices using browser session authentication. This tool simplifies the bootloader unlocking process by automating token retrieval and device communication.

## ✨ Features

- 🔓 Automated bootloader unlocking process
- 🌐 Browser-based authentication
- 🖥️ Cross-platform compatibility (Windows, Linux, macOS)
- ⚡ Automatic platform-tools (fastboot) download
- 📱 Support for all Xiaomi devices

## 📋 Requirements

- Python 3.6 or higher
- Platform-tools (fastboot) - automatically downloaded if not found
- Active Xiaomi account
- Device in bootloader/fastboot mode

## 🚀 Installation

### Standard Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/rafliiar17/MiUnlockTool-Arch
   cd MiUnlockTool
   ```

2. **Set up virtual environment and install dependencies:**
   ```bash
   python -m venv venv && source venv/bin/activate
   python -m pip install -r requirements.txt
   ```

3. **Make the script executable and run:**
   ```bash
   chmod +x MiUnlockTool.py
   python MiUnlockTool.py
   ```

## 📱 Usage

1. Boot your Xiaomi device into fastboot/bootloader mode
2. Connect your device to the computer via USB
3. Run the MiUnlockTool script
4. Follow the on-screen instructions
5. Authenticate using your browser when prompted
6. Wait for the unlocking process to complete

## ⚠️ Important Notes

- ⚡ **Unlocking the bootloader will erase all data on your device**
- 🔒 Ensure you have backed up important data before proceeding
- ⏰ Some devices may have a waiting period before unlocking is allowed
- 🛡️ Unlocking may void your device warranty

## 🆘 Troubleshooting

Encountering errors? Check our comprehensive error codes documentation:

<div align="center">
  <a href="https://rafliiar17.github.io/MiUnlockTool-Arch/docs/error_codes.html">
    <img src="https://img.shields.io/badge/🔍_View-Error_Codes_Documentation-critical?style=for-the-badge&logo=readthedocs&logoColor=white" alt="Error Codes" />
  </a>
</div>

## 🤝 Contributing

Contributions are welcome! Feel free to:

- 🐛 Report bugs
- 💡 Suggest new features
- 🔧 Submit pull requests
- 📖 Improve documentation

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](./LICENSE) file for details.

## 📞 Contact & Support

<div align="center">

  [![Telegram Channel](https://img.shields.io/badge/Join-Telegram_Channel-0088cc?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/Miunlock_Arch)
  [![GitHub Issues](https://img.shields.io/badge/Report-Issues-red?style=for-the-badge&logo=github&logoColor=white)](https://github.com/rafliiar17/MiUnlockTool-Arch/issues)

</div>

---

<div align="center">
  <p>Made with ❤️ for the Xiaomi community</p>
  <p><sub>⚠️ Use at your own risk. The developers are not responsible for any damage to your device.</sub></p>
</div>