# AutoIt3 Deobfuscator 🔍

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Advanced deobfuscation tool for AutoIt3 scripts, featuring:
- XOR string decryption
- Control flow flattening removal
- Math obfuscation simplification
- Variable name normalization
- Malicious function detection

## 📥 Installation

```bash
git clone https://github.com/bl4d3rvnner7/autoit3-unpacker/
cd autoit3-unpacker
```

## 🚀 Usage

```bash
python autoit.py -f obfuscated.au3 [-v]
```

**Arguments:**
- `-f/--file`: Path to obfuscated AutoIt script (required)
- `-v/--verbose`: Enable detailed output (optional)

## ✨ Features

### Deobfuscation Capabilities
| Technique               | Status |
|-------------------------|--------|
| String Decryption       | ✅      |
| Math Simplification     | ✅      |
| Dead Code Removal       | ✅      |
| Variable Normalization  | ✅      |
| API Call Analysis       | ✅      |

### Output Examples
**Before:**
```autoit
Local $x = 0x2A
Global $y = "encrypted"
$y &= "data"
Func X($1) Return $1+Tan(0x1F4) EndFunc
```

**After:**
```autoit
Global $y = "decrypted_data"
Func X($arg1) Return $arg1+500 EndFunc
```

Note: Sometimes it may not work, try other files then.

## 📊 Detection Categories

The tool classifies AutoIt functions into:

| Category     | Examples                      |
|-------------|-------------------------------|
| **Good**    | MsgBox, ConsoleWrite          |
| **Suspicious** | Run, DllCall               |
| **Malicious** | FileDelete, RegWrite      |

## 🤝 Contributing

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License
MIT License - See [LICENSE](LICENSE) for details



