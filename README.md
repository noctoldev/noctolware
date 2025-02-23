## **CipherStrike Ransomware - Feature Overview**

This Rust-based ransomware encrypts files in a target directory using AES-256-CBC, appends `.cipherstriked` to encrypted filenames, and incorporates anti-debugging, obfuscation, and self-destruction mechanisms. Below is a summary of its core features.

### **Core Encryption**
- **AES-256-CBC Encryption**: Encrypts file contents using the AES-256 algorithm in Cipher Block Chaining (CBC) mode with a 32-byte key and 16-byte IV.
- **Directory Traversal**: Recursively scans and encrypts files in the specified directory (default: `./`) using the `walkdir` crate.
- **Protected Directory Exclusion**: Avoids encrypting files in critical system directories (e.g., `C:\Windows`, `C:\Program Files`) to maintain system stability.

### **Anti-Analysis Techniques**
- **Debugger Detection**: Checks for debuggers on Windows by inspecting the PEB `BeingDebugged` flag via inline assembly; exits if detected.
- **Timing Analysis Detection**: Measures execution time with the `rdtsc` instruction to detect virtualized or slowed environments; exits if timing exceeds threshold.
- **Environment Checks**: Monitors for suspicious conditions (e.g., `DEBUG` environment variable) and triggers a division-by-zero crash if detected.

### **Obfuscation Mechanisms**
- **Dynamic Key/IV Generation**: Generates random keys and IVs, encrypted with a time-based seed for added complexity.
- **Control Flow Obfuscation**: Introduces recursive calls or undefined instructions (`ud2`) to confuse static analysis.
- **Stack Obfuscation**: Fills the stack with encrypted junk data and overwrites it with breakpoints (`0xCC`).
- **Junk Code Injection**: Produces random encrypted bytecode with x86 NOPs (`0x90`) to obscure program logic.
- **XOR Obfuscation**: Applies XOR operations with random bytes to encrypted data.
- **Dynamic Address Resolution**: Encrypts dummy data with time-based keys to hide memory addresses.

### **File Handling**
- **File Encryption**: Encrypts files in two stages—initial tamper encryption followed by main encryption—and replaces originals with `.cipherstriked` versions.
- **Random Delays**: Inserts variable sleep durations between file operations to evade behavioral detection.

### **Self-Destruction**
- **Executable Overwrite**: Overwrites the running binary with random junk data and attempts to delete it.
- **Crash Triggers**: Uses assembly breakpoints (`int 3`) to crash if debugged during self-destruction.

### **Process Spoofing**
- **Process Name Spoofing**: On Windows with MSVC, attempts to disguise the process as `svchost.exe` (note: implementation is incomplete and unsafe).

### **Additional Features**
- **Key/IV Cleanup**: Repeatedly encrypts and zeroes out the key and IV after use to prevent recovery from memory.
- **Mutation Seed**: Uses a time-based seed for key generation, encryption, and obfuscation to ensure variability across executions.

### **Dependencies**
- **`openssl`**: Provides cryptographic primitives for AES encryption.
- **`rand`**: Generates random numbers for keys, IVs, and obfuscation.
- **`walkdir`**: Enables recursive directory traversal.
- **`std`**: Leverages standard library features for file I/O, threading, system time, and inline assembly.

### **Platform Considerations**
- Primarily targets Windows (e.g., debugger checks, protected directories), with limited functionality on non-Windows systems.

---

### **Purpose**
This code serves as an educational example of ransomware mechanics, highlighting encryption, anti-debugging, and obfuscation techniques. It is **not intended for malicious use** and should only be studied in controlled, ethical environments. This was made with the assumption no illegal use would be so, and that all responsibiity to abide by laws is for the user

---

i'd like to thank zillakami for the music, caffiene and various other factors that helped me make this lmfao
this as of feb 23rd is fully undetectable on virustotal.

thank AI for the markdown
