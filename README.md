# pemcracker
A fast, multi-threaded password cracker for encrypted PEM private key files - use it for Active Directory Certificate keys 

## Description

`pemcracker` attempts to find the password for an encrypted PEM private key file (typically containing RSA, EC, or other keys in PKCS#1 or PKCS#8 format) by trying passwords from a provided wordlist. It utilizes multiple CPU cores via C++ threads to significantly speed up the cracking process compared to single-threaded tools.

## Features

* **Multi-threaded:** Uses C++ `std::thread` to leverage multiple CPU cores for faster cracking. Defaults to the number of hardware threads available.
* **Handles Common Formats:** Supports both legacy (DEK-Info header) and modern (PKCS#8) PEM encryption formats automatically via OpenSSL's `PEM_read_bio_PrivateKey`.
* **Simple Command-Line Interface:** Easy to use with clear arguments for the PEM file and wordlist.

## Prerequisites

* **C++ Compiler:** A modern C++ compiler that supports C++11 features (e.g., g++, clang++).
* **OpenSSL Development Libraries:** You need the OpenSSL headers and libraries installed.
    * On Debian/Ubuntu: `sudo apt-get update && sudo apt-get install libssl-dev`
    * On Fedora/CentOS/RHEL: `sudo yum install openssl-devel` or `sudo dnf install openssl-devel`
    * On macOS (using Homebrew): `brew install openssl` (might require setting linker/compiler flags, see Homebrew output)

## Compilation

Open your terminal and use the following command:

```bash
g++ pem_cracker.cpp -o pemcracker -std=c++11 -pthread -lssl -lcrypto
```

- `pem_cracker.cpp`: The name of the source code file.
    
- `-o pemcracker`: The desired name for the output executable.
    
- `-std=c++11`: Enable C++11 standard features.
    
- `-pthread`: Link the POSIX threads library (needed for `std::thread`).
    
- `-lssl -lcrypto`: Link the required OpenSSL libraries.
    

## Usage

```
./pemcracker -pem <path_to_pem_file> -wordlist <path_to_wordlist> [-workers <num_threads>]
```

**Arguments:**

- `-pem <path_to_pem_file>`: (Required) Path to the encrypted PEM private key file.
    
- `-wordlist <path_to_wordlist>`: (Required) Path to the wordlist file (one password per line).
    
- `-workers <num_threads>`: (Optional) Number of concurrent worker threads to use. Defaults to the number of CPU cores detected by `std::thread::hardware_concurrency()`.
    

## Example

```
./pemcracker -pem /keys/encrypted_server.key -wordlist /usr/share/wordlists/rockyou.txt -workers 8
```

This command will attempt to crack the password for `/keys/encrypted_server.key` using passwords from `/usr/share/wordlists/rockyou.txt` with 8 worker threads.

## Disclaimer

This tool is intended for legitimate security testing and password recovery purposes only. Attempting to crack passwords
