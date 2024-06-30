
# Python Botnet C2 Server-Client

## Overview
This repository contains a Python-based botnet Command and Control (C2) server and client. The project demonstrates how a C2 server can control multiple infected clients using encrypted communications.

## Features
- Encrypted communication between server and client using AES encryption.
- Command execution on the client machine from the server.
- File transfer between server and client.

## Directory Structure


## Directory Hierarchy
```
|—— .gitignore
|—— RAT - HERE !
|    |—— Client
|        |—— aes_crypt.py
|        |—— client.py
|        |—— requirements.txt
|        |—— Secret-Client-File.txt
|    |—— Server
|        |—— aes_crypt.py
|        |—— Infected-File.txt
|        |—— requirements.txt
|        |—— server.py
|—— Research
|    |—— Elie
|        |—— aes_crypt.py
|        |—— Client
|            |—— aes_crypt.py
|            |—— clientfinal.py
|            |—— requirements.txt
|            |—— Secret-Client-File.txt
|        |—— Infected-File.txt
|        |—— requirements.txt
|        |—— server.py
|        |—— serverscreen.py
|        |—— serveurfinal.py
|        |—— Template
|            |—— modules
|                |—— autorun.py
|                |—— my_crypt_func.py
|                |—— my_logger.py
|            |—— requirements.txt
|            |—— Shell_Cleaner.py
|            |—— TinkererShell.py
|            |—— TinkererShellMaster.py
|    |—— Younes
|        |—— cert.pem
|        |—— clientyounes.py
|        |—— hashdump_windows
|        |—— key.pem
|        |—— openssl.cnf
|        |—— serveryounes.py
```


## Installation

### Server Setup
1. Navigate to the `RAT - HERE !/Server` directory.
2. Install required packages:
    ```bash
    pip install -r requirements.txt
    ```
3. Run the server:
    ```bash
    python server.py
    ```

### Client Setup
1. Navigate to the `RAT - HERE !/Client` directory.
2. Install required packages:
    ```bash
    pip install -r requirements.txt
    ```
3. Run the client:
    ```bash
    python client.py
    ```

## Usage
1. Start the server on your machine.
2. Start the client on the target machine.
3. Use the server console to send commands to the connected client(s).

## Disclaimer
This project is for educational purposes only. Use responsibly and do not deploy on unauthorized systems.

## License
[MIT License](LICENSE)
