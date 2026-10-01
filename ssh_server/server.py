import os
import sys
import json
import socket
import threading
import logging
import uuid
import requests
import paramiko

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(threadName)s: %(message)s"
)

# Configuration from environment variables with sane defaults
HOST_KEY_FILE = os.getenv("SSH_HOST_KEY", "server.key")
SSH_HOST = os.getenv("SSH_HOST", "0.0.0.0")
SSH_PORT = int(os.getenv("SSH_PORT", "2222"))
HARNESS_API_URL = os.getenv("HARNESS_API_URL", "http://localhost:8000/api/command")
AUTH_LOG_FILE = os.getenv("AUTH_LOG_FILE", "logs/auth_attempts.jsonl")

# Ensure logs directory exists
os.makedirs(os.path.dirname(AUTH_LOG_FILE) if "/" in AUTH_LOG_FILE else "logs", exist_ok=True)

# Load local RSA host key
try:
    if os.path.exists(HOST_KEY_FILE):
        HOST_KEY = paramiko.RSAKey(filename=HOST_KEY_FILE)
    else:
        logging.info(f"Host key '{HOST_KEY_FILE}' not found. Generating a temporary 2048-bit RSA key...")
        HOST_KEY = paramiko.RSAKey.generate(2048)
        HOST_KEY.write_private_key_file(HOST_KEY_FILE)
        logging.info(f"Generated and saved host key to '{HOST_KEY_FILE}'.")
except Exception as e:
    logging.error(f"Failed to load or generate host key '{HOST_KEY_FILE}': {e}")
    sys.exit(1)


def log_auth_attempt(ip, username, password=None, auth_type="password"):
    """Persist credential attempt for Track 3 Threat Intel Dashboard."""
    record = {
        "event": "auth_attempt",
        "ip": str(ip),
        "username": username,
        "password": password,
        "auth_type": auth_type
    }
    try:
        with open(AUTH_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as err:
        logging.warning(f"Could not write auth log entry: {err}")


class DeceptiNodeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.username = "root"
        self.password = None
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        logging.info(f"Auth Attempt [Password] | IP: {self.client_ip} | User: '{username}' | Pass: '{password}'")
        log_auth_attempt(self.client_ip, username, password, auth_type="password")
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        self.username = username
        logging.info(f"Auth Attempt [PublicKey] | IP: {self.client_ip} | User: '{username}'")
        log_auth_attempt(self.client_ip, username, auth_type="publickey")
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True


def handle_client(client_socket, client_addr):
    client_ip = client_addr[0]
    session_id = str(uuid.uuid4())[:8]
    logging.info(f"[{session_id}] New connection from {client_ip}:{client_addr[1]}")

    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)
        server = DeceptiNodeSSHServer(client_ip)

        transport.start_server(server=server)
        chan = transport.accept(timeout=20)

        if chan is None:
            logging.warning(f"[{session_id}] Channel negotiation timed out.")
            return

        server.event.wait(timeout=10)
        if not server.event.is_set():
            logging.warning(f"[{session_id}] Client did not request interactive shell.")
            return

        # Terminal banner & realistic prompt
        welcome_banner = (
            "Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.8.0-40-generic x86_64)\r\n"
            " * Documentation:  https://help.ubuntu.com\r\n"
            " * Management:     https://landscape.canonical.com\r\n"
            " * Support:        https://ubuntu.com/pro\r\n\r\n"
        )
        prompt = f"{server.username}@ubuntu-server:~# " if server.username else "root@ubuntu-server:~# "

        chan.send(welcome_banner)
        chan.send(prompt)

        cmd_buffer = ""

        while True:
            data = chan.recv(1024)
            if not data:
                break

            for char in data.decode("utf-8", errors="ignore"):
                # Handle Enter key (\r or \n)
                if char in ("\r", "\n"):
                    chan.send("\r\n")
                    command = cmd_buffer.strip()

                    if command:
                        # Handle exit / logout directly
                        if command in ("exit", "logout"):
                            chan.send("logout\r\n")
                            return

                        logging.info(f"[{session_id} | {client_ip}] Executed: '{command}'")

                        # Forward command to Harness Engine (Track 2 API)
                        try:
                            payload = {
                                "command": command,
                                "ip": client_ip,
                                "session_id": session_id,
                                "username": server.username,
                                "password": server.password
                            }
                            response = requests.post(
                                HARNESS_API_URL,
                                json=payload,
                                timeout=10
                            )
                            if response.status_code == 200:
                                output = response.text
                            else:
                                output = f"bash: internal harness error (HTTP {response.status_code})\n"
                        except Exception as req_err:
                            output = f"bash: harness engine unreachable ({req_err})\n"

                        # Ensure standard CRLF (\r\n) line endings for SSH terminal display
                        formatted_output = output.replace("\r\n", "\n").replace("\n", "\r\n")
                        chan.send(formatted_output)

                    cmd_buffer = ""
                    chan.send(prompt)

                # Handle Backspace (\x08 or \x7f)
                elif char in ("\x08", "\x7f"):
                    if len(cmd_buffer) > 0:
                        cmd_buffer = cmd_buffer[:-1]
                        chan.send("\b \b")

                # Handle Ctrl+C (\x03)
                elif char == "\x03":
                    cmd_buffer = ""
                    chan.send("^C\r\n" + prompt)

                # Handle Ctrl+D (\x04) -> EOF / Exit
                elif char == "\x04":
                    chan.send("\r\nlogout\r\n")
                    return

                # Ignore non-printable control sequences (arrow keys, tab, etc.)
                elif ord(char) < 32:
                    continue

                # Normal character keystroke
                else:
                    cmd_buffer += char
                    chan.send(char)

    except Exception as e:
        logging.error(f"[{session_id}] Error in client session: {e}")
    finally:
        if transport:
            transport.close()
        client_socket.close()
        logging.info(f"[{session_id}] Session closed for {client_ip}")


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((SSH_HOST, SSH_PORT))
    server_socket.listen(100)

    logging.info(f"Decepti-Node SSH Gateway active on {SSH_HOST}:{SSH_PORT}...")
    logging.info(f"Routing commands to Harness Engine at: {HARNESS_API_URL}")

    while True:
        try:
            client_socket, client_addr = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_addr),
                daemon=True
            )
            client_thread.start()
        except KeyboardInterrupt:
            logging.info("Shutting down Decepti-Node SSH Gateway.")
            break
        except Exception as e:
            logging.error(f"Socket error: {e}")


if __name__ == "__main__":
    start_server()
