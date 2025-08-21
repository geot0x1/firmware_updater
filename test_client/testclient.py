import socket
import time
import sys

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9090

def test_client(id):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            print(f"Connected to {SERVER_HOST}:{SERVER_PORT}")

            # Send request for firmware ID=v1
            request = f"ID={id}\r\n".encode()
            s.sendall(request)
            print("Sent:", request.decode().strip())

            while True:
                # Receive server response
                response = s.recv(1024)
                if response:
                    for byte in response:
                        print(hex(byte).replace("0x", ""), end=' ')

                # Send acknowledgment
                ack = "DATA OK\r\n".encode()
                s.sendall(ack)
                print("Sent:", ack.decode().strip())

                # Wait for a moment before closing
                time.sleep(0.1)

    except Exception as e:
        print("Error:", e)


if __name__ == "__main__":
    id = sys.argv[1]
    while True:
        test_client(id)
        time.sleep(5)  # Wait before reconnecting
