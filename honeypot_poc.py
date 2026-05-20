import socket
import datetime

# 1. Configuration of the trap
HOST = '0.0.0.0' # Listen on all available local network interfaces
PORT = 2222      # We use a port above 1024 so we don't need root/admin privileges

print("-" * 50)
print(f"[*] Honeypot is active. Listening on port {PORT}...")
print("-" * 50)

# 2. Create the network socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen() 
    
    while True:
        # 3. Wait silently for a connection
        conn, addr = s.accept()
        
        with conn:
            # When someone connects, grab their details
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            attacker_ip = addr[0]
            attacker_port = addr[1]
            
            print(f"[{timestamp}] [ALERT] Incoming connection from: {attacker_ip}:{attacker_port}")
            
            # 4. Send a fake response (banner) to trick automated scanners
            fake_banner = b"Ubuntu 22.04 LTS\nLogin: "
            conn.sendall(fake_banner)
            
            # 5. Capture whatever the attacker types
            try:
                data = conn.recv(1024)
                if data:
                    print(f"[*] Captured payload: {data.decode('utf-8', errors='ignore').strip()}")
            except Exception:
                pass