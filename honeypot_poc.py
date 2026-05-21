import socket
import datetime
import sqlite3


# connect to SQLite / creates the file if it doesn't exist
db = sqlite3.connect("threat_logs.db")
cursor = db.cursor()

# table to store attack data / if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip_address TEXT,
         port INTEGER,
         payload TEXT
    )
''')
db.commit()


# configuration of the trap
HOST = '0.0.0.0' # listen on all available local network interfaces
PORT = 2222      # use a port above 1024 so we don't need root/admin privileges

print("-" * 50)
print(f"[*] Honeypot is active. Listening on port {PORT}...")
print("-" * 50)

# create the network socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen() 

    while True:
        # wait on silent for a connection
        conn, addr = s.accept()
        
        with conn:
            # when someone connects, grab their details
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            attacker_ip = addr[0]
            attacker_port = addr[1]
            
            print(f"[{timestamp}] [ALERT] Incoming connection from: {attacker_ip}:{attacker_port}")
            
            # send a fake response (banner) to trick automated scanners
            fake_banner = b"Ubuntu 22.04 LTS\nLogin: "
            conn.sendall(fake_banner)
            
            # capture whatever the attacker types
            try:
                data = conn.recv(1024)
                if data:
                    # decode the raw bytes into a readable string
                    payload = data.decode('utf-8', errors='ignore').strip()
                    print(f"[*] Captured payload: {payload}")
                    
                    # database Injection
                    # save the captured details into the SQLite database
                    cursor.execute('''
                        INSERT INTO attacks (timestamp, ip_address, port, payload) 
                        VALUES (?, ?, ?, ?)
                    ''', (timestamp, attacker_ip, attacker_port, payload))
                    
                    db.commit() # save changes to the disk physically
                    print("[*] Attack successfully logged to the database.")
                    
            except Exception as e:
                # catch and ignore errors so the honeypot doesn't crash on bad inputs
                pass