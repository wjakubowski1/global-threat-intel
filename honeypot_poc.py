import socket
import datetime
import sqlite3
import requests


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
        country TEXT,
        city TEXT,
        payload TEXT
    )
''')
db.commit()


# configuration of the trap
HOST = '0.0.0.0' # listen on all available local network interfaces
PORT = 2222      # use a port above 1024 so we don't need root/admin privileges

print("-" * 50)
print(f"[*] Honeypot is active. Listening on port {PORT}...")
print("[*] Database 'threat_logs.db' is ready and recording with Geolocation.")
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
            
            country = "Unknown"
            city = "Unknown"
            
            if attacker_ip == "127.0.0.1":
                country = "Localhost"
                city = "Local network"
                print("[*] IP is local. Skipping API request.")
            else:
                try:
                    # query the external API for real IP addresses
                    response = requests.get(f"http://ip-api.com/json/{attacker_ip}", timeout=3)
                    api_data = response.json()
                    
                    if api_data.get("status") == "success":
                        country = api_data.get("country", "Unknown")
                        city = api_data.get("city", "Unknown")
                        print(f"[*] Geolocation matched: {city}, {country}")
                except Exception as e:
                    print("[!] Geolocation API error. Proceeding with 'Unknown'.")

            # send a fake response (banner) to trick automated scanners
            fake_banner = b"Ubuntu 22.04 LTS\nLogin: "
            conn.sendall(fake_banner)
            
            # capture payload and save to db
            try:
                data = conn.recv(1024)
                if data:
                    payload = data.decode('utf-8', errors='ignore').strip()
                    print(f"[*] Captured payload: {payload}")
                    
                    # Injecting enriched data into the database
                    cursor.execute('''
                        INSERT INTO attacks (timestamp, ip_address, port, country, city, payload) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (timestamp, attacker_ip, attacker_port, country, city, payload))
                    
                    db.commit() 
                    print("[*] Attack logged to the database successfully.")
                    
            except Exception as e:
                print(f"[-] Error processing: {e}")