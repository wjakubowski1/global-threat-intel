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
        lat REAL,
        lon REAL,
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
            
            country, city, lat, lon, payload = "Unknown", "Unknown", 0.0, 0.0, "No payload"

        if attacker_ip == "127.0.0.1":
            country, city = "Localhost", "Localhost"
            print("[*] IP is local. Skipping API request.")
        else:
            try:
                # query the external API for real IP addresses
                response = requests.get(f"http://ip-api.com/json/{attacker_ip}", timeout=3)
                api_data = response.json()
                
                if api_data.get("status") == "success":
                    country = api_data.get("country", "Unknown")
                    city = api_data.get("city", "Unknown")
                    lat = api_data.get("lat", 0.0)
                    lon = api_data.get("lon", 0.0)
            except Exception as e:
                print(f"[!] Geolocation API error: {e}")

        # recieve data and override empty payload
        try:
            data = conn.recv(1024)
            if data:
                payload = data.decode('utf-8', errors='ignore').strip()
                print(f"[*] Captured payload: {payload}")
        except Exception as e:
            print(f"[-] Data receive error: {e}")

        # export enriched data to the database
        try:
            cursor.execute('''
                INSERT INTO attacks (timestamp, ip_address, port, country, city, lat, lon, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, attacker_ip, attacker_port, country, city, lat, lon, payload))
            
            db.commit()
            print("[*] Attack logged to the database successfully.")
            
        except Exception as e:
            print(f"[-] Error processing DB: {e}")