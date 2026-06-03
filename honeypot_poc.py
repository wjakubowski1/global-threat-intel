import socket
import datetime
import psycopg2
import requests
import threading
import os
from dotenv import load_dotenv
load_dotenv()


# configuration for postgresql database
DB_CONFIG = {
    "dbname": "honeypot_db",
    "user": "admin_honeypot",
    "password": os.getenv("DB_PASSWORD"),
    "host": "localhost",
    "port": "5432"
}


# setup postgresql database and create table if it doesn't exist
def init_db():
    try:
        db = psycopg2.connect(**DB_CONFIG)
        cursor = db.cursor()
        
        # table to store attack data / if it doesn't exist (using SERIAL for postgresql)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP,
                ip_address VARCHAR(50),
                port INTEGER,
                country VARCHAR(100),
                city VARCHAR(100),
                lat REAL,
                lon REAL,
                payload TEXT
            )
        ''')
        db.commit()
        cursor.close()
        db.close()
    except Exception as e:
        print(f"[-] Database initialization error: {e}")
        exit()


# function to handle each attack independently in a new thread
def handle_attacker(conn, addr):
    with conn:
        # set timeout to prevent attackers from blocking the trap
        conn.settimeout(5)
        
        # when someone connects, grab their details
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        attacker_ip = addr[0]
        attacker_port = addr[1]
        
        print(f"[{timestamp}] [ALERT] Incoming connection from: {attacker_ip}:{attacker_port}")
        
        country, city, lat, lon, payload = "Unknown", "Unknown", 0.0, 0.0, "No payload"

        # recieve data inside the active connection
        try:
            data = conn.recv(1024)
            if data:
                payload = data.decode('utf-8', errors='ignore').strip()
                print(f"[*] Captured payload: {payload}")
        except Exception as e:
            print(f"[-] Data receive error: {e}")

    if attacker_ip == "127.0.0.1":
        country, city = "Localhost", "Localhost"
        print("[*] IP is local. Skipping API request.")
    else:
        try:
            # query the external API using https for security
            url = f"https://ipinfo.io/{attacker_ip}/json"
            response = requests.get(url, timeout=3)
            
            # throw exception if api returns an error code
            response.raise_for_status()
            
            api_data = response.json()
            
            country = api_data.get("country", "Unknown")
            city = api_data.get("city", "Unknown")
            
            # ipinfo.io stores coordinates in one string "lat,lon"
            loc = api_data.get("loc", "0,0").split(",")
            if len(loc) == 2:
                lat = float(loc[0])
                lon = float(loc[1])
                
        except Exception as e:
            print(f"[!] Geolocation API error: {e}")

    # export enriched data to the database
    try:
        # open connection specifically for this thread
        db = psycopg2.connect(**DB_CONFIG)
        cursor = db.cursor()
        
        # export enriched data to the database (postgresql uses %s instead of ?)
        cursor.execute('''
            INSERT INTO attacks (timestamp, ip_address, port, country, city, lat, lon, payload)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (timestamp, attacker_ip, attacker_port, country, city, lat, lon, payload))
        
        db.commit()
        cursor.close()
        db.close()
        print("[*] Attack logged to the database successfully.")
        
    except Exception as e:
        print(f"[-] Error processing DB: {e}")


# main execution function
def main():
    init_db()

    # configuration of the trap
    HOST = '0.0.0.0' # listen on all available local network interfaces
    PORT = 2222      # use a port above 1024 so we don't need root/admin privileges

    print("-" * 50)
    print(f"[*] Honeypot is active. Listening on port {PORT}...")
    print("[*] Database is ready and recording with Geolocation.")
    print("-" * 50)

    # create the network socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen() 

        while True:
            # wait on silent for a connection
            conn, addr = s.accept()
            
            # create and start a new thread for the attacker
            attacker_thread = threading.Thread(target=handle_attacker, args=(conn, addr))
            attacker_thread.daemon = True # ensure threads close when the main script stops
            attacker_thread.start()


if __name__ == "__main__":
    main()