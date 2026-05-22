# Global Threat Intel Honeypot

A simple script written in Python, created as part of learning threat intelligence and cloud infrastructure in a SOC environment (Blue Team).

## What does this script do?

The script acts as a fake server (honeypot) listening for unauthorized connection attempts on a specific port. When an automated bot or attacker connects, the script captures the data they send (payload) and extracts their IP address. Then, it uses an external API to find their exact geographical coordinates (Latitude and Longitude). All of this data is logged into a local SQLite database, which is later used to visualize the attacks in real-time on an interactive world map using Grafana. 

## How to run it?

1. Open the terminal on your Linux server (AWS EC2 Ubuntu).
2. Optional – create and activate a virtual environment to keep dependencies clean: 
   `python3 -m venv venv`
   `source venv/bin/activate`
3. Install the required library for API requests: `pip install requests`
4. Run the script: `python3 honeypot_poc.py`
5. Optional - to keep the script running in the background 24/7 after closing the terminal, use the `tmux` tool before running the script.
