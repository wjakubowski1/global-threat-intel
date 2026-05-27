import requests

# public DNS address from google (8.8.8.8)
target_ip = "8.8.8.8"
print(f"Sending IP Request: {target_ip}...")

# free API
try:
    response = requests.get(f"https://ipinfo.io/{target_ip}/json", timeout=3)
    response.raise_for_status() # error for codes 4xx an 5xx
    
    data = response.json()
# print out most important data
    print("-" * 30)
    print(f"Country: {data.get('country', 'Unknown')}")
    print(f"City: {data.get('city', 'Unknown')}")
    print("-" * 30)
except Exception as e:
    print(f"Błąd API: {e}")