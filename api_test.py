import requests

# public DNS address from google (8.8.8.8)
target_ip = "8.8.8.8"
print(f"Sending IP Request: {target_ip}...")

# free API
response = requests.get(f"http://ip-api.com/json/{target_ip}")
data = response.json()

# print out most important data
print("-" * 30)
print(f"Country: {data['country']}")
print(f"City: {data['city']}")
print(f"Internet provider (ISP): {data['isp']}")
print("-" * 30)