import requests
import pandas as pd
import time
import os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
if not API_KEY:
    raise ValueError("API Key not found! Make sure you have a .env file here")

# IP list to check - 
CSV_FILE = "ip_list.csv"
try:
    df = pd.read_csv(CSV_FILE)
    IP_LIST = df["ip_address"].tolist() # convert the IP column to a list
except Exception as e:
    raise ValueError(f"Error reading file:{e}")

# Function to check IP reputation
def check_reputation(ip):
    url =f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        last_analysis_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return last_analysis_stats
    else:
        return {"error": f"Failed to fetch data for {ip}"}
    
# Run checks
results = []
for ip in IP_LIST:
print(f"Checking IP: {ip}...")
result = check_reputation(ip)
result["ip"] = ip
results.append(result)
time.sleep(15)

# Convert results to a dataframe
df_results = pd.DataFrame(results)

# Save results to a csv
output_file = "ip_reputation_results.csv"
df_results.to_csv(output_file, index=False)
print(f"IP reputation check completed. results saved in '{output_file}'")
    