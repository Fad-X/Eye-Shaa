import requests
from tabulate import tabulate

# Replace with your actual VirusTotal API key
API_KEY = 'your_virustotal_api_key_here'
VT_URL = 'https://www.virustotal.com/api/v3/ip_addresses/'


def load_ips(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]


def check_ip_reputation(ip):
    headers = {
        'x-apikey': API_KEY
    }
    response = requests.get(VT_URL + ip, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        return {
            'ip': ip,
            'harmless': stats.get('harmless', 0),
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
        }
    else:
        return {
            'ip': ip,
            'error': f"Failed - Status Code: {response.status_code}"
        }


if __name__ == '__main__':
    # REPLACE WITH YOUR IP ADDRESS FILE PATH
    ip_list = load_ips('FILE-PATH-HERE')

    undetected_ips = []
    flagged_ips = []
    failed_ips = []

    for ip in ip_list:
        result = check_ip_reputation(ip)
        if 'error' in result:
            failed_ips.append([ip, result['error']])
            continue

        if result['malicious'] > 0 or result['suspicious'] > 0:
            flagged_ips.append([result['ip'], result['malicious'], result['suspicious']])
        else:
            undetected_ips.append([result['ip'], result['undetected'], result['harmless']])

    print("\n--- 🟢 Undetected IPs ---")
    print(tabulate(undetected_ips, headers=['IP', 'Undetected', 'Harmless'], tablefmt='pretty'))

    print("\n--- 🔴 Suspicious / Malicious IPs ---")
    print(tabulate(flagged_ips, headers=['IP', 'Malicious', 'Suspicious'], tablefmt='pretty'))

    if failed_ips:
        print("\n--- ⚠️ Failed Lookups ---")
        print(tabulate(failed_ips, headers=['IP', 'Error'], tablefmt='pretty'))
