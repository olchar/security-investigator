"""
Ad-hoc IP Enrichment Utility

Usage:
    python enrich_ips.py <ip1> <ip2> <ip3> ...
    python enrich_ips.py --file investigation.json
    python enrich_ips.py 203.0.113.42 198.51.100.10

Enriches IP addresses using ipinfo.io, vpnapi.io, and AbuseIPDB.
"""

import json
import sys
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# AbuseIPDB category ID to name mapping
ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted"
}


def load_config() -> dict:
    """Load API tokens from config.json"""
    config_path = Path(__file__).parent / 'config.json'
    with open(config_path, 'r') as f:
        return json.load(f)


def enrich_single_ip(ip: str, config: dict) -> dict:
    """Enrich a single IP address using multiple threat intelligence APIs"""
    result = {
        'ip': ip,
        'city': 'Unknown',
        'region': 'Unknown',
        'country': 'Unknown',
        'org': 'Unknown',
        'asn': 'Unknown',
        'timezone': 'Unknown',
        'is_vpn': False,
        'is_proxy': False,
        'is_tor': False,
        'is_hosting': False,
        'vpnapi_security_vpn': False,
        'vpnapi_security_proxy': False,
        'vpnapi_security_tor': False,
        'vpnapi_security_relay': False,
        'abuse_confidence_score': 0,
        'total_reports': 0,
        'is_whitelisted': False,
        'recent_comments': [],  # List of recent abuse report comments
    }
    
    # 1. IPInfo.io enrichment
    ipinfo_token = config.get('ipinfo_token')
    try:
        url = f"https://ipinfo.io/{ip}/json"
        params = {'token': ipinfo_token} if ipinfo_token else {}
        response = requests.get(url, params=params, timeout=5)
        
        if response.status_code == 200:
            ipinfo_data = response.json()
            result['city'] = ipinfo_data.get('city', 'Unknown')
            result['region'] = ipinfo_data.get('region', 'Unknown')
            result['country'] = ipinfo_data.get('country', 'Unknown')
            result['org'] = ipinfo_data.get('org', 'Unknown')
            result['timezone'] = ipinfo_data.get('timezone', 'Unknown')
            
            privacy = ipinfo_data.get('privacy', {})
            result['is_vpn'] = privacy.get('vpn', False)
            result['is_proxy'] = privacy.get('proxy', False)
            result['is_tor'] = privacy.get('tor', False)
            result['is_hosting'] = privacy.get('hosting', False)
            
            org_str = ipinfo_data.get('org', '')
            if org_str.startswith('AS'):
                result['asn'] = org_str.split(' ')[0]
    except Exception as e:
        print(f"  [ipinfo.io] Error for {ip}: {str(e)}", file=sys.stderr)
    
    # 2. VPNapi.io enrichment
    vpnapi_token = config.get('vpnapi_token')
    try:
        url = f"https://vpnapi.io/api/{ip}"
        params = {'key': vpnapi_token} if vpnapi_token else {}
        response = requests.get(url, params=params, timeout=5)
        
        if response.status_code == 200:
            vpnapi_data = response.json()
            security = vpnapi_data.get('security', {})
            result['vpnapi_security_vpn'] = security.get('vpn', False)
            result['vpnapi_security_proxy'] = security.get('proxy', False)
            result['vpnapi_security_tor'] = security.get('tor', False)
            result['vpnapi_security_relay'] = security.get('relay', False)
    except Exception as e:
        print(f"  [vpnapi.io] Error for {ip}: {str(e)}", file=sys.stderr)
    
    # 3. AbuseIPDB enrichment
    abuseipdb_token = config.get('abuseipdb_token')
    if abuseipdb_token:
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': abuseipdb_token,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            response = requests.get(url, headers=headers, params=params, timeout=5)
            
            if response.status_code == 200:
                abuse_data = response.json().get('data', {})
                result['abuse_confidence_score'] = abuse_data.get('abuseConfidenceScore', 0)
                result['total_reports'] = abuse_data.get('totalReports', 0)
                result['is_whitelisted'] = abuse_data.get('isWhitelisted', False)
            elif response.status_code == 429:
                print(f"  [AbuseIPDB] Rate limit for {ip}", file=sys.stderr)
        except Exception as e:
            print(f"  [AbuseIPDB] Error for {ip}: {str(e)}", file=sys.stderr)
        
        # 4. Fetch AbuseIPDB comments/reports (separate API call)
        if result['total_reports'] > 0:
            try:
                reports_url = "https://api.abuseipdb.com/api/v2/reports"
                reports_params = {
                    'ipAddress': ip,
                    'maxAgeInDays': 90,
                    'perPage': 5  # Get 5 most recent
                }
                reports_response = requests.get(reports_url, headers=headers, params=reports_params, timeout=5)
                
                if reports_response.status_code == 200:
                    reports_data = reports_response.json().get('data', {}).get('results', [])
                    for report in reports_data:
                        cat_ids = report.get('categories', [])
                        cat_names = [ABUSE_CATEGORIES.get(c, f"#{c}") for c in cat_ids]
                        result['recent_comments'].append({
                            'date': report.get('reportedAt', '')[:19].replace('T', ' '),
                            'reporter_country': report.get('reporterCountryCode', '??'),
                            'categories': cat_names,
                            'comment': report.get('comment', '(no comment)')[:300]
                        })
            except Exception as e:
                print(f"  [AbuseIPDB Reports] Error for {ip}: {str(e)}", file=sys.stderr)
    
    return result


def enrich_ips(ip_list: list[str], max_workers: int = 3) -> list[dict]:
    """Enrich multiple IPs in parallel"""
    config = load_config()
    results = []
    
    print(f"Enriching {len(ip_list)} IPs using ipinfo.io, vpnapi.io, AbuseIPDB...\n")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(enrich_single_ip, ip, config): ip for ip in ip_list}
        
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                results.append(result)
                
                # Show inline status
                flags = []
                if result['is_vpn'] or result['vpnapi_security_vpn']:
                    flags.append("VPN")
                if result['is_proxy'] or result['vpnapi_security_proxy']:
                    flags.append("Proxy")
                if result['is_tor'] or result['vpnapi_security_tor']:
                    flags.append("Tor")
                if result['vpnapi_security_relay']:
                    flags.append("Relay")
                if result['abuse_confidence_score'] > 0:
                    flags.append(f"Abuse:{result['abuse_confidence_score']}%")
                
                flag_str = f"[{', '.join(flags)}]" if flags else "[Clean]"
                print(f"  OK {ip:<17} {flag_str}")
            except Exception as e:
                print(f"  FAIL {ip} - {str(e)}")
    
    return sorted(results, key=lambda x: x['ip'])


def print_detailed_results(results: list[dict]):
    """Print detailed enrichment results table"""
    print(f"\n{'='*130}")
    print(f"Detailed Results ({len(results)} IPs):\n")
    print(f"{'IP Address':<17} | {'City':<20} | {'Country':<3} | {'ISP/Org':<30} | {'Flags':<45}")
    print(f"{'-'*130}")
    
    for item in results:
        flags = []
        if item['is_vpn']:
            flags.append("ipinfo:VPN")
        if item['vpnapi_security_vpn']:
            flags.append("vpnapi:VPN")
        if item['is_proxy']:
            flags.append("ipinfo:Proxy")
        if item['vpnapi_security_proxy']:
            flags.append("vpnapi:Proxy")
        if item['is_tor']:
            flags.append("ipinfo:Tor")
        if item['vpnapi_security_tor']:
            flags.append("vpnapi:Tor")
        if item['vpnapi_security_relay']:
            flags.append("vpnapi:Relay")
        if item['abuse_confidence_score'] > 0:
            flags.append(f"Abuse:{item['abuse_confidence_score']}%")
        if item['total_reports'] > 0:
            flags.append(f"Reports:{item['total_reports']}")
        if item['is_whitelisted']:
            flags.append("Whitelisted")
        
        flag_str = ", ".join(flags) if flags else "Clean"
        print(f"{item['ip']:<17} | {item['city']:<20} | {item['country']:<3} | {item['org'][:30]:<30} | {flag_str}")


def print_abuse_comments(results: list[dict]):
    """Print AbuseIPDB comments for IPs with reports"""
    ips_with_comments = [r for r in results if r.get('recent_comments')]
    
    if not ips_with_comments:
        return
    
    print(f"\n{'='*130}")
    print(f"AbuseIPDB Recent Reports ({len(ips_with_comments)} IPs with comments):\n")
    
    # Sort by abuse score descending
    ips_with_comments.sort(key=lambda x: x['abuse_confidence_score'], reverse=True)
    
    for item in ips_with_comments:
        print(f"{'─'*130}")
        print(f"🔴 {item['ip']} | {item['city']}, {item['country']} | Abuse Score: {item['abuse_confidence_score']}% | Reports: {item['total_reports']}")
        print(f"{'─'*130}")
        
        for i, comment in enumerate(item['recent_comments'], 1):
            cats = ", ".join(comment['categories'])
            print(f"  [{i}] {comment['date']} UTC (from {comment['reporter_country']})")
            print(f"      Attack Types: {cats}")
            print(f"      Comment: {comment['comment']}")
            print()


def print_summary(results: list[dict]):
    """Print summary statistics"""
    print(f"\n{'='*130}")
    print("Summary Statistics:\n")
    print("  ipinfo.io Detection:")
    print(f"    VPN IPs: {sum(1 for x in results if x['is_vpn'])}")
    print(f"    Proxy IPs: {sum(1 for x in results if x['is_proxy'])}")
    print(f"    Tor IPs: {sum(1 for x in results if x['is_tor'])}")
    print(f"    Hosting IPs: {sum(1 for x in results if x['is_hosting'])}")
    print("\n  vpnapi.io Detection:")
    print(f"    VPN IPs: {sum(1 for x in results if x['vpnapi_security_vpn'])}")
    print(f"    Proxy IPs: {sum(1 for x in results if x['vpnapi_security_proxy'])}")
    print(f"    Tor IPs: {sum(1 for x in results if x['vpnapi_security_tor'])}")
    print(f"    Relay IPs: {sum(1 for x in results if x['vpnapi_security_relay'])}")
    print("\n  AbuseIPDB Detection:")
    print(f"    IPs with reports: {sum(1 for x in results if x['total_reports'] > 0)}")
    print(f"    High confidence (>75%): {sum(1 for x in results if x['abuse_confidence_score'] > 75)}")
    print(f"    Medium confidence (25-75%): {sum(1 for x in results if 25 <= x['abuse_confidence_score'] <= 75)}")
    print(f"    Whitelisted: {sum(1 for x in results if x['is_whitelisted'])}")
    print("\n  Overall:")
    print(f"    Clean residential IPs: {sum(1 for x in results if not any([x['is_vpn'], x['vpnapi_security_vpn'], x['is_proxy'], x['vpnapi_security_proxy'], x['is_tor'], x['vpnapi_security_tor'], x['abuse_confidence_score'] > 0]))}")


def extract_ips_from_investigation(json_path: str) -> list[str]:
    """Extract unenriched IPs from an investigation JSON file or simple IP list JSON"""
    with open(json_path, 'r') as f:
        data = json.load(f)
    
    # Check if this is a simple IP list file (honeypot format)
    if 'ips' in data and isinstance(data['ips'], list):
        return data['ips']
    
    # Otherwise, extract from full investigation format
    # Get already enriched IPs
    enriched_ips = {item['ip'] for item in data.get('ip_enrichment', [])}
    
    # Extract all IPv4 addresses from signin data
    all_ips = set()
    for app in data.get('signin_apps', []):
        for ip in app.get('IPAddresses', []):
            if ':' not in ip:  # Skip IPv6
                all_ips.add(ip)
    
    for loc in data.get('signin_locations', []):
        for ip in loc.get('IPAddresses', []):
            if ':' not in ip:  # Skip IPv6
                all_ips.add(ip)
    
    # Return unenriched IPs
    return sorted(all_ips - enriched_ips)


def main():
    """CLI entry point"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python enrich_ips.py <ip1> <ip2> <ip3> ...")
        print("  python enrich_ips.py --file <json_file>")
        print("\nJSON File Formats:")
        print("  1. Simple IP list: {\"ips\": [\"1.2.3.4\", \"5.6.7.8\"]}")
        print("  2. Full investigation JSON (auto-extracts unenriched IPs)")
        print("\nExamples:")
        print("  python enrich_ips.py 203.0.113.42 198.51.100.10")
        print("  python enrich_ips.py --file temp/honeypot_ips_20251213.json")
        print("  python enrich_ips.py --file temp/investigation_user_20251130.json")
        sys.exit(1)
    
    # Parse arguments
    if sys.argv[1] == '--file':
        if len(sys.argv) < 3:
            print("Error: --file requires a path to investigation JSON")
            sys.exit(1)
        ip_list = extract_ips_from_investigation(sys.argv[2])
        if not ip_list:
            print("No unenriched IPs found in investigation file")
            sys.exit(0)
    else:
        ip_list = sys.argv[1:]
    
    # Enrich IPs
    results = enrich_ips(ip_list)
    
    # Display results
    print_detailed_results(results)
    print_abuse_comments(results)  # New: show abuse comments
    print_summary(results)
    
    # Optionally save to JSON
    from datetime import datetime
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = Path('temp') / f'ip_enrichment_{timestamp}.json'
    output_file.parent.mkdir(exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {output_file}")


if __name__ == '__main__':
    main()
