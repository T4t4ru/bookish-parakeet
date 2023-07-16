import re
import urllib
import requests
import argparse
import json
from urllib.parse import urlparse

TOKEN_DATA = "YOUR_TOKEN_HERE"

API_KEY_PATTERNS = {
    "bevigil": r"[A-Za-z0-9]{64}",
    "binaryedge": r"[A-Za-z0-9]{32}",
    "bufferover": r"[A-Za-z0-9]{32}",
    "c99": r"[A-Za-z0-9]{32}",
    "censys": r"[A-Za-z0-9]{32}",
    "certspotter": r"[A-Za-z0-9]{32}",
    "chaos": r"[A-Za-z0-9]{32}",
    "chinaz": r"[A-Za-z0-9]{32}",
    "dnsdb": r"[A-Za-z0-9]{32}",
    "dnsrepo": r"[A-Za-z0-9]{32}",
    "fofa": r"[A-Za-z0-9]{32}",
    "fullhunt": r"[A-Za-z0-9]{32}",
    "github": r"[A-Za-z0-9]{32}",
    "hunter": r"[A-Za-z0-9]{32}",
    "intelx": r"[A-Za-z0-9]{32}",
    "leakix": r"[A-Za-z0-9]{32}",
    "passivetotal": r"[A-Za-z0-9]{32}",
    "quake": r"[A-Za-z0-9]{32}",
    "robtex": r"[A-Za-z0-9]{32}",
    "securitytrails": r"[A-Za-z0-9]{32}",
    "shodan": r"[A-Za-z0-9]{32}",
    "threatbook": r"[A-Za-z0-9]{32}",
    "virustotal": r"[A-Za-z0-9]{32}",
    "whoisxmlapi": r"[A-Za-z0-9]{32}",
    "zoomeye": r"[A-Za-z0-9]{32}",
    "zoomeyeapi": r"[A-Za-z0-9]{32}"
}

def get_raw_file(file_url):
    raw_host = "raw.githubusercontent.com"
    github_original_host = urlparse(file_url).hostname
    result = file_url.replace(github_original_host, raw_host)
    return result.replace('blob/', '')

def find_match(raw_url, pattern):
    with urllib.request.urlopen(raw_url) as resource:
        content = resource.read().decode(resource.headers.get_content_charset())
        keys = re.findall(pattern, content)
    return keys

def github_api_search_code(query, page, token):
    raw_urls = []
    headers = {"Authorization": "token " + token}
    url = f'https://api.github.com/search/code?s=indexed&type=Code&o=desc&q={query}&page={page}'
    response = requests.get(url, headers=headers)
    response_json = json.loads(response.content)
    for item in response_json['items']:
        raw_urls.append(get_raw_file(item['html_url']))
    return raw_urls

def parse_arguments():
    parser = argparse.ArgumentParser(description="Search for API keys in GitHub repositories")
    parser.add_argument("-bevigil", action="store_true", help="Search for Bevigil API keys")
    parser.add_argument("-binaryedge", action="store_true", help="Search for BinaryEdge API keys")
    parser.add_argument("-bufferover", action="store_true", help="Search for Bufferover API keys")
    parser.add_argument("-c99", action="store_true", help="Search for C99 API keys")
    parser.add_argument("-censys", action="store_true", help="Search for Censys API keys")
    parser.add_argument("-certspotter", action="store_true", help="Search for Certspotter API keys")
    parser.add_argument("-chaos", action="store_true", help="Search for Chaos API keys")
    parser.add_argument("-chinaz", action="store_true", help="Search for Chinaz API keys")
    parser.add_argument("-dnsdb", action="store_true", help="Search for DNSDB API keys")
    parser.add_argument("-dnsrepo", action="store_true", help="Search for DNSRepo API keys")
    parser.add_argument("-fofa", action="store_true", help="Search for Fofa API keys")
    parser.add_argument("-fullhunt", action="store_true", help="Search for FullHunt API keys")
    parser.add_argument("-github", action="store_true", help="Search for GitHub API keys")
    parser.add_argument("-hunter", action="store_true", help="Search for Hunter API keys")
    parser.add_argument("-intelx", action="store_true", help="Search for Intelx API keys")
    parser.add_argument("-leakix", action="store_true", help="Search for Leakix API keys")
    parser.add_argument("-passivetotal", action="store_true", help="Search for PassiveTotal API keys")
    parser.add_argument("-quake", action="store_true", help="Search for Quake API keys")
    parser.add_argument("-robtex", action="store_true", help="Search for Robtex API keys")
    parser.add_argument("-securitytrails", action="store_true", help="Search for SecurityTrails API keys")
    parser.add_argument("-shodan", action="store_true", help="Search for Shodan API keys")
    parser.add_argument("-threatbook", action="store_true", help="Search for Threatbook API keys")
    parser.add_argument("-virustotal", action="store_true", help="Search for VirusTotal API keys")
    parser.add_argument("-whoisxmlapi", action="store_true", help="Search for WhoisXMLAPI keys")
    parser.add_argument("-zoomeye", action="store_true", help="Search for ZoomEye API keys")
    parser.add_argument("-zoomeyeapi", action="store_true", help="Search for ZoomEyeAPI keys")
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_arguments()

    print("--- DATA COLLECTION ---")

    for api in API_KEY_PATTERNS:
        if getattr(args, api):
            query = f"{api}_api_key"
            pattern = API_KEY_PATTERNS[api]
            raw_file_urls = github_api_search_code(query, 1, TOKEN_DATA)
            for url in raw_file_urls:
                keys = find_match(url, pattern)
                if keys:
                    print(f"Found {api.upper()} API keys {keys} in file {url}")

    print("--- Data collection completed ---")
