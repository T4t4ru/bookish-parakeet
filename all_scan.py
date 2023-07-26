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
    parser.add_argument("-all", action="store_true", help="Search for all supported API keys")
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_arguments()

    print("--- DATA COLLECTION ---")

    if args.all:
        for api, pattern in API_KEY_PATTERNS.items():
            query = f"{api}_api_key"
            raw_file_urls = github_api_search_code(query, 1, TOKEN_DATA)
            for url in raw_file_urls:
                keys = find_match(url, pattern)
                if keys:
                    print(f"Found {api.upper()} API keys {keys} in file {url}")
    else:
        for api, pattern in API_KEY_PATTERNS.items():
            if getattr(args, api):
                query = f"{api}_api_key"
                raw_file_urls = github_api_search_code(query, 1, TOKEN_DATA)
                for url in raw_file_urls:
                    keys = find_match(url, pattern)
                    if keys:
                        print(f"Found {api.upper()} API keys {keys} in file {url}")

    print("--- Data collection completed ---")
