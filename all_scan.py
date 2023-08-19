import re
import urllib
import requests
import argparse
import json
from urllib.parse import urlparse

TOKEN_DATA = "YOUR_TOKEN_HERE"

class GitHubApiKeySearch:
    def __init__(self, token):
        self.token = token
        self.raw_host = "raw.githubusercontent.com"

    def get_raw_file(self, file_url):
        github_original_host = urlparse(file_url).hostname
        result = file_url.replace(github_original_host, self.raw_host)
        return result.replace('blob/', '')

    def find_match(self, raw_url, pattern):
        with urllib.request.urlopen(raw_url) as resource:
            content = resource.read().decode(resource.headers.get_content_charset())
            keys = re.findall(pattern, content)
        return keys

    def github_api_search_code(self, query, page):
        raw_urls = []
        headers = {"Authorization": "token " + self.token}
        url = f'https://api.github.com/search/code?s=indexed&type=Code&o=desc&q={query}&page={page}'
        response = requests.get(url, headers=headers)
        response_json = json.loads(response.content)
        for item in response_json['items']:
            raw_urls.append(self.get_raw_file(item['html_url']))
        return raw_urls

    def search_api_keys(self, patterns, query, page):
        raw_file_urls = self.github_api_search_code(query, page)
        found_keys = []
        for url in raw_file_urls:
            for api, pattern in patterns.items():
                keys = self.find_match(url, pattern)
                if keys:
                    found_keys.append(f"Found {api.upper()} API keys {keys} in file {url}")
        return found_keys

def parse_arguments():
    parser = argparse.ArgumentParser(description="Search for API keys in GitHub repositories")
    parser.add_argument("-all", action="store_true", help="Search for all supported API keys")
    parser.add_argument("-telegram", action="store_true", help="Search for Telegram API keys")
    parser.add_argument("-openai", action="store_true", help="Search for OpenAI API keys")
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_arguments()

    print("--- DATA COLLECTION ---")

    api_key_patterns = {
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
        "zoomeyeapi": r"[A-Za-z0-9]{32}",
        "telegram": r"[A-Za-z0-9]{45}",
        "openai": r"[A-Za-z0-9]{32}-[A-Za-z0-9]{32}-[A-Za-z0-9]{32}-[A-Za-z0-9]{32}-[A-Za-z0-9]{32}"
    }

    search_manager = GitHubApiKeySearch(TOKEN_DATA)

    output = []

    if args.all:
        output.extend(search_manager.search_api_keys(api_key_patterns, '', 1))
    else:
        for api, pattern in api_key_patterns.items():
            if getattr(args, api):
                query = f"{api}_api_key"
                output.extend(search_manager.search_api_keys({api: pattern}, query, 1))

    with open('Save_api.txt', 'w') as file:
        for line in output:
            file.write(line + '\n')

    print("--- Data collection completed ---")
