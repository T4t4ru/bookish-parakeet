import re
import urllib
import requests
import json
from urllib.parse import urlparse

SHODAN_API_KEY_REGEX = r"[0-9a-zA-Z]{32}"
TOKEN_DATA = "YOUR_TOKEN_HERE"

def get_raw_file(file_url):
    raw_host = "raw.githubusercontent.com"
    github_original_host = urlparse(file_url).hostname
    result = file_url.replace(github_original_host, raw_host)
    return result.replace('blob/', '')

def find_match(raw_url):
    with urllib.request.urlopen(raw_url) as resource:
        content = resource.read().decode(resource.headers.get_content_charset())
        keys = re.findall(SHODAN_API_KEY_REGEX, content)
    return keys

def github_api_search_code(query, page):
    raw_urls = []
    headers = {"Authorization": "token " + TOKEN_DATA}
    url = f'https://api.github.com/search/code?s=indexed&type=Code&o=desc&q={query}&page={page}'
    response = requests.get(url, headers=headers)
    response_json = json.loads(response.content)
    for item in response_json['items']:
        raw_urls.append(get_raw_file(item['html_url']))
    return raw_urls

if __name__ == '__main__':
    print("--- DATA COLLECTION ---")
    query = 'shodan_api_key'
    page = 1
    raw_file_urls = github_api_search_code(query, page)
    for url in raw_file_urls:
        keys = find_match(url)
        if keys:
            print(f"Shodan API keys found {keys} in file {url}")
    print("--- Data collection completed ---")
