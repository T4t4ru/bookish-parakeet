GitHub API Key Scraper
This is a Python script to search GitHub code for exposed API keys.

Usage
The script accepts the following arguments:

Copy code

-bevigil - Search for Bevigil API keys
-binaryedge - Search for BinaryEdge API keys  
-bufferover - Search for Bufferover API keys
...
To search for a specific API key, pass the corresponding argument. Multiple arguments can be passed to search for multiple API keys.

A valid GitHub token must be provided in TOKEN_DATA.

Example:

bash

Copy code

python scraper.py -shodan -virustotal
This will search GitHub code for Shodan and VirusTotal API keys.

Implementation
The script uses the GitHub code search API to find files containing API keys. It searches for common patterns used for different API keys.

The key components are:

APIKeyScraper - Main scraper class
get_raw_file() - Gets raw file URL from GitHub URL
search_github() - Searches GitHub code using the API
find_matches() - Extracts API keys from file content
run() - Runs the scraper for given APIs
The script is structured in an Object Oriented manner with the scraper being a class.

Contributing
Pull requests are welcome to add support for more APIs. New API key patterns can be added to the api_patterns dictionary in the APIKeyScraper class.

License
This project is licensed under the MIT License - see the LICENSE file for details.
