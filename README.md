# GitHub API Key Scraper

This is a Python script to search GitHub code for exposed API keys.

## Usage

The script accepts the following arguments:

- `-bevigil` - Search for Bevigil API keys  
- `-binaryedge` - Search for BinaryEdge API keys
- `-bufferover` - Search for Bufferover API keys
- ...

To search for a specific API key, pass the corresponding argument. Multiple arguments can be passed to search for multiple API keys.

A valid GitHub token must be provided in `TOKEN_DATA`. 

Example:

```bash
python scraper.py -shodan -virustotal
