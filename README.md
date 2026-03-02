# 🛡️ IOC Search Tool - Threat Intelligence CLI

A high-performance command-line interface (CLI) tool designed for security analysts to perform rapid Threat Intelligence lookups. It aggregates data from multiple providers to analyze IP addresses (IPV4 and IPV6), Domains, URLs, and File Hashes.

---

## 🇺🇸 English Version

###  Features
* **Multi-Provider Analysis**: Integration with VirusTotal, AbuseIPDB, AlienVault OTX, HybridAnalysis, GreyNoise, and Google Safe Browsing.
* **Network Insights**: Automatically identifies **ASN** and **ISP/Organization** for IP addresses.
* **Intelligent Caching**: Stores results for **48 hours** in a local SQLite database.
* **Clean UI**: Professional tables and color-coded threat levels (Clean, Info, Alert).

###  Installation & System Utility Setup
To use this tool from anywhere in your terminal as `ioc-search`, follow these steps:

1. **Clone and Install**:
   ```bash
   git clone [https://github.com/youruser/ioc-search.git](https://github.com/youruser/ioc-search.git)
   cd ioc-search
   pip install -r requirements.txt
   ```

2. **Set up Global Alias:**

Add the tool to your shell configuration (Bash or ZSH):

```
# Open your config file
nano ~/.bashrc  # or ~/.zshrc

# Add this line at the end (replace with your actual path)
alias ioc-search='python3 /home/felipe/ioc-search/cli.py'
```

3. **Reload Config:**
```
source ~/.bashrc  # or ~/.zshrc
```
4. **Usage:**

* Single Scan:
```
ioc-search scan -i 8.8.8.8
```
* File Scan: 
```
ioc-search scan -f targets.txt
```
* History: 
```
ioc-search scan history
```
* Export options:
```
ioc-search scan -i 8.8.8.8 -e json
```
```
ioc-search scan -i 8.8.8.8 -e csv
```
