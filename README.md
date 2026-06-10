# Kiro: Phishing Detection CLI Tool

A fast, single-file Python CLI tool that analyzes URLs to determine if they are legitimate or potential phishing attempts.

## Features

- **Interactive CLI Loop**: Persistent session that waits for user input without requiring complex terminal commands
- **Smart URL Parsing**: Automatically handles missing `http://` protocols and normalizes input
- **Pre-Scan Whitelist**: Bypasses scans for known safe domains (google.com, facebook.com, etc.)
- **Comprehensive Threat Scanning**:
  - IP address detection (suspicious use of IPs instead of domain names)
  - URL shortener detection (identifies known phishing-prone shorteners)
  - Homograph/Typosquatting detection (flags domains impersonating legitimate brands)
- **Plain-English Reasoning**: Color-coded output with numbered explanations for all findings

## Installation

### Prerequisites
- Python 3.7+

### Setup

1. Clone or download the Kiro project directory
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run Kiro with:
```bash
python kiro.py
```

You'll see the Kiro banner and an interactive prompt:
```
╔═══════════════════════════════════╗
║           KIRO v1.0               ║
║    Phishing Detection Tool        ║
╚═══════════════════════════════════╝

kiro [User] >>
```

### Examples

**Checking a legitimate URL:**
```
kiro [User] >> https://google.com
[SAFE] https://google.com
────────────────────────────────────
  1. Domain is on the trusted whitelist.
────────────────────────────────────
```

**Checking a suspicious URL:**
```
kiro [User] >> http://g00gle-account-verify.com
[SUSPICIOUS] http://g00gle-account-verify.com
────────────────────────────────────
  1. Domain resembles a legitimate brand (possible homograph/typosquatting attack).
────────────────────────────────────
```

**Checking a URL with shortener:**
```
kiro [User] >> https://bit.ly/abc123
[SUSPICIOUS] https://bit.ly/abc123
────────────────────────────────────
  1. URL uses a known shortener service (potential phishing tactic).
────────────────────────────────────
```

### Commands

- **Enter a URL**: Paste or type any URL to scan it
- **exit / quit / q**: Exit the tool
- **Ctrl+C**: Force exit

## Architecture

### How It Works

1. **URL Cleaning**: Normalizes input by adding `http://` if missing
2. **Whitelist Check**: Immediately returns "SAFE" for known trusted domains (fixes Error 1: false positives)
3. **Threat Scanning** (if not whitelisted):
   - Detects IP addresses used instead of domain names
   - Identifies suspicious URL shorteners
   - Flags homograph/typosquatting attacks
4. **Verdict & Reasoning**: Outputs color-coded result with numbered explanations

### Error Prevention

**Error 1: Homograph False Positives**
- **Problem**: The scanner flagged legitimate domains containing target keywords as homograph attacks
- **Solution**: Pre-scan whitelist bypasses evaluation for known safe domains

**Error 2: CLI Input Friction**
- **Problem**: Script crashed if user forgot the `--url` argument
- **Solution**: Interactive CLI loop catches empty input and prompts again without crashing

## File Structure

```
kiro/
├── kiro.py              # Main script (all logic in one file)
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

## Configuration

### Whitelist

Add trusted domains to the `WHITELIST` set in `kiro.py`:
```python
WHITELIST = {
    "google.com",
    "facebook.com",
    # Add more domains here
}
```

### Suspicious Shorteners

Modify the `SUSPICIOUS_SHORTENERS` set to track known phishing shorteners:
```python
SUSPICIOUS_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    # Add more shorteners here
}
```

### Brand Keywords

Adjust `BRAND_KEYWORDS` for typosquatting detection:
```python
BRAND_KEYWORDS = {
    "google",
    "facebook",
    # Add more brands here
}
```

## Output Colors

- **Green [SAFE]**: No phishing indicators detected
- **Red [SUSPICIOUS]**: One or more threats detected
- **Yellow [UNKNOWN]**: Unable to process URL

## Requirements

- `requests`: Used for URL validation and connectivity checks

## Troubleshooting

**Q: The tool crashes when I paste a URL**
A: Make sure you've installed dependencies with `pip install -r requirements.txt`

**Q: Empty input causes an error**
A: Just press Enter again at the prompt—the tool is designed to handle empty input gracefully.

**Q: I want to add more trusted domains**
A: Edit the `WHITELIST` set in `kiro.py` to include additional domains.

## Future Enhancements

- SSL/TLS certificate validation
- Domain registration age detection
- WHOIS lookup integration
- Redirect chain analysis
- Machine learning-based threat scoring

## License

Open source. Use and modify as needed.

## Support

For issues or improvements, review the PRD in `Kiro_Hardened_PRD.txt`.
