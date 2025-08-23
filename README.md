<div align="center">
  <a><img width="320" height="320" alt="odoomap logo" src="https://github.com/user-attachments/assets/f55b8312-227e-4db8-82a6-300271758555" />
</a>
</div>

# OdooMap
![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)
![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.9-blue)
![Last Commit](https://img.shields.io/github/last-commit/MohamedKarrab/odoomap)
[![Twitter](https://img.shields.io/twitter/url/https/twitter.com/cloudposse.svg?style=social&label=%20%40_karrab)](https://x.com/_Karrab)
[![LinkedIn](https://img.shields.io/badge/-LinkedIn-black.svg?style=flat-square&logo=linkedin&colorB=555)](https://www.linkedin.com/in/mohamedkarrab/)


**OdooMap** is a reconnaissance, enumeration, and security testing tool for [Odoo](https://www.odoo.com/) applications.

## Features

- Detect Odoo version and metadata
- Enumerate databases and accessible models
- Authenticate and check CRUD permissions
- Extract data from specific models
- Brute-force login credentials & Master password
- Brute-force internal model names
- Extensible plugin system for security assessments

## Screenshots

<img width="967" height="492" alt="odoomap usage" src="https://github.com/user-attachments/assets/e95c3eee-a665-4690-a4dd-36f1c4d8dbe3" />

## Installation
> :information_source: It is advisable to use `pipx` over `pip` for system-wide installations.
```bash
git clone https://github.com/MohamedKarrab/odoomap.git && cd odoomap
pipx ensurepath && pipx install .

# Now restart your terminal and run
odoomap -h
```
*Or*
```bash
git clone https://github.com/MohamedKarrab/odoomap.git
cd odoomap
pip install -r requirements.txt
python odoomap.py -h
```

## Usage Examples

#### Basic Reconnaissance

```bash
odoomap -u https://example.com
```

#### Authenticate and Enumerate Models

```bash
odoomap -u https://example.com -D database_name -U admin -P pass -e -l 200 -o models.txt
```

#### Check Model Permissions (Read, Write, Create, Delete)

```bash
odoomap -u https://example.com -D database_name -U test@example.com -P pass -e -pe -l 10
```

#### Dump Data from Specific Models

```bash
odoomap -u https://example.com -D database_name -U admin -P pass -d res.users,res.partner -o ./output.txt
```

#### Dump Data from Model File

```bash
odoomap -u https://example.com -D database_name -U admin -P pass -d models.txt -o ./dump
```


## Brute-force Options

#### Brute-force Database Names
Case-sensitive, but db names are generally lowercase.
```bash
odoomap -u https://example.com -n -N db-names.txt
```

#### Default Credentials Attack

```bash
odoomap -u https://example.com -D database_name -b
```

#### Custom User & Pass Files

```bash
odoomap -u https://example.com -D database_name -b --usernames users.txt --passwords passes.txt
```

#### User\:Pass Combo List

```bash
odoomap -u https://example.com -D database_name -b -w wordlist.txt
```

#### Brute-force Master Password

```bash
odoomap -u https://example.com -M -p pass_list.txt
```

## Advanced Enumeration

#### Brute-force Model Names

```bash
odoomap -u https://example.com -D database_name -U admin -P pass -e -B --model-file models.txt
```

#### Recon + Enumeration + Dump

```bash
odoomap -u https://example.com -D database_name -U admin -P pass -r -e -pe -d res.users -o ./output
```

## Plugin System

#### List Available Plugins

```bash
odoomap --list-plugins
```

#### Run CVE Scanner Plugin

```bash
odoomap -u https://example.com --plugin cve-scanner
```

#### Run Plugin with Authentication

```bash
odoomap -u https://example.com -D database_name -U admin -P pass --plugin cve-scanner
```


## Full Usage

```
usage: odoomap [-h] [-u URL] [-D DATABASE] [-U USERNAME] [-P PASSWORD] [-r] [-e] [-pe] [-l LIMIT] [-o OUTPUT] [-d DUMP] [-B] [--model-file MODEL_FILE] [-b] [-w WORDLIST] [--usernames USERNAMES] [--passwords PASSWORDS] [-M] [-p MASTER_PASS] [-n] [-N DB_NAMES_FILE] [--plugin PLUGIN] [--list-plugins]

Odoo Security Assessment Tool

options:
  -h, --help            show this help message and exit
  -u, --url URL         Target Odoo server URL
  -D, --database DATABASE
                        Target database name
  -U, --username USERNAME
                        Username for authentication
  -P, --password PASSWORD
                        Password for authentication
  -r, --recon           Perform initial reconnaissance
  -e, --enumerate       Enumerate available model names
  -pe, --permissions    Enumerate model permissions (requires -e)
  -l, --limit LIMIT     Limit results for enumeration or dump operations
  -o, --output OUTPUT   Output file for results
  -d, --dump DUMP       Dump data from specified model(s); accepts a comma-separated list or a file path containing model names (one per line)   
  -B, --bruteforce-models
                        Bruteforce model names instead of listing them (default if listing fails)
  --model-file MODEL_FILE
                        File containing model names for bruteforcing (one per line)
  -b, --bruteforce      Bruteforce login credentials (requires -D)
  -w, --wordlist WORDLIST
                        Wordlist file for bruteforcing in user:pass format
  --usernames USERNAMES
                        File containing usernames for bruteforcing (one per line)
  --passwords PASSWORDS
                        File containing passwords for bruteforcing (one per line)
  -M, --bruteforce-master
                        Bruteforce the database's master password
  -p, --master-pass MASTER_PASS
                        Wordlist file for master password bruteforcing (one password per line)
  -n, --brute-db-names  Bruteforce database names
  -N, --db-names-file DB_NAMES_FILE
                        File containing database names for bruteforcing (case-sensitive)
  --plugin PLUGIN       Run a specific plugin by name (from odoomap/plugins/)
  --list-plugins        List all available plugins with metadata
                        
```

## Plugin Development

OdooMap features an extensible plugin system for custom security assessments. Plugins are located in `odoomap/plugins/` and follow a standardized interface.

### Built-in Plugins

- **CVE Scanner**: Searches for known CVEs affecting the detected Odoo version using the NVD database

### Creating Custom Plugins

1. Create a new Python file in `odoomap/plugins/`
2. Inherit from `BasePlugin` class
3. Implement required methods:
   - `get_metadata()`: Return plugin information
   - `run()`: Main plugin logic

## License

Apache License 2.0, see [LICENSE](https://github.com/MohamedKarrab/odoomap/blob/main/LICENSE)

## Notice
OdooMap is an independent project and is not affiliated with, endorsed by, or sponsored by Odoo S.A. or the official Odoo project in any way.

## Disclaimer

This tool is for lawful security and penetration testing with proper authorization. Unauthorized use is strictly prohibited. The author assumes no liability for any misuse or damage resulting from the use of this tool.

## Contributions

Feel free to open issues or submit pull requests for enhancements or bug fixes!
