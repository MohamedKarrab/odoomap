<div align="center">
  <a><img width="320" height="320" alt="odoomap logo-min" src="https://github.com/user-attachments/assets/f55b8312-227e-4db8-82a6-300271758555" />
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

## Screenshots

<img width="967" height="492" alt="image" src="https://github.com/user-attachments/assets/e95c3eee-a665-4690-a4dd-36f1c4d8dbe3" />

## Installation
> :information_source: It is advisable to use `pipx` over `pip` for system-wide installations.
```bash
pip install git+https://github.com/MohamedKarrab/odoomap
odoomap -h
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
odoomap -u https://example.com -D database_name -U test@example.com -P pass -e -p -l 10
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
odoomap -u https://example.com -D database_name -U admin -P pass -r -e -p -d res.users -o ./output
```


## Full Usage

```
usage: odoomap [-h] -u URL [-D DATABASE] [-U USERNAME] [-P PASSWORD] [-r] [-e] [-pe] [-l LIMIT] [-o OUTPUT] [-d DUMP] [-B]
               [--model-file MODEL_FILE] [-b] [-w WORDLIST] [--usernames USERNAMES] [--passwords PASSWORDS] [-M] [-p MASTER_PASS]

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
  -e, --enumerate       Enumerate model names
  -pe, --permissions    Enumerate model permissions (requires -e)
  -l, --limit LIMIT     Limit for enumeration or dump operations
  -o, --output OUTPUT   Output file/directory for results
  -d, --dump DUMP       Dump data from specified model(s). Can be comma-separated list or a file path containing model names (one per
                        line)
  -B, --bruteforce-models
                        Bruteforce models instead of listing them (Happens by default if listing fails)
  --model-file MODEL_FILE
                        File containing model names for bruteforcing (one per line)
  -b, --bruteforce      Bruteforce login (requires -D)
  -w, --wordlist WORDLIST
                        Wordlist file for bruteforce in user:pass format (optional)
  --usernames USERNAMES
                        File containing usernames for bruteforce (one per line)
  --passwords PASSWORDS
                        File containing passwords for bruteforce (one per line)
  -M, --bruteforce-master
                        Bruteforce the database's master password
  -p, --master-pass MASTER_PASS
                        Wordlist file for master password bruteforce (one password per line)

```

## License

Apache License 2.0, see [LICENSE](https://github.com/MohamedKarrab/odoomap/blob/main/LICENSE)

## Notice
OdooMap is an independent project and is not affiliated with, endorsed by, or sponsored by Odoo S.A. or the official Odoo project in any way.

## Disclaimer

This tool is for lawful security and penetration testing with proper authorization. Unauthorized use is strictly prohibited. The author assumes no liability for any misuse or damage resulting from the use of this tool.

## Contributions

Feel free to open issues or submit pull requests for enhancements or bug fixes!
