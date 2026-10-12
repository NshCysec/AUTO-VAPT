# AUTO-VAPT

Authorized service enumeration for explicitly in-scope hosts. The script performs sequential Nmap scans and routes follow-up checks using the service names and fingerprints in Nmap's XML output, so services on nonstandard ports are handled too.

## Usage

```bash
./vapt_enum.sh -i ip_list.txt -o engagement_results -u -w
```

- `-i FILE`: required input, one IP address or hostname per line; blank lines and `#` comments are ignored.
- `-o DIR`: output directory. Defaults to `vapt_results_<timestamp>`.
- `-u`: also scan the top 200 UDP ports.
- `-w`: run Gobuster for detected HTTP(S) services when Gobuster and `/usr/share/wordlists/dirb/common.txt` are installed.
- `-p PORTS`: scan selected TCP ports or ranges, such as `80,443,8000-8100`. The default scans all TCP ports.
- `-t LEVEL`: Nmap timing template from 0 through 5; default is 4.

Each target gets a consolidated `<target>_results.txt` report and a target directory containing `nmap_full.nmap`, `nmap_full.gnmap`, and `nmap_full.xml`. When `-u` is used, corresponding `nmap_udp` evidence files are also written.

Nmap is required. Python 3 is used to parse Nmap XML. Optional tools are detected at startup and skipped when unavailable. Checks are sequential. The script does not run password guessing, SMTP user enumeration, relay tests, or exploit attempts. SMB checks include Nmap's MS17-010 and MS08-067 vulnerability-detection scripts. Optional `nikto`, `enum4linux`, and web-content checks can generate substantial traffic, so use them only when permitted by the engagement scope.

Run only against systems for which you have explicit authorization.
