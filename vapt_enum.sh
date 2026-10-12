#!/usr/bin/env bash

# Authorized VAPT service enumeration. Run only against explicitly authorized targets.

set -uo pipefail

usage() {
    cat <<'EOF'
Usage: vapt_enum.sh -i targets.txt [options]

Options:
  -i FILE   Input file with one IP address or hostname per line (required)
  -o DIR    Output directory (default: vapt_results_<timestamp>)
  -u        Also scan the top 200 UDP ports
  -w        Run Gobuster against detected HTTP(S) services when available
  -p PORTS  TCP ports/ranges for a faster scan (default: all ports)
  -t LEVEL  Nmap timing template, 0 through 5 (default: 4)
  -h        Show this help
EOF
}

INPUT=""
OUTDIR="vapt_results_$(date +%Y%m%d_%H%M%S)"
UDP_SCAN=0
WEB_SCAN=0
PORTS="-"
TIMING=4

while getopts ":i:o:uwp:t:h" option; do
    case "$option" in
        i) INPUT="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        u) UDP_SCAN=1 ;;
        w) WEB_SCAN=1 ;;
        p) PORTS="$OPTARG" ;;
        t) TIMING="$OPTARG" ;;
        h) usage; exit 0 ;;
        :) echo "[-] Option -$OPTARG requires an argument." >&2; usage >&2; exit 2 ;;
        \?) echo "[-] Unknown option: -$OPTARG" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$INPUT" || ! -f "$INPUT" ]]; then
    echo "[-] Provide an existing target file with -i." >&2
    usage >&2
    exit 2
fi

if [[ ! "$TIMING" =~ ^[0-5]$ ]]; then
    echo "[-] Timing template must be an integer from 0 to 5." >&2
    exit 2
fi

if [[ ! "$PORTS" =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ && "$PORTS" != "-" ]]; then
    echo "[-] Ports must be a comma-separated list of ports or ranges (for example: 80,443,8000-8100)." >&2
    exit 2
fi

if ! command -v nmap >/dev/null 2>&1; then
    echo "[-] Nmap is not installed." >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "[-] Python 3 is required to parse Nmap's XML service results." >&2
    exit 1
fi

OPTIONAL_TOOLS=(curl enum4linux onesixtyone snmpwalk nikto whatweb gobuster ssh-audit smbclient showmount dig)
MISSING_TOOLS=()
for tool in "${OPTIONAL_TOOLS[@]}"; do
    command -v "$tool" >/dev/null 2>&1 || MISSING_TOOLS+=("$tool")
done
if ((${#MISSING_TOOLS[@]})); then
    echo "[!] Optional tools unavailable (their checks will be skipped): ${MISSING_TOOLS[*]}"
fi

mkdir -p "$OUTDIR" || exit 1

if [[ "$EUID" -eq 0 ]]; then
    SCAN_TYPE="-sS"
else
    SCAN_TYPE="-sT"
fi

trim() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

valid_target() {
    local target="$1"
    [[ "$target" != -* && "$target" != */* && "$target" != *[[:space:]]* &&
        "$target" =~ ^[[:alnum:]_.:-]+$ ]]
}

run_logged() {
    "$@" 2>&1 | tee -a "$REPORT"
    local -a command_status=("${PIPESTATUS[@]}")
    return "${command_status[0]}"
}

run_nmap_scripts() {
    local port="$1"
    local scripts="$2"
    run_logged nmap -n -Pn "$SCAN_TYPE" -sV -p "$port" \
        --script "$scripts" --script-timeout 30s --max-retries 1 "$TARGET"
}

service_rows() {
    python3 - "$1" <<'PY'
import sys
import xml.etree.ElementTree as ET

try:
    root = ET.parse(sys.argv[1]).getroot()
except (ET.ParseError, OSError):
    raise SystemExit(0)

for host in root.findall("host"):
    for port in host.findall("./ports/port"):
        state = port.find("state")
        service = port.find("service")
        if state is None or state.get("state") != "open" or service is None:
            continue
        port_id = port.get("portid", "")
        name = service.get("name", "")
        details = " ".join(filter(None, (
            service.get("tunnel", ""), service.get("product", ""),
            service.get("version", ""), service.get("extrainfo", "")
        )))
        print(f"{port_id}\t{name}\t{details}")
PY
}

total=$(awk '{ sub(/#.*/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, ""); if (length) count++ } END { print count+0 }' "$INPUT")
count=0

echo "[+] Targets: $total"
echo "[+] Reports: $OUTDIR/"
if [[ "$PORTS" == "-" ]]; then
    echo "[+] TCP coverage: ports 1-65535"
else
    echo "[+] TCP ports: $PORTS"
fi
echo

while IFS= read -r TARGET || [[ -n "$TARGET" ]]; do
    TARGET="${TARGET%%#*}"
    TARGET="$(trim "$TARGET")"
    [[ -z "$TARGET" ]] && continue

    if ! valid_target "$TARGET"; then
        echo "[!] Skipping invalid target entry: $TARGET"
        continue
    fi

    count=$((count + 1))
    safe_name=$(printf '%s' "$TARGET" | tr -c '[:alnum:]._-' '_')
    host_dir="$OUTDIR/$safe_name"
    report="$OUTDIR/${safe_name}_results.txt"
    mkdir -p "$host_dir" || continue

    {
        echo "=================================================="
        echo "VAPT SERVICE ENUMERATION REPORT"
        echo "Target: $TARGET"
        echo "Date: $(date -Is)"
        echo "TCP ports: $([[ "$PORTS" == "-" ]] && printf '1-65535' || printf '%s' "$PORTS")"
        echo "=================================================="
        echo
        echo "[1] TCP SCAN AND SERVICE DETECTION"
        echo
    } > "$report"

    REPORT="$report"
    echo "[$count/$total] Scanning $TARGET ..."

    nmap -n -Pn "$SCAN_TYPE" -sV --version-all -p "$PORTS" \
        --open --reason -T"$TIMING" --max-retries 2 --script-timeout 30s \
        -sC -oA "$host_dir/nmap_full" "$TARGET" 2>&1 | tee -a "$REPORT"
    scan_status=("${PIPESTATUS[@]}")
    {
        echo
        echo "[TCP scan exit code: ${scan_status[0]}]"
        echo
    } >> "$REPORT"

    if [[ -s "$host_dir/nmap_full.xml" ]]; then
        echo "[2] SERVICE-SPECIFIC ENUMERATION (routed by detected service)" >> "$REPORT"
        while IFS=$'\t' read -r port service details; do
            [[ -z "$port" || -z "$service" ]] && continue
            fingerprint="${service,,} ${details,,}"
            echo "[+] $service on detected TCP port $port${details:+ ($details)}"
            printf '\n--- %s on TCP port %s ---\n' "$service" "$port" >> "$REPORT"

            case "$fingerprint" in
                *ftp*)
                    run_nmap_scripts "$port" "ftp-anon,ftp-syst,banner" || true
                    if command -v curl >/dev/null 2>&1; then
                        run_logged curl --max-time 10 --list-only "ftp://$TARGET:$port/" || true
                    fi
                    ;;
                *ssh*)
                    run_nmap_scripts "$port" "ssh-hostkey,ssh2-enum-algos,ssh-auth-methods" || true
                    if command -v ssh-audit >/dev/null 2>&1; then
                        run_logged ssh-audit -p "$port" "$TARGET" || true
                    fi
                    ;;
                *smtp*|*submission*)
                    run_nmap_scripts "$port" "smtp-commands,smtp-strangeport,banner" || true
                    ;;
                *pop3*)
                    run_nmap_scripts "$port" "pop3-capabilities,ssl-cert,banner" || true
                    ;;
                *imap*)
                    run_nmap_scripts "$port" "imap-capabilities,ssl-cert,banner" || true
                    ;;
                *http*|*https*)
                    run_nmap_scripts "$port" "http-title,http-headers,http-methods,http-server-header,ssl-cert" || true
                    scheme="http"
                    if [[ "$fingerprint" == *https* || "$fingerprint" == *ssl* || "$fingerprint" == *tls* ]]; then
                        scheme="https"
                    fi
                    url="$scheme://$TARGET:$port/"
                    if command -v whatweb >/dev/null 2>&1; then
                        run_logged whatweb --color=never "$url" || true
                    fi
                    if command -v nikto >/dev/null 2>&1; then
                        run_logged nikto -host "$url" -nointeractive || true
                    fi
                    if ((WEB_SCAN)); then
                        wordlist="/usr/share/wordlists/dirb/common.txt"
                        if command -v gobuster >/dev/null 2>&1 && [[ -r "$wordlist" ]]; then
                            run_logged gobuster dir -u "$url" -w "$wordlist" -q || true
                        else
                            echo "[!] Gobuster skipped: tool or $wordlist unavailable." | tee -a "$REPORT"
                        fi
                    fi
                    ;;
                *smb*|*microsoft-ds*|*netbios-ssn*)
                    run_nmap_scripts "$port" "smb-os-discovery,smb-protocols,smb-security-mode,smb-enum-shares,smb-vuln-ms17-010,smb-vuln-ms08-067" || true
                    if command -v enum4linux >/dev/null 2>&1; then
                        run_logged enum4linux -a -p "$port" "$TARGET" || true
                    fi
                    if command -v smbclient >/dev/null 2>&1; then
                        run_logged smbclient -p "$port" -N -L "//$TARGET" || true
                    fi
                    ;;
                *snmp*)
                    run_nmap_scripts "$port" "snmp-info,snmp-sysdescr" || true
                    if command -v onesixtyone >/dev/null 2>&1; then
                        run_logged onesixtyone "$TARGET" public || true
                    fi
                    if command -v snmpwalk >/dev/null 2>&1; then
                        run_logged snmpwalk -v2c -c public -t 2 -r 1 "$TARGET" || true
                    fi
                    ;;
                *ms-wbt-server*|*rdp*)
                    run_nmap_scripts "$port" "rdp-enum-encryption,rdp-ntlm-info" || true
                    ;;
                *telnet*)
                    run_nmap_scripts "$port" "banner,telnet-encryption" || true
                    ;;
                *mysql*)
                    run_nmap_scripts "$port" "mysql-info,mysql-variables" || true
                    ;;
                *ms-sql*|*mssql*)
                    run_nmap_scripts "$port" "ms-sql-info" || true
                    ;;
                *postgres*|*pgsql*)
                    run_nmap_scripts "$port" "pgsql-info" || true
                    ;;
                *nfs*|*rpcbind*)
                    run_nmap_scripts "$port" "nfs-showmount,rpcinfo" || true
                    if command -v showmount >/dev/null 2>&1; then
                        run_logged showmount -e "$TARGET" || true
                    fi
                    ;;
                *domain*)
                    run_nmap_scripts "$port" "dns-nsid,dns-service-discovery" || true
                    if command -v dig >/dev/null 2>&1; then
                        run_logged dig +time=2 +tries=1 -p "$port" @"$TARGET" version.bind chaos txt || true
                        if [[ "$TARGET" == *.* && "$TARGET" != *:* ]]; then
                            run_logged dig +time=2 +tries=1 -p "$port" @"$TARGET" "$TARGET" AXFR || true
                        fi
                    fi
                    ;;
                *msrpc*)
                    run_nmap_scripts "$port" "msrpc-enum,rpcinfo" || true
                    ;;
                *vnc*)
                    run_nmap_scripts "$port" "vnc-info" || true
                    ;;
                *ldap*)
                    run_nmap_scripts "$port" "ldap-rootdse" || true
                    ;;
                *)
                    run_nmap_scripts "$port" "banner" || true
                    ;;
            esac
        done < <(service_rows "$host_dir/nmap_full.xml")
    else
        echo "[!] Nmap XML output missing; service-specific checks were skipped." | tee -a "$REPORT"
    fi

    if ((UDP_SCAN)); then
        {
            echo
            echo "[3] UDP TOP-200 PORT SCAN"
            echo "Note: this does not cover every UDP port."
            echo
        } >> "$REPORT"
        nmap -n -Pn -sU -sV --top-ports 200 --open --reason \
            -T"$TIMING" --max-retries 1 -oA "$host_dir/nmap_udp" "$TARGET" 2>&1 | tee -a "$REPORT"
        udp_status=("${PIPESTATUS[@]}")
        echo "[UDP scan exit code: ${udp_status[0]}]" >> "$REPORT"
    fi

    echo "[+] Saved: $report"
    echo "[+] Raw scans: $host_dir/"
    echo
done < "$INPUT"

echo "=================================================="
echo "[+] Enumeration completed."
echo "[+] Individual reports: $OUTDIR/"
echo "=================================================="