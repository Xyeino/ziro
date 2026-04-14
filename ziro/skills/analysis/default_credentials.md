---
name: default_credentials
description: Database of default credentials by vendor/service/device for authentication testing before brute-force.
mitre_techniques: [T1078.001]
kill_chain_phases: [credential_access]
---

# Default Credentials Reference

Always try default credentials BEFORE brute-forcing. Most successful breaches start with unchanged defaults.

## Web Applications
| Service | Username | Password |
|---------|----------|----------|
| WordPress | admin | admin, password, wordpress |
| Joomla | admin | admin |
| Drupal | admin | admin |
| phpMyAdmin | root | (empty), root, mysql |
| Tomcat Manager | tomcat | tomcat, s3cret, admin |
| Tomcat Manager | admin | admin, tomcat |
| Jenkins | admin | admin, password |
| Grafana | admin | admin |
| Kibana | elastic | changeme |
| Portainer | admin | (set on first login) |
| pgAdmin | pgadmin4@pgadmin.org | admin |
| Webmin | root | (system password) |
| Zabbix | Admin | zabbix |
| Nagios | nagiosadmin | nagiosadmin |
| SonarQube | admin | admin |
| Gitlab | root | 5iveL!fe |
| Minio | minioadmin | minioadmin |

## Databases
| Service | Username | Password |
|---------|----------|----------|
| MySQL | root | (empty), root, mysql, password |
| PostgreSQL | postgres | postgres, password |
| MongoDB | (no auth) | (no auth by default) |
| Redis | (no auth) | (no auth by default) |
| Elasticsearch | elastic | changeme |
| CouchDB | admin | password |
| Cassandra | cassandra | cassandra |
| InfluxDB | admin | admin |
| MSSQL | sa | (empty), sa, Password1 |
| Oracle | system | oracle, manager |
| Oracle | sys | change_on_install |

## Network Devices
| Device | Username | Password |
|--------|----------|----------|
| Cisco IOS | admin | cisco, admin, password |
| Cisco IOS | cisco | cisco |
| Cisco Enable | (none) | cisco |
| Juniper | root | (none) |
| MikroTik | admin | (empty) |
| Ubiquiti | ubnt | ubnt |
| TP-Link | admin | admin |
| Netgear | admin | password |
| D-Link | admin | (empty), admin |
| Fortinet | admin | (empty) |
| Palo Alto | admin | admin |
| SonicWall | admin | password |
| pfSense | admin | pfsense |
| OpenWrt | root | (none) |

## IoT / Embedded
| Device | Username | Password |
|--------|----------|----------|
| Hikvision | admin | 12345 |
| Dahua | admin | admin |
| Axis camera | root | pass |
| Raspberry Pi | pi | raspberry |
| Default SSH | root | toor, root, password |

## Cloud / DevOps
| Service | Username | Password / Key |
|---------|----------|----------------|
| AWS | AKIAIOSFODNN7EXAMPLE | (check .env, .aws/credentials) |
| Docker Registry | (none) | (no auth by default) |
| Kubernetes | (none) | (check ~/.kube/config) |
| Consul | (none) | (no ACL by default) |
| Vault | (none) | (check VAULT_TOKEN) |
| RabbitMQ | guest | guest |
| ActiveMQ | admin | admin |

## SSH / Remote Access
| Service | Username | Password |
|---------|----------|----------|
| SSH | root | toor, root, password, 123456 |
| SSH | admin | admin, password |
| VNC | (none) | password, 1234 |
| RDP | administrator | (empty), password |
| Telnet | admin | admin, password |
| FTP | anonymous | (any email) |
| FTP | ftp | ftp |

## Testing workflow
1. Identify service/version from recon
2. Try defaults from this list FIRST
3. Try vendor-specific defaults (search web if not listed)
4. Try common patterns: admin:admin, admin:password, admin:company_name
5. Only THEN resort to hydra brute-force with wordlists
