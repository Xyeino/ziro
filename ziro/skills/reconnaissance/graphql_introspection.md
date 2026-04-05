---
name: graphql_introspection
description: Full GraphQL introspection queries and schema analysis techniques for API reconnaissance
---

# GraphQL Introspection Reconnaissance

Dedicated reconnaissance skill for GraphQL API discovery and schema mapping. Use alongside the main `graphql` protocol skill for exploitation.

## Full Introspection Query

Use this complete query to dump the entire GraphQL schema:

```graphql
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields {
        name
        description
        args {
          name
          description
          type {
            name
            kind
            ofType {
              name
              kind
              ofType {
                name
                kind
              }
            }
          }
          defaultValue
        }
        type {
          name
          kind
          ofType {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
      }
      inputFields {
        name
        type {
          name
          kind
          ofType { name kind }
        }
        defaultValue
      }
      interfaces { name }
      enumValues { name description }
      possibleTypes { name }
    }
    directives {
      name
      description
      locations
      args {
        name
        type { name kind ofType { name kind } }
        defaultValue
      }
    }
  }
}
```

## Curl One-Liner

```bash
curl -s -X POST TARGET_URL \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"query":"{__schema{queryType{name}mutationType{name}types{name kind description fields{name description args{name type{name kind ofType{name kind}}}type{name kind ofType{name kind}}}inputFields{name type{name kind ofType{name kind}}}enumValues{name}possibleTypes{name}}directives{name locations args{name type{name kind}}}}}"}'
```

## Schema Analysis Checklist

After dumping the schema, identify:

### High-Value Types
Look for types containing keywords:
- **Auth**: User, Account, Session, Token, Auth, Login, Role, Permission
- **Financial**: Payment, Order, Invoice, Balance, Transaction, Price, Cart, Billing
- **Data**: Profile, Document, File, Upload, Secret, Config, Setting
- **Admin**: Admin, Dashboard, Management, Internal, Debug

### Critical Mutations
Flag mutations that:
- Create/modify users or roles
- Handle payments or balance changes
- Modify permissions or access controls
- Upload files or modify configurations
- Delete or purge data

### Input Types
Examine input objects for:
- Fields that accept IDs (IDOR candidates)
- Boolean fields like `isAdmin`, `verified`, `premium`
- Nested input objects (mass assignment risk)
- Fields with no validation constraints

## Introspection Disabled? Alternatives

1. **Field suggestion mining**: Send typos to get suggestions
   ```graphql
   { __typena }  # May suggest __typename
   ```

2. **Error message harvesting**: Parse error messages for type/field names
   ```graphql
   { nonexistent { id } }  # "Did you mean 'user'?"
   ```

3. **Clairvoyance tool**: Automated schema recovery
   ```bash
   python3 clairvoyance.py -o schema.json -w wordlist.txt TARGET_URL
   ```

4. **Client-side JS analysis**: Search bundled JS for:
   ```bash
   grep -roh 'query [A-Z][a-zA-Z]*' bundle.js | sort -u
   grep -roh 'mutation [A-Z][a-zA-Z]*' bundle.js | sort -u
   ```

## Common Endpoints to Try

```
/graphql
/api/graphql
/api/graphql/query
/v1/graphql
/v2/graphql
/gql
/query
/graphql/console
/graphiql
/playground
/altair
/explorer
```

## Quick Validation

Minimal probe to confirm GraphQL endpoint:
```bash
curl -s -X POST TARGET_URL -H "Content-Type: application/json" -d '{"query":"{__typename}"}'
```

Expected response: `{"data":{"__typename":"Query"}}` or similar.
