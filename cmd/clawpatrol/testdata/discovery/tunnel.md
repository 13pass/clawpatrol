# Claw Patrol access manifest — profile: tunneled

You are connected through the Claw Patrol gateway. It intercepts your
connections transparently: dial the hosts below as you normally would and
the gateway injects credentials and enforces policy. A credential
`placeholder` is a literal string you send where the secret would go — the
gateway swaps it for the real secret. This manifest is scoped to YOUR
device profile; it lists only what this profile grants.

TLS is intercepted only for the hosts this profile grants — the
endpoints listed below. For those, the gateway terminates TLS and acts
as a transparent man-in-the-middle: the certificate you see is minted on
the fly by Claw Patrol's own certificate authority, not the host's real
public certificate. The hostname matches but the issuer is the gateway
CA. You normally don't have to do anything to trust it: Claw Patrol
already installed its CA on this device when you joined — both in the
system trust store and via environment-variable pushdown
(SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE,
and similar) that `clawpatrol run` sets for the processes it wraps. So
most clients validate these connections out of the box, and a
certificate-authority mismatch against the public web PKI is expected
for these hosts, not an attack. If a client ignores both the system
store and those env vars, fetch the CA from
https://clawpatrol.internal/ca.crt, verify its fingerprint against
https://clawpatrol.internal/info, and point that
client at it explicitly.

Every other host is passed through untouched: the gateway does not
intercept it, you get the upstream's real certificate, and you must
still verify it against the public web PKI as usual.

## Human-in-the-loop approval

Some endpoints have rules that gate a matching request behind human approval (human-in-the-loop). When such a rule matches, the gateway PARKS the request pending a human decision instead of forwarding it upstream — and it may stay parked indefinitely while it waits for a person to approve or deny it. The gateway does NOT call upstream while a request is parked, so no side effect has happened yet. Do NOT treat a slow or hanging request to a gated endpoint as a failure or retry it blindly; the gateway is holding it on purpose.

The gateway parks the request synchronously: it holds your connection open until a human decides and then answers on that same connection — the real upstream response once the request is approved, or a denial if it is rejected. You do not have to do anything special or re-send anything; just let the request run instead of aborting it.

To see everything currently waiting on a human for your device, GET https://clawpatrol.internal/pending. It lists each parked action — its method, endpoint, and redacted target — so you can tell what is held without keeping the original connection in view.

None of this profile's endpoints currently gate requests behind human approval.

## Proposing a rule

When a rule would help (a request was blocked or held, or you want a guard), you can propose one instead of describing it: build a link and give it to your human. It opens the dashboard's rule dialog filled in; nothing changes until they check the preview and confirm.

- For an HTTPS or Kubernetes request the gateway refused, use the request link. The 403 carries the request ID in its X-Clawpatrol-Request header and on the last line of its body. Anyone who owns your profile can open it, member or admin; a member's rule may go to an admin for review.
- Otherwise use the endpoint link, with endpoint set to an endpoint name from this manifest. Only an admin of the dashboard can open it.

- verdict: deny, allow (pre-approve) or approve (hold for a human).
- condition: a CEL expression on the request, e.g. `http.method == 'DELETE'`. HTTP endpoints have http.method, http.path, http.query, http.headers, http.body_json; Kubernetes ones add k8s.verb, k8s.resource, k8s.namespace, k8s.name, k8s.params; SQL ones have sql.verb, sql.tables, sql.function, sql.statement. Omitted, the request link matches requests like that one (same method and path, or same Kubernetes object; a host with no endpoint as a whole), the endpoint link every request to the endpoint. Keep it as narrow as the need.
- note: one sentence on why, shown to your human.
- Optional, endpoint link only: approver=<human approver> for verdict approve, profile=<profile> to limit the rule to one profile.

URL-encode every value (encodeURIComponent).

Request link: `https://gw.example.test/#/request/<request id>?verdict=<deny|allow|approve>&condition=<CEL>&note=<why>`

Endpoint link: `https://gw.example.test/#/rules/new?endpoint=<endpoint>&verdict=<deny|allow|approve>&condition=<CEL>&note=<why>`

## Endpoints (5)

### github  (https)

- Host(s): api.github.com
- Credential: bearer_token `gh` — send placeholder `PH_GH`
- Example: `curl https://api.github.com/ -H "Authorization: Bearer PH_GH"`

### k8s-pg  (postgres)

- Host(s): k8s-pg.example
- Port: 5432
- SSL mode: require
- Credential: postgres_credential `k8s-rw` — connect with database=prod user=app
- Example: `psql "host=k8s-pg.example port=5432 user=app dbname=prod sslmode=require"`

### metrics  (clickhouse_native)

- Host(s): ch.example
- Port: 9440
- Credential: clickhouse_credential `ch-ro` — connect with user=ro
- Example: `clickhouse-client --host ch.example --port 9440 --user ro`

### prod-pg  (postgres)

- Host(s): main-pg.example
- Port: 5432
- SSL mode: require
- Credential: postgres_credential `pg-rw` — connect with database=prod user=app
- Example: `psql "host=main-pg.example port=5432 user=app dbname=prod sslmode=require"`

### rds-pg  (postgres)

- Host(s): rds.example
- Port: 5432
- SSL mode: require
- Credential: postgres_credential `rds-rw` — connect with database=prod user=app
- Example: `psql "host=rds.example port=5432 user=app dbname=prod sslmode=require"`

## Environment variables (0)

_None pushed for this profile._

