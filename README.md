# Security Rules API

A portfolio project: an ASP.NET Core 11 Web API that packages the security
concerns a real backend has to get right into one small, testable service:
authentication with refresh-token rotation, policy-based authorization with
a rule engine, rate limiting, security headers, secrets handling, and an
append-only audit trail.

Built to demonstrate current .NET security practice. It is not production
software and has not been run against real users or data.

## What it does

The domain is a small access-control service. Users register and get a
department and a clearance level. Documents have a classification. Admins
define **access rules** ("Legal documents require the Admin role", "this
department needs Confidential clearance"). Every document read is decided by
a pure domain evaluator (ownership, then classification, then active rules),
and every decision, login, token refresh, and denied request lands in an
audit trail that only admins can read.

## Security features

- **Authentication**: ASP.NET Core Identity, JWT access tokens (15 min) with
  issuer/audience/lifetime validation, and single-use refresh tokens (7 days)
  with **rotation and reuse detection**: replaying a rotated token revokes
  the whole token family.
- **Authorization**: role policies (`Admin`, `Manager`, `Reviewer`) plus
  resource rules evaluated in the domain layer. Only refresh-token hashes
  (SHA-256) are stored, never the tokens.
- **Account lockout**: 5 failed logins lock the account for 15 minutes.
- **Rate limiting**: strict per-IP fixed window on the auth endpoints,
  sliding window per user on the rest of the API. Rejections return 429 with
  `Retry-After`.
- **Security headers**: CSP, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy`, HSTS in production, and the
  Kestrel `Server` header removed.
- **Secrets handling**: no secrets in the repo. Signing keys, API keys, and
  passwords come from user-secrets / environment variables / mounted secrets,
  validated at startup (`ValidateOnStart`) so a missing or weak key fails
  fast. Service API keys are stored as SHA-256 hashes and compared in
  constant time.
- **Audit trail**: append-only record of logins, lockouts, token refreshes
  and reuse detection, denied authorizations, document access decisions, and
  rule changes, each stamped with the request's correlation id.
- **Validation & errors**: FluentValidation on every input, problem-details
  responses, and a global exception handler that never leaks stack traces.
- **Service-to-service**: a separate API-key authentication scheme for
  machine callers (`GET /api/service/ping`).

## Stack

.NET 11 (LTS-wave current release, GA November 2026), ASP.NET Core,
EF Core 11 + SQL Server, ASP.NET Core Identity, JWT bearer, FluentValidation,
xUnit, WebApplicationFactory, Docker.

## Project layout

```
src/SecurityRules.Domain          Entities, clearance levels, the pure DocumentAccessEvaluator
src/SecurityRules.Application     Services, DTOs, validation, result types
src/SecurityRules.Infrastructure  Identity, EF Core, JWT/refresh tokens, API keys, audit writer
src/SecurityRules.Api             Controllers, middleware, rate limiting, Program.cs
tests/SecurityRules.UnitTests         Domain evaluator, token service, middleware, validators
tests/SecurityRules.IntegrationTests  Full HTTP pipeline against SQLite via WebApplicationFactory
```

## Running with Docker

```bash
export DB_SA_PASSWORD='YourStrong!Passw0rd'
export JWT_SIGNING_KEY='at-least-32-characters-long-signing-key'
docker compose up --build
```

The API listens on `http://localhost:8080` (`/health` for the health check).
Migrations and role seeding run automatically at startup. To seed a first
administrator, also set `ADMIN_EMAIL` and `ADMIN_PASSWORD`.

## Running locally

Requires the .NET 11 SDK and a SQL Server instance.

```bash
cd src/SecurityRules.Api
dotnet user-secrets set "Jwt:SigningKey" "at-least-32-characters-long-signing-key"
dotnet user-secrets set "AdminSeed:Email" "admin@example.com"
dotnet user-secrets set "AdminSeed:Password" "a strong password"
dotnet run
```

## Tests

```bash
dotnet test
```

40 tests: 20 unit tests (access evaluator rules, token issuing and hashing,
security headers and correlation middleware, validators) and 20 integration
tests through the real HTTP pipeline: register/login, lockout after five
failures, refresh rotation with family revocation on replay, role policies,
clearance- and rule-based document access, 429 rate limiting, API-key auth,
security headers, and the audit trail.

## API overview

| Method | Route | Access |
| --- | --- | --- |
| POST | `/api/auth/register` | anonymous, rate limited |
| POST | `/api/auth/login` | anonymous, rate limited |
| POST | `/api/auth/refresh` | refresh token (body or HttpOnly cookie) |
| POST | `/api/auth/logout` | refresh token |
| GET  | `/api/auth/me` | authenticated |
| GET  | `/api/rules` | authenticated |
| POST | `/api/rules` | Admin or Manager |
| PUT  | `/api/rules/{id}` | Admin or Manager |
| DELETE | `/api/rules/{id}` | Admin |
| POST | `/api/documents` | authenticated |
| GET  | `/api/documents/{id}` | owner, or clearance + rules pass |
| GET  | `/api/audit` | Admin |
| GET  | `/api/service/ping` | service API key |

## Notes and limits

This is a demonstration project. A few deliberate simplifications: the audit
trail has no retention job, there is no admin UI for managing users or
clearances (they are set through the database or the seed), and email
confirmation is not wired up. Known trade-offs are called out in code
comments where they live.
