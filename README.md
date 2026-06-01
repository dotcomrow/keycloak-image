# Keycloak with Dynamic IdP Membership Providers (Provable CI)

This repo builds a Keycloak image that **bakes in** custom Authenticator + Realm Resource SPIs for
dynamic role resolution from identity-provider membership.

CI proves providers load and can be attached to a flow via `kcadm.sh` **before pushing** the image.

## Quick start (locally)

```bash
# build the image locally (build-time args are required)
docker build \
  --build-arg KEYCLOAK_VERSION=26.5.1 \
  --build-arg KC_FEATURES=token-exchange-standard,token-exchange-external-internal \
  --build-arg KC_HTTP_RELATIVE_PATH=/ \
  --build-arg KC_TRANSACTION_XA_ENABLED=false \
  -t keycloak/github-team-admin:dev .

# run with a local Postgres
docker network create kc-net || true
docker run -d --rm --name kc-db --network kc-net   -e POSTGRES_USER=keycloak -e POSTGRES_PASSWORD=keycloak -e POSTGRES_DB=keycloak   -p 5432:5432 postgres:15

# wait for db then run keycloak
docker run -d --rm --name kc --network kc-net -p 8080:8080   -e KC_DB=postgres   -e KC_DB_URL=jdbc:postgresql://kc-db:5432/keycloak   -e KC_DB_USERNAME=keycloak   -e KC_DB_PASSWORD=keycloak   -e KC_DB_SCHEMA=public   keycloak/github-team-admin:dev

# health check
curl -fsS http://localhost:8080/health/ready
```

## GitHub Actions

- Builds the provider jar against the **same Keycloak version** as the runtime image.
- Boots **Postgres + the built Keycloak image**.
- Uses `kcadm.sh` to **verify** the provider appears and can be attached to a flow.
- **Only pushes** if proof passes and the event is not a PR.

### Tags produced (on `main`)

- `latest`
- `${KEYCLOAK_VERSION}` (e.g. `26.5.1`)
- `${KEYCLOAK_VERSION}-sha-${{ github.sha }}`
- `sha-${{ github.sha }}` (from metadata-action)
- `${{ inputs.image_version }}` if provided via **workflow_dispatch** input (e.g. `1.0.3`)

Set the repository variable **`IMAGE_REPO`** to your destination, e.g.:

- `ghcr.io/your-org/keycloak-github-admin`
- `docker.io/youruser/keycloak-github-admin`

For Docker Hub (or another registry), add secrets:

- `REGISTRY_USERNAME`
- `REGISTRY_PASSWORD`

## Provider IDs

- Authenticator: `github-team-admin`
- Authenticator: `google-groups-authenticator`
- Realm endpoint provider: `suncoast-memberships`

### GitHub Membership Resolver behavior

- Looks up user teams from GitHub (`org/team` keys from `/user/teams`).
- Derives role names directly from team slug (team segment after `org/`), e.g.
  - `dotcomrow/openwebui_access` -> `openwebui_access`
- Does **not** create/grant/revoke Keycloak role mappings.
- Optional env:
  - `GITHUB_MEMBERSHIP_ENABLED` (default `true`)
  - `GITHUB_API_VERSION` (optional, forwarded as `X-GitHub-Api-Version`)
  - `GITHUB_USER_AGENT` (optional, default `keycloak-github-membership-resolver/1.0`)

### Google Membership Resolver behavior

Fetches Cloud Identity / Google Workspace group membership at login using a
service account with domain-wide delegation.

### Required env

- `GOOGLE_ADMIN_EMAIL` (or `GOOGLE_DELEGATED_ADMIN`) — delegated admin to impersonate
- `GOOGLE_SA_JSON_PATH` or `GOOGLE_SA_JSON` — service account JSON

### Behavior

- Lists groups for the logged-in user via Directory API `groups.list?userKey=<email>`.
- Derives role names directly from group key, e.g. `openwebui_access@yourdomain.com` -> `openwebui_access`.
- Does **not** create/grant/revoke Keycloak role mappings.
- Optional env:
  - `GOOGLE_MEMBERSHIP_ENABLED` (default `true`)

### Admin SDK scopes

Ensure the service account is authorized for:
- `https://www.googleapis.com/auth/admin.directory.group.readonly`
- `https://www.googleapis.com/auth/admin.directory.group.member.readonly`

## Membership Endpoint

This image exposes:

- `GET /realms/{realm}/suncoast-memberships/me`

It returns:

- effective role list resolved from current IdP membership
- per-source diagnostics (`github`, `google`) with membership keys and derived roles

Authentication supports either:

- bearer token, or
- Keycloak identity cookie session
