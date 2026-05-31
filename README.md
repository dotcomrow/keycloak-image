# Keycloak with Custom GitHub Team Admin Authenticator (Provable CI)

This repo builds a Keycloak image that **bakes in** a custom Authenticator SPI (`github-team-admin`).
CI proves the provider loads and can be attached to a flow via `kcadm.sh` **before pushing** the image.

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

## Provider ID

The authenticator **id** is: `github-team-admin`

### GitHub Team Authenticator behavior

- Looks up user teams from GitHub (`org/team` keys from `/user/teams`).
- Grants a realm role derived from team name (team slug segment after `org/`), e.g.
  - `dotcomrow/openwebui_access` -> `openwebui_access`
- Optional env:
  - `GITHUB_AUTO_ROLES` (default `true`)
  - `GITHUB_ROLE_PREFIX` (default empty)
  - `GITHUB_STRICT_REVOKE` (default `true`)

## Google Groups Authenticator

Provider **id**: `google-groups-authenticator`

Fetches Cloud Identity / Google Workspace group membership at login using a
service account with domain-wide delegation. It supports external users by
checking membership against a configured list of groups.

### Required env

- `GOOGLE_ADMIN_EMAIL` (or `GOOGLE_DELEGATED_ADMIN`) — delegated admin to impersonate
- `GOOGLE_SA_JSON_PATH` or `GOOGLE_SA_JSON` — service account JSON

### Group selection and role derivation

- `GOOGLE_GROUPS` — CSV list of group emails to check
- `GOOGLE_AUTO_ROLES` — `true|false` (default `true`) to auto-create roles from group name
  - Example: `openwebui_access@yourdomain.com` -> `openwebui_access`
- `GOOGLE_ROLE_PREFIX` — optional prefix for auto roles (default empty)

### Behavior

- `GOOGLE_STRICT_REVOKE` — `true|false` (default `true`) revoke managed roles if no longer in group
- `GOOGLE_GROUPS_TTL_SECONDS` — cache TTL (default `600`)

### Admin SDK scopes

Ensure the service account is authorized for:
- `https://www.googleapis.com/auth/admin.directory.group.readonly`
- `https://www.googleapis.com/auth/admin.directory.group.member.readonly`
