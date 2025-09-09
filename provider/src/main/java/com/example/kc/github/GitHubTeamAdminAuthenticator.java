package com.example.kc.github;

import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * GitHub team → admin grants for Keycloak.
 *
 * Primary behavior:
 *  - If user is in GITHUB_ORG/GITHUB_TEAM (or allow-listed or DEBUG_ALWAYS_GRANT=true),
 *    grant *all roles in the realm* (realm + every client role).
 *  - Optional extra team→role mappings via GITHUB_ROLE_MAP (JSON).
 *  - Optional excludes via GITHUB_ADMIN_EXCLUDE.
 *  - Optional revocation (GITHUB_STRICT_REVOKE=true) removes previously granted roles
 *    when user is not in the admin team.
 *
 * Env:
 *   GITHUB_ORG / GITHUB_TEAM
 *   DEBUG_ALWAYS_GRANT=true|false
 *   GITHUB_ADMIN_USERNAMES="a,b,c"
 *   GITHUB_STRICT_REVOKE=true|false (default true)
 *   GITHUB_ROLE_MAP='{"org/team":["realm:ROLE","client:CID:ROLE"]}'
 *   GITHUB_ADMIN_EXCLUDE="realm:R1,client:CID:R2,R3"
 *
 * GitHub IdP tips:
 *   - Set storeToken=true
 *   - Include "read:org" in default scopes
 *   - If your org enforces SAML/SSO, authorize your OAuth app/token for the org
 */
public class GitHubTeamAdminAuthenticator implements Authenticator {
    private static final Logger LOG = Logger.getLogger(GitHubTeamAdminAuthenticator.class);

    // ---------- config ----------
    private static String getenv(String k, String def) { String v = System.getenv(k); return v != null ? v : def; }
    private static boolean isTrue(String k, boolean def) {
        String v = getenv(k, def ? "true" : "false");
        return "true".equalsIgnoreCase(v) || "1".equals(v);
    }
    private static String adminOrg()  { return getenv("GITHUB_ORG", getenv("GITHUB_ADMIN_ORG", "")).trim(); }
    private static String adminTeam() { return getenv("GITHUB_TEAM", getenv("GITHUB_ADMIN_TEAM", "")).trim(); }
    private static boolean debugAlwaysGrant() { return isTrue("DEBUG_ALWAYS_GRANT", false); }
    private static boolean strictRevoke()     { return isTrue("GITHUB_STRICT_REVOKE", true); }
    private static String roleMapJson()       { return getenv("GITHUB_ROLE_MAP", "").trim(); }
    private static String excludeCsv()        { return getenv("GITHUB_ADMIN_EXCLUDE", "").trim(); }
    private static Set<String> adminUsernames() {
        String csv = getenv("GITHUB_ADMIN_USERNAMES", "").trim();
        if (csv.isEmpty()) return Collections.emptySet();
        Set<String> s = new HashSet<>();
        for (String part : csv.split(",")) {
            String p = part.trim().toLowerCase(Locale.ROOT);
            if (!p.isEmpty()) s.add(p);
        }
        return s;
    }

    // ---------- main ----------
    @Override
    public void authenticate(AuthenticationFlowContext ctx) {
        try {
            final KeycloakSession session = ctx.getSession();
            final RealmModel realm = ctx.getRealm();
            final UserModel user = ctx.getUser();

            final String org = adminOrg();
            final String team = adminTeam();
            final boolean flagAlways = debugAlwaysGrant();
            final boolean flagRevoke = strictRevoke();
            final Set<String> allowUsers = adminUsernames();

            LOG.infof("GitHubTeamAdminAuthenticator: start user=%s realm=%s org=%s team=%s DEBUG_ALWAYS_GRANT=%s STRICT_REVOKE=%s allowUsers=%s",
                    user.getUsername(), realm.getName(), safe(org), safe(team), flagAlways, flagRevoke, allowUsers);

            boolean adminMember = flagAlways
                    || allowUsers.contains(user.getUsername().toLowerCase(Locale.ROOT))
                    || isMemberOf(session, realm, user, org, team);

            LOG.infof("Admin membership decision for user=%s → %s", user.getUsername(), adminMember ? "GRANT" : "NO-GRANT");

            // Build target role set
            Set<RoleModel> target = new LinkedHashSet<>();
            if (adminMember) {
                Set<RoleModel> all = allRolesInRealm(realm);
                target.addAll(all);
                LOG.infof("Admin grant: collected %d total roles (realm + client).", all.size());
            }

            // Optional extra maps
            Map<String, List<RoleSpec>> map = parseRoleMap(roleMapJson());
            if (!map.isEmpty()) {
                Set<String> myTeams = fetchTeams(session, realm, user); // "org/team"
                LOG.infof("Extra role map: user teams=%s", myTeams);
                for (String key : myTeams) {
                    List<RoleSpec> wants = map.get(key);
                    if (wants == null) continue;
                    for (RoleSpec spec : wants) {
                        RoleModel r = resolve(realm, spec);
                        if (r != null) {
                            target.add(r);
                            LOG.debugf("Added mapped role %s due to team %s", pretty(r), key);
                        } else {
                            LOG.warnf("Mapped role not found for spec=%s team=%s", specString(spec), key);
                        }
                    }
                }
            }

            // Optional excludes
            Set<RoleSpec> excludes = parseExcludes(excludeCsv());
            if (!excludes.isEmpty()) {
                int before = target.size();
                target.removeIf(r -> excludeMatch(r, excludes));
                LOG.infof("Excludes applied: removed %d role(s) from target", (before - target.size()));
            }

            // Grant
            if (!target.isEmpty()) {
                grantIfMissing(user, target);
            } else {
                LOG.infof("No target roles to grant for user=%s", user.getUsername());
            }

            // Revoke (only when NOT admin)
            if (!adminMember && flagRevoke) {
                Set<RoleModel> grantable = new LinkedHashSet<>(allRolesInRealm(realm));
                for (List<RoleSpec> specs : map.values()) {
                    for (RoleSpec s : specs) {
                        RoleModel r = resolve(realm, s);
                        if (r != null) grantable.add(r);
                    }
                }
                if (!excludes.isEmpty()) grantable.removeIf(r -> excludeMatch(r, excludes));
                LOG.infof("Revocation pass: considering %d role(s).", grantable.size());
                revokeIfPresent(user, grantable);
            }

            ctx.success();
            LOG.infof("GitHubTeamAdminAuthenticator: success user=%s", user.getUsername());
        } catch (Exception e) {
            LOG.error("GitHubTeamAdminAuthenticator: exception — allowing login (non-blocking).", e);
            ctx.success();
        }
    }

    // ---------- membership ----------
    private boolean isMemberOf(KeycloakSession session, RealmModel realm, UserModel user, String org, String team) {
        if (org.isBlank() || team.isBlank()) {
            LOG.warn("GITHUB_ORG or GITHUB_TEAM is blank; cannot determine membership.");
            return false;
        }
        if (debugAlwaysGrant()) return true;

        String token = extractGithubAccessToken(session, realm, user);
        if (token == null || token.isBlank()) {
            LOG.warn("No usable GitHub access token; ensure storeToken=true and scope includes read:org.");
            return false;
        }

        // 1) /user/teams
        try {
            var resp = SimpleHttp
                    .doGet("https://api.github.com/user/teams", session)
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", "application/vnd.github+json")
                    .param("per_page", "100")
                    .asResponse();

            int sc = resp.getStatus();
            String body = resp.asString();
            LOG.infof("GitHub /user/teams -> status=%d body=%s", sc, truncate(body, 500));

            JsonNode node = parseJsonQuiet(body);
            if (sc / 100 == 2 && node != null && node.isArray()) {
                for (var it = node.elements(); it.hasNext();) {
                    JsonNode t = it.next();
                    String slug = t.path("slug").asText("");
                    String orgLogin = t.path("organization").path("login").asText("");
                    LOG.debugf("Team seen: %s/%s", orgLogin, slug);
                    if (team.equalsIgnoreCase(slug) && org.equalsIgnoreCase(orgLogin)) {
                        LOG.infof("Matched admin team via /user/teams: %s/%s", org, team);
                        return true;
                    }
                }
            } else {
                LOG.warnf("GitHub /user/teams returned non-array or error; will try membership fallback.");
            }
        } catch (Exception e) {
            LOG.warn("GitHub /user/teams threw; will try membership fallback.", e);
        }

        // 2) explicit membership fallback
        try {
            String url = String.format("https://api.github.com/orgs/%s/teams/%s/memberships/%s",
                    org, team, user.getUsername());
            var resp = SimpleHttp.doGet(url, session)
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", "application/vnd.github+json")
                    .asResponse();

            int sc = resp.getStatus();
            String body = resp.asString();
            LOG.infof("GitHub team membership -> status=%d body=%s", sc, truncate(body, 500));

            if (sc == 200) {
                JsonNode node = parseJsonQuiet(body);
                String state = node != null ? node.path("state").asText("") : "";
                LOG.infof("Membership state for %s/%s user=%s -> %s", org, team, user.getUsername(), state);
                return "active".equalsIgnoreCase(state);
            } else if (sc == 404) {
                LOG.info("Membership endpoint says not found (not a member).");
                return false;
            }
        } catch (Exception e) {
            LOG.warn("GitHub membership fallback threw.", e);
        }
        return false;
    }

    /**
     * Extract a usable GitHub access token from the federated identity record.
     * Some brokers store a raw token string; others store a JSON blob containing "access_token".
     */
    private String extractGithubAccessToken(KeycloakSession session, RealmModel realm, UserModel user) {
        try {
            FederatedIdentityModel fi = session.users().getFederatedIdentity(realm, user, "github");
            if (fi == null) {
                LOG.infof("No federated identity record for provider=github (user=%s)", user.getUsername());
                return null;
            }
            String raw = fi.getToken();
            String desc = (raw == null) ? "null" : (raw.startsWith("{") ? "JSON" : (raw.contains(".") ? "JWT-ish" : "opaque"));
            LOG.infof("Federated token shape for user=%s: %s (len=%d)", user.getUsername(), desc, raw == null ? 0 : raw.length());

            if (raw == null || raw.isBlank()) return null;

            if (raw.startsWith("{")) {
                // Likely a full token response; extract access_token
                JsonNode n = parseJsonQuiet(raw);
                String at = (n != null) ? n.path("access_token").asText(null) : null;
                if (at != null && !at.isBlank()) {
                    LOG.info("Extracted access_token from JSON federated token.");
                    return at;
                } else {
                    LOG.warn("Federated JSON token had no access_token; falling back to raw.");
                    return raw;
                }
            }
            // Otherwise assume it's an opaque bearer token already
            return raw;
        } catch (Exception e) {
            LOG.warn("Error extracting GitHub access token.", e);
            return null;
        }
    }

    private Set<String> fetchTeams(KeycloakSession session, RealmModel realm, UserModel user) {
        Set<String> out = new HashSet<>();
        String token = extractGithubAccessToken(session, realm, user);
        if (token == null || token.isBlank()) return out;
        try {
            var resp = SimpleHttp
                    .doGet("https://api.github.com/user/teams", session)
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", "application/vnd.github+json")
                    .param("per_page", "100")
                    .asResponse();

            int sc = resp.getStatus();
            String body = resp.asString();
            LOG.infof("GitHub /user/teams (for map) -> status=%d body=%s", sc, truncate(body, 400));

            JsonNode node = parseJsonQuiet(body);
            if (sc / 100 == 2 && node != null && node.isArray()) {
                for (var it = node.elements(); it.hasNext();) {
                    JsonNode t = it.next();
                    String slug = t.path("slug").asText("");
                    String orgLogin = t.path("organization").path("login").asText("");
                    if (!slug.isBlank() && !orgLogin.isBlank()) {
                        out.add((orgLogin + "/" + slug).toLowerCase(Locale.ROOT));
                    }
                }
            }
            LOG.infof("Parsed %d team(s) for user=%s", out.size(), user.getUsername());
        } catch (Exception ex) {
            LOG.warn("GitHub teams fetch failed.", ex);
        }
        return out;
    }

    // ---------- roles ----------
    private Set<RoleModel> allRolesInRealm(RealmModel realm) {
        Set<RoleModel> all = new LinkedHashSet<>();
        realm.getRolesStream().forEach(all::add);
        List<ClientModel> clients = realm.getClientsStream().collect(Collectors.toList());
        int clientCount = 0, clientRoleCount = 0;
        for (ClientModel c : clients) {
            clientCount++;
            long before = all.size();
            c.getRolesStream().forEach(all::add);
            clientRoleCount += (all.size() - before);
        }
        LOG.infof("Role inventory for realm=%s → realmRoles=%d clients=%d clientRoles=%d total=%d",
                realm.getName(), realm.getRolesStream().count(), clientCount, clientRoleCount, all.size());
        return all;
    }

    private void grantIfMissing(UserModel user, Collection<RoleModel> roles) {
        int granted = 0;
        for (RoleModel r : roles) {
            if (!user.hasRole(r)) {
                user.grantRole(r);
                granted++;
                LOG.infof("Granted %s to %s", pretty(r), user.getUsername());
            }
        }
        if (granted == 0) {
            LOG.infof("No new roles to grant for %s.", user.getUsername());
        } else {
            LOG.infof("Total newly granted roles to %s: %d", user.getUsername(), granted);
        }
    }

    private void revokeIfPresent(UserModel user, Collection<RoleModel> roles) {
        int revoked = 0;
        for (RoleModel r : roles) {
            if (user.hasRole(r)) {
                user.deleteRoleMapping(r);
                revoked++;
                LOG.infof("Revoked %s from %s", pretty(r), user.getUsername());
            }
        }
        if (revoked > 0) {
            LOG.infof("Total roles revoked from %s: %d", user.getUsername(), revoked);
        } else {
            LOG.infof("No roles to revoke from %s", user.getUsername());
        }
    }

    private String pretty(RoleModel r) {
        if (r.isClientRole()) {
            RoleContainerModel cont = r.getContainer();
            String clientId = (cont instanceof ClientModel) ? ((ClientModel) cont).getClientId() : r.getContainerId();
            return "client:" + clientId + ":" + r.getName();
        } else {
            return "realm:" + r.getName();
        }
    }

    // ---------- mapping/excludes ----------
    private static final class RoleSpec {
        final boolean realm; final String clientId; final String role;
        RoleSpec(boolean realm, String clientId, String role) { this.realm = realm; this.clientId = clientId; this.role = role; }
        static RoleSpec realm(String role) { return new RoleSpec(true, null, role); }
        static RoleSpec client(String clientId, String role) { return new RoleSpec(false, clientId, role); }
    }
    private static String specString(RoleSpec s) { return s == null ? "null" : (s.realm ? "realm:" + s.role : "client:" + s.clientId + ":" + s.role); }

    private static RoleSpec parseRoleSpec(String spec) {
        if (spec == null || spec.isBlank()) return null;
        String[] parts = spec.split(":", 3);
        if (parts.length >= 2 && "realm".equalsIgnoreCase(parts[0])) return RoleSpec.realm(parts[1]);
        if (parts.length == 3 && "client".equalsIgnoreCase(parts[0])) return RoleSpec.client(parts[1], parts[2]);
        if (parts.length == 1) return RoleSpec.realm(parts[0]); // bare -> realm
        return null;
    }

    private Map<String, List<RoleSpec>> parseRoleMap(String json) {
        Map<String, List<RoleSpec>> out = new HashMap<>();
        if (json == null || json.isBlank()) return out;
        try {
            JsonNode root = org.keycloak.util.JsonSerialization.mapper.readTree(json);
            if (!root.isObject()) return out;
            Iterator<String> it = root.fieldNames();
            while (it.hasNext()) {
                String key = it.next(); // "org/team"
                JsonNode arr = root.get(key);
                if (arr == null || !arr.isArray()) continue;
                List<RoleSpec> specs = new ArrayList<>();
                for (JsonNode n : arr) {
                    RoleSpec s = parseRoleSpec(n.asText(""));
                    if (s != null) specs.add(s);
                }
                if (!specs.isEmpty()) out.put(key.toLowerCase(Locale.ROOT), specs);
            }
            LOG.infof("Parsed GITHUB_ROLE_MAP for %d team key(s).", out.size());
        } catch (Exception e) {
            LOG.warn("Failed to parse GITHUB_ROLE_MAP; ignoring.", e);
        }
        return out;
    }

    private Set<RoleSpec> parseExcludes(String csv) {
        Set<RoleSpec> out = new HashSet<>();
        if (csv == null || csv.isBlank()) return out;
        for (String raw : csv.split(",")) {
            RoleSpec s = parseRoleSpec(raw.trim());
            if (s != null) out.add(s);
        }
        LOG.infof("Parsed %d exclude spec(s) from GITHUB_ADMIN_EXCLUDE.", out.size());
        return out;
    }

    private boolean excludeMatch(RoleModel role, Set<RoleSpec> excludes) {
        for (RoleSpec s : excludes) {
            if (s.realm && !role.isClientRole() && role.getName().equals(s.role)) return true;
            if (!s.realm && role.isClientRole()) {
                String cid = (role.getContainer() instanceof ClientModel)
                        ? ((ClientModel) role.getContainer()).getClientId()
                        : role.getContainerId();
                if (cid.equals(s.clientId) && role.getName().equals(s.role)) return true;
            }
        }
        return false;
    }

    private RoleModel resolve(RealmModel realm, RoleSpec spec) {
        if (spec == null) return null;
        if (spec.realm) return realm.getRole(spec.role);
        ClientModel c = realm.getClientByClientId(spec.clientId);
        return (c != null) ? c.getRole(spec.role) : null;
    }

    // ---------- utils ----------
    private static String safe(String s) { return (s == null || s.isBlank()) ? "(blank)" : s; }
    private static String truncate(String s, int max) { if (s == null) return ""; return s.length() <= max ? s : s.substring(0, max) + "…"; }
    private static JsonNode parseJsonQuiet(String body) { try { return org.keycloak.util.JsonSerialization.mapper.readTree(body); } catch (Exception e) { return null; } }

    // ---------- Authenticator plumbing ----------
    @Override public void action(AuthenticationFlowContext ctx) { }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) { }
    @Override public void close() { }
}
