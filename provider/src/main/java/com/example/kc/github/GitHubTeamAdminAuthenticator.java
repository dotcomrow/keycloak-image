package com.example.kc.github;

import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.*;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

/**
 * GitHub team → admin grants for Keycloak (Keycloak 24.x).
 *
 * Behavior:
 *  - If user is in GITHUB_ORG/GITHUB_TEAM (or allow-listed, or DEBUG_ALWAYS_GRANT=true),
 *    grant *all roles in the realm* (realm + all client roles).
 *  - Optional extra team→role mappings via GITHUB_ROLE_MAP (JSON).
 *  - Optional excludes via GITHUB_ADMIN_EXCLUDE.
 *  - Optional revocation (GITHUB_STRICT_REVOKE=true) removes previously granted roles
 *    when user is not in the admin team; skipped for this login if the GitHub token is invalid.
 *
 * Env:
 *   GITHUB_ORG / GITHUB_TEAM
 *   DEBUG_ALWAYS_GRANT=true|false
 *   GITHUB_ADMIN_USERNAMES="a,b,c"         (optional allow-list, case-insensitive)
 *   GITHUB_STRICT_REVOKE=true|false        (default true)
 *   GITHUB_ROLE_MAP='{"org/team":["realm:ROLE","client:CID:ROLE"]}'
 *   GITHUB_ADMIN_EXCLUDE="realm:R1,client:CID:R2,R3"
 *   GITHUB_API_VERSION="2022-11-28"        (optional; X-GitHub-Api-Version)
 *   GITHUB_USER_AGENT="my-app/1.0"         (optional; User-Agent)
 *
 * GitHub IdP tips:
 *  - Identity provider → “Store tokens” = ON
 *  - Default Scopes should include: read:org user:email
 *  - If your org enforces SSO for OAuth apps, authorize your app for the org
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
    private static String apiVersion()        { return getenv("GITHUB_API_VERSION", "").trim(); }
    private static String userAgent()         { return getenv("GITHUB_USER_AGENT", "keycloak-github-admin/1.0"); }

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

            final String ghLogin = githubLogin(session, realm, user);
            LOG.infof("Derived GitHub login for user=%s -> '%s'", user.getUsername(), ghLogin);

            boolean adminMember = flagAlways
                    || allowUsers.contains(user.getUsername().toLowerCase(Locale.ROOT))
                    || isMemberOf(session, realm, user, ghLogin, org, team);

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
                Set<String> myTeams = fetchTeams(session, realm, user);
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

            // Revoke (only when NOT admin) — but skip if token invalid this turn
            boolean tokenInvalidThisTurn = "true".equals(
                    session.getContext().getAuthenticationSession().getAuthNote("GITHUB_TOKEN_INVALID"));

            if (!adminMember && flagRevoke && !tokenInvalidThisTurn) {
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
            } else if (tokenInvalidThisTurn) {
                LOG.warn("Skipping revocation because GitHub token was INVALID (401) in this login.");
            }

            ctx.success();
            LOG.infof("GitHubTeamAdminAuthenticator: success user=%s", user.getUsername());
        } catch (Exception e) {
            LOG.error("GitHubTeamAdminAuthenticator: exception — allowing login (non-blocking).", e);
            ctx.success();
        }
    }

    // ---------- membership ----------
    private enum TokenState { VALID, INVALID, UNKNOWN }
    private enum AuthScheme { BEARER, TOKEN }

    private boolean isMemberOf(KeycloakSession session, RealmModel realm, UserModel user,
                               String ghLogin, String org, String team) {
        if (org.isBlank() || team.isBlank()) {
            LOG.warn("GITHUB_ORG or GITHUB_TEAM is blank; cannot determine membership.");
            return false;
        }
        if (debugAlwaysGrant()) return true;

        AccessToken at = extractGithubAccessToken(session, realm, user);
        if (at == null || at.token == null || at.token.isBlank()) {
            LOG.warn("No usable GitHub access token; ensure storeToken=true and scope includes read:org.");
            return false;
        }

        // Probe token
        TokenState ts = probeToken(session, at);
        if (ts == TokenState.INVALID) {
            LOG.warn("GitHub token is INVALID (401 on /user). Treating as not member and marking to skip revocation.");
            session.getContext().getAuthenticationSession().setAuthNote("GITHUB_TOKEN_INVALID", "true");
            return false;
        }

        // 1) /user/teams (paginate)
        try {
            int page = 1;
            boolean matched = false;
            while (page <= 5) {
                String url = "https://api.github.com/user/teams?per_page=100&page=" + page;
                HttpResp resp = ghGetTryBoth(session, at, url);
                LOG.infof("GitHub /user/teams (page=%d) -> status=%d scheme=%s body=%s",
                        page, resp.status, resp.schemeUsed, truncate(resp.body, 600));

                JsonNode node = parseJsonQuiet(resp.body);
                if (resp.status / 100 == 2 && node != null && node.isArray()) {
                    int seen = 0;
                    for (var it = node.elements(); it.hasNext();) {
                        JsonNode t = it.next(); seen++;
                        String slug = t.path("slug").asText("");
                        String orgLogin = t.path("organization").path("login").asText("");
                        LOG.debugf("Team seen: %s/%s", orgLogin, slug);
                        if (team.equalsIgnoreCase(slug) && org.equalsIgnoreCase(orgLogin)) {
                            LOG.infof("Matched admin team via /user/teams: %s/%s", org, team);
                            matched = true; break;
                        }
                    }
                    if (matched) return true;
                    if (seen < 100) break; // no more pages
                    page++;
                } else {
                    LOG.warnf("/user/teams returned non-2xx or non-array; trying membership fallback. status=%d", resp.status);
                    break;
                }
            }
        } catch (Exception e) {
            LOG.warn("/user/teams threw; will try membership fallback.", e);
        }

        // 2) explicit membership fallback
        try {
            String url = String.format("https://api.github.com/orgs/%s/teams/%s/memberships/%s", org, team, ghLogin);
            HttpResp resp = ghGetTryBoth(session, at, url);
            LOG.infof("GitHub team membership -> status=%d scheme=%s body=%s",
                    resp.status, resp.schemeUsed, truncate(resp.body, 600));

            if (resp.status == 200) {
                JsonNode node = parseJsonQuiet(resp.body);
                String state = node != null ? node.path("state").asText("") : "";
                LOG.infof("Membership state for %s/%s user=%s -> %s", org, team, ghLogin, state);
                return "active".equalsIgnoreCase(state);
            } else if (resp.status == 404) {
                LOG.info("Membership endpoint says not found (not a member).");
                return false;
            } else if (resp.status == 401) {
                LOG.warn("Membership fallback returned 401 — marking token invalid for this login; skipping revocation.");
                session.getContext().getAuthenticationSession().setAuthNote("GITHUB_TOKEN_INVALID", "true");
                return false;
            }
        } catch (Exception e) {
            LOG.warn("GitHub membership fallback threw.", e);
        }
        return false;
    }

    private TokenState probeToken(KeycloakSession session, AccessToken at) {
        try {
            HttpResp resp = ghGetTryBoth(session, at, "https://api.github.com/user");
            LOG.infof("GitHub /user -> status=%d scheme=%s body=%s",
                    resp.status, resp.schemeUsed, truncate(resp.body, 400));
            if (resp.status == 200) return TokenState.VALID;
            if (resp.status == 401) return TokenState.INVALID;
        } catch (Exception e) {
            LOG.warn("GitHub /user probe threw.", e);
        }
        return TokenState.UNKNOWN;
    }

    /** Prefer federated identity username for GitHub, fallback to KC username. */
    private String githubLogin(KeycloakSession session, RealmModel realm, UserModel user) {
        try {
            FederatedIdentityModel fi = session.users().getFederatedIdentity(realm, user, "github");
            if (fi != null && fi.getUserName() != null && !fi.getUserName().isBlank()) {
                return fi.getUserName();
            }
        } catch (Exception ignored) {}
        return user.getUsername();
    }

    private Set<String> fetchTeams(KeycloakSession session, RealmModel realm, UserModel user) {
        Set<String> out = new HashSet<>();
        AccessToken at = extractGithubAccessToken(session, realm, user);
        if (at == null || at.token == null || at.token.isBlank()) return out;
        try {
            int page = 1;
            while (page <= 5) {
                String url = "https://api.github.com/user/teams?per_page=100&page=" + page;
                HttpResp resp = ghGetTryBoth(session, at, url);
                LOG.infof("GitHub /user/teams (for map, page=%d) -> status=%d scheme=%s body=%s",
                        page, resp.status, resp.schemeUsed, truncate(resp.body, 400));

                JsonNode node = parseJsonQuiet(resp.body);
                if (resp.status / 100 == 2 && node != null && node.isArray()) {
                    int seen = 0;
                    for (var it = node.elements(); it.hasNext();) {
                        JsonNode t = it.next(); seen++;
                        String slug = t.path("slug").asText("");
                        String orgLogin = t.path("organization").path("login").asText("");
                        if (!slug.isBlank() && !orgLogin.isBlank()) {
                            out.add((orgLogin + "/" + slug).toLowerCase(Locale.ROOT));
                        }
                    }
                    if (seen < 100) break;
                    page++;
                } else {
                    break;
                }
            }
            LOG.infof("Parsed %d team(s) for user=%s", out.size(), user.getUsername());
        } catch (Exception ex) {
            LOG.warn("GitHub teams fetch failed.", ex);
        }
        return out;
    }

    // ---------- token extraction ----------
    private static final class AccessToken {
        final String token;
        final AuthScheme preferredScheme;
        AccessToken(String token, AuthScheme scheme) { this.token = token; this.preferredScheme = scheme; }
    }

    /**
     * Extract a usable GitHub access token (and preferred scheme) from the federated identity record.
     * Supports:
     *  - Raw bearer/token string
     *  - JSON: {"access_token":"...","token_type":"bearer"}
     *  - URL-encoded: "access_token=...&scope=...&token_type=bearer"
     */
    private AccessToken extractGithubAccessToken(KeycloakSession session, RealmModel realm, UserModel user) {
        try {
            FederatedIdentityModel fi = session.users().getFederatedIdentity(realm, user, "github");
            if (fi == null) {
                LOG.infof("No federated identity record for provider=github (user=%s)", user.getUsername());
                return null;
            }
            String raw = fi.getToken();
            String desc = (raw == null) ? "null" :
                    (raw.startsWith("{") ? "JSON" :
                            (raw.contains("=") && raw.contains("&") && raw.startsWith("access_token=") ? "URL-ENC" :
                                    (raw.contains(".") ? "JWT-ish" : "opaque")));
            LOG.infof("Federated token shape for user=%s: %s len=%d prefix=%s",
                    user.getUsername(), desc, raw == null ? 0 : raw.length(), maskPrefix(raw));

            if (raw == null || raw.isBlank()) return null;

            // JSON payload
            if (raw.startsWith("{")) {
                JsonNode n = parseJsonQuiet(raw);
                if (n != null) {
                    String at = orNull(n.path("access_token").asText());
                    String tt = orNull(n.path("token_type").asText());
                    if (at != null) {
                        AuthScheme scheme = "token".equalsIgnoreCase(tt) ? AuthScheme.TOKEN : AuthScheme.BEARER;
                        LOG.infof("Extracted access_token from JSON; token_type=%s → scheme=%s", tt, scheme);
                        return new AccessToken(at, scheme);
                    }
                }
                LOG.warn("Federated JSON token had no access_token; falling back to raw string.");
            }

            // URL-encoded payload
            if (raw.startsWith("access_token=")) {
                String at = null, tt = null;
                for (String pair : raw.split("&")) {
                    int i = pair.indexOf('=');
                    if (i <= 0) continue;
                    String k = URLDecoder.decode(pair.substring(0, i), StandardCharsets.UTF_8);
                    String v = URLDecoder.decode(pair.substring(i + 1), StandardCharsets.UTF_8);
                    if ("access_token".equalsIgnoreCase(k)) at = v;
                    if ("token_type".equalsIgnoreCase(k)) tt = v;
                }
                if (at != null) {
                    AuthScheme scheme = "token".equalsIgnoreCase(tt) ? AuthScheme.TOKEN : AuthScheme.BEARER;
                    LOG.infof("Extracted access_token from URL-ENC; token_type=%s → scheme=%s", tt, scheme);
                    return new AccessToken(at, scheme);
                }
                LOG.warn("URL-ENC federated token lacked access_token; falling back to raw.");
            }

            // Raw token string (no metadata) — default to BEARER
            return new AccessToken(raw, AuthScheme.BEARER);
        } catch (Exception e) {
            LOG.warn("Error extracting GitHub access token.", e);
            return null;
        }
    }

    // ---------- roles ----------
    private Set<RoleModel> allRolesInRealm(RealmModel realm) {
        Set<RoleModel> all = new LinkedHashSet<>();
        realm.getRolesStream().forEach(all::add);
        long realmCount = realm.getRolesStream().count();

        List<ClientModel> clients = realm.getClientsStream().collect(Collectors.toList());
        int clientCount = 0, clientRoleCount = 0;
        for (ClientModel c : clients) {
            clientCount++;
            long before = all.size();
            c.getRolesStream().forEach(all::add);
            clientRoleCount += (all.size() - before);
        }
        LOG.infof("Role inventory for realm=%s → realmRoles=%d clients=%d clientRoles=%d total=%d",
                realm.getName(), realmCount, clientCount, clientRoleCount, all.size());
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

    // ---------- HTTP helpers ----------
    private static final class HttpResp {
        final int status; final String body; final AuthScheme schemeUsed;
        HttpResp(int status, String body, AuthScheme schemeUsed) { this.status = status; this.body = body; this.schemeUsed = schemeUsed; }
    }

    /** Try with preferred scheme; on 401, retry with alternate scheme once. */
    private HttpResp ghGetTryBoth(KeycloakSession session, AccessToken at, String url) throws Exception {
        HttpResp first = ghGet(session, at.token, at.preferredScheme, url);
        if (first.status != 401) return first;
        AuthScheme alt = (at.preferredScheme == AuthScheme.BEARER) ? AuthScheme.TOKEN : AuthScheme.BEARER;
        LOG.warnf("GitHub request got 401 with scheme=%s; retrying with %s", at.preferredScheme, alt);
        HttpResp second = ghGet(session, at.token, alt, url);
        return (second.status == 401) ? first : second;
    }

    private HttpResp ghGet(KeycloakSession session, String token, AuthScheme scheme, String url) throws Exception {
        SimpleHttp req = SimpleHttp.doGet(url, session)
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", userAgent());
        String ver = apiVersion();
        if (!ver.isBlank()) req.header("X-GitHub-Api-Version", ver);

        String authHeader = (scheme == AuthScheme.TOKEN ? "token " : "Bearer ") + token;
        req.header("Authorization", authHeader);

        var resp = req.asResponse();
        return new HttpResp(resp.getStatus(), resp.asString(), scheme);
    }

    // ---------- utils ----------
    private static String safe(String s) { return (s == null || s.isBlank()) ? "(blank)" : s; }
    private static String truncate(String s, int max) { if (s == null) return ""; return s.length() <= max ? s : s.substring(0, max) + "…"; }
    private static JsonNode parseJsonQuiet(String body) { try { return org.keycloak.util.JsonSerialization.mapper.readTree(body); } catch (Exception e) { return null; } }
    private static String maskPrefix(String t) {
        if (t == null || t.isBlank()) return "(none)";
        int len = t.length();
        String head = t.substring(0, Math.min(4, len));
        return head + "… (" + len + ")";
    }
    private static String orNull(String s) { return (s == null || s.isBlank() || "null".equalsIgnoreCase(s)) ? null : s; }

    // ---------- Authenticator plumbing ----------
    @Override public void action(AuthenticationFlowContext ctx) { }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) { }
    @Override public void close() { }
}
