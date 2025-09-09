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
 * Admin team -> grant ALL roles in the realm (realm roles + all client roles).
 * Optional GITHUB_ROLE_MAP supports future narrower teams/roles, but the admin
 * team still always gets the full set.
 *
 * Env vars:
 *   GITHUB_ORG / GITHUB_TEAM           -> primary "god-mode" team
 *   DEBUG_ALWAYS_GRANT=true            -> force grant (for smoke tests)
 *   GITHUB_STRICT_REVOKE=true|false    -> revoke previously granted roles if user is NOT in admin team (default: true)
 *   GITHUB_ROLE_MAP (optional JSON)    -> extra team->roles mapping (formats: "realm:ROLE" or "client:CLIENT_ID:ROLE")
 *   GITHUB_ADMIN_EXCLUDE (optional)    -> comma-separated list of role specs to EXCLUDE from grant
 *                                         formats: "realm:ROLE" or "client:CLIENT_ID:ROLE" or bare role name
 */
public class GitHubTeamAdminAuthenticator implements Authenticator {
    private static final Logger LOG = Logger.getLogger(GitHubTeamAdminAuthenticator.class);

    // ---- config helpers ----
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

    @Override
    public void authenticate(AuthenticationFlowContext ctx) {
        try {
            final KeycloakSession session = ctx.getSession();
            final RealmModel realm = ctx.getRealm();
            final UserModel user = ctx.getUser();

            // Determine membership of the admin team (or forced by DEBUG_ALWAYS_GRANT)
            boolean adminMember = debugAlwaysGrant() || isMemberOf(session, realm, user, adminOrg(), adminTeam());

            // Build the target role set
            Set<RoleModel> target = new LinkedHashSet<>();

            if (adminMember) {
                // Grant absolutely everything in the realm
                target.addAll(allRolesInRealm(realm));
            }

            // Optional: layer in additional mappings for other teams
            Map<String, List<RoleSpec>> map = parseRoleMap(roleMapJson());
            if (!map.isEmpty()) {
                Set<String> myTeams = fetchTeams(session, realm, user); // "org/team" lowercase
                for (String key : myTeams) {
                    List<RoleSpec> wants = map.get(key);
                    if (wants == null) continue;
                    for (RoleSpec spec : wants) {
                        RoleModel r = resolve(realm, spec);
                        if (r != null) target.add(r);
                    }
                }
            }

            // Optional excludes
            Set<RoleSpec> excludes = parseExcludes(excludeCsv());
            if (!excludes.isEmpty()) {
                target.removeIf(r -> excludeMatch(r, excludes));
            }

            // Apply: grant target; optionally revoke anything "grantable" that’s not in target
            if (!target.isEmpty()) {
                grantIfMissing(user, target);
            }

            if (!adminMember && strictRevoke()) {
                // Only revoke roles we consider "grantable" (everything in realm by default, plus mapped ones)
                Set<RoleModel> grantable = new LinkedHashSet<>(allRolesInRealm(realm));
                for (List<RoleSpec> specs : map.values()) {
                    for (RoleSpec s : specs) {
                        RoleModel r = resolve(realm, s);
                        if (r != null) grantable.add(r);
                    }
                }
                if (!excludes.isEmpty()) grantable.removeIf(r -> excludeMatch(r, excludes));
                revokeIfPresent(user, grantable);
            }

            ctx.success();
        } catch (Exception e) {
            LOG.error("Error in GitHubTeamAdminAuthenticator", e);
            // Never block login on provider errors
            ctx.success();
        }
    }

    // ---- GitHub membership helpers ----

    private boolean isMemberOf(KeycloakSession session, RealmModel realm, UserModel user, String org, String team) {
        if (org.isBlank() || team.isBlank()) return false;
        if (debugAlwaysGrant()) return true;

        String token = fetchGithubToken(session, realm, user);
        if (token == null || token.isBlank()) {
            LOG.info("No GitHub token; ensure your IdP has storeToken=true.");
            return false;
        }
        try {
            JsonNode teams = SimpleHttp
                    .doGet("https://api.github.com/user/teams", session)
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", "application/vnd.github+json")
                    .asJson();
            for (var it = teams.elements(); it.hasNext();) {
                JsonNode t = it.next();
                String slug = t.path("slug").asText("");
                String orgLogin = t.path("organization").path("login").asText("");
                LOG.debugf("Team seen: %s/%s", orgLogin, slug);
                if (team.equalsIgnoreCase(slug) && org.equalsIgnoreCase(orgLogin)) return true;
            }
        } catch (Exception ex) {
            LOG.warn("GitHub teams lookup failed; treating as not a member.", ex);
        }
        return false;
    }

    private String fetchGithubToken(KeycloakSession session, RealmModel realm, UserModel user) {
        try {
            FederatedIdentityModel fi = session.users().getFederatedIdentity(realm, user, "github");
            return fi != null ? fi.getToken() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private Set<String> fetchTeams(KeycloakSession session, RealmModel realm, UserModel user) {
        Set<String> out = new HashSet<>();
        String token = fetchGithubToken(session, realm, user);
        if (token == null || token.isBlank()) return out;
        try {
            JsonNode teams = SimpleHttp
                    .doGet("https://api.github.com/user/teams", session)
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", "application/vnd.github+json")
                    .asJson();
            for (var it = teams.elements(); it.hasNext();) {
                JsonNode t = it.next();
                String slug = t.path("slug").asText("");
                String orgLogin = t.path("organization").path("login").asText("");
                if (!slug.isBlank() && !orgLogin.isBlank()) {
                    out.add((orgLogin + "/" + slug).toLowerCase(Locale.ROOT));
                }
            }
        } catch (Exception ex) {
            LOG.warn("GitHub teams fetch failed.", ex);
        }
        return out;
    }

    // ---- Role collection / resolution ----

    private Set<RoleModel> allRolesInRealm(RealmModel realm) {
        Set<RoleModel> all = new LinkedHashSet<>();
        realm.getRolesStream().forEach(all::add); // realm roles
        // client roles
        List<ClientModel> clients = realm.getClientsStream().collect(Collectors.toList());
        for (ClientModel c : clients) {
            c.getRolesStream().forEach(all::add);
        }
        LOG.debugf("Discovered %d total roles in realm %s", all.size(), realm.getName());
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
            LOG.debugf("No new roles to grant for %s (already had them).", user.getUsername());
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
        }
    }

    private String pretty(RoleModel r) {
        if (r.isClientRole()) {
            // Convert internal containerId to human clientId if we can
            RoleContainerModel cont = r.getContainer();
            String clientId = (cont instanceof ClientModel) ? ((ClientModel) cont).getClientId() : r.getContainerId();
            return "client:" + clientId + ":" + r.getName();
        } else {
            return "realm:" + r.getName();
        }
    }

    // ---- RoleSpec & (optional) mapping/excludes ----

    private static final class RoleSpec {
        final boolean realm;
        final String clientId; // when !realm
        final String role;

        RoleSpec(boolean realm, String clientId, String role) {
            this.realm = realm; this.clientId = clientId; this.role = role;
        }
        static RoleSpec realm(String role) { return new RoleSpec(true, null, role); }
        static RoleSpec client(String clientId, String role) { return new RoleSpec(false, clientId, role); }
    }

    private static RoleSpec parseRoleSpec(String spec) {
        if (spec == null || spec.isBlank()) return null;
        String[] parts = spec.split(":", 3);
        if (parts.length >= 2 && "realm".equalsIgnoreCase(parts[0])) {
            return RoleSpec.realm(parts[1]);
        }
        if (parts.length == 3 && "client".equalsIgnoreCase(parts[0])) {
            return RoleSpec.client(parts[1], parts[2]);
        }
        // bare role name as realm role (fallback)
        if (parts.length == 1) return RoleSpec.realm(parts[0]);
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
                String key = it.next(); // expected "org/team"
                JsonNode arr = root.get(key);
                if (arr == null || !arr.isArray()) continue;
                List<RoleSpec> specs = new ArrayList<>();
                for (JsonNode n : arr) {
                    RoleSpec s = parseRoleSpec(n.asText(""));
                    if (s != null) specs.add(s);
                }
                if (!specs.isEmpty()) out.put(key.toLowerCase(Locale.ROOT), specs);
            }
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

    // ---- Authenticator plumbing ----
    @Override public void action(AuthenticationFlowContext ctx) { }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) { }
    @Override public void close() { }
}
