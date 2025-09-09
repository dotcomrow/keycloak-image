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
 * Grants admin privileges to users who are members of a specific GitHub org/team.
 *
 * Priority:
 *  1) If realm role "admin" exists, grant it (god-level in the realm).
 *  2) Else, grant any available combination of client roles that approximate admin
 *     (today: manage-realm + view-realm wherever they exist).
 *
 * Extensibility:
 *  - Optional GITHUB_ROLE_MAP env allows mapping other org/team slugs to specific
 *    realm/client roles (see notes below).
 */
public class GitHubTeamAdminAuthenticator implements Authenticator {
    private static final Logger LOG = Logger.getLogger(GitHubTeamAdminAuthenticator.class);

    // Primary admin team (god-level)
    private static String adminOrg()  { return getenv("GITHUB_ORG", getenv("GITHUB_ADMIN_ORG", "")).trim(); }
    private static String adminTeam() { return getenv("GITHUB_TEAM", getenv("GITHUB_ADMIN_TEAM", "")).trim(); }

    // Optional JSON map for future narrower teams → roles (see notes)
    // Example:
    //   {"myorg/devs":["realm:manage-users","client:master-realm:view-realm"]}
    private static String roleMapJson() { return getenv("GITHUB_ROLE_MAP", "").trim(); }

    private static boolean debugAlwaysGrant() {
        return "true".equalsIgnoreCase(getenv("DEBUG_ALWAYS_GRANT", "false"));
    }

    private static String getenv(String k, String def) {
        String v = System.getenv(k);
        return v != null ? v : def;
    }

    @Override
    public void authenticate(AuthenticationFlowContext ctx) {
        try {
            final KeycloakSession session = ctx.getSession();
            final RealmModel realm = ctx.getRealm();
            final UserModel user = ctx.getUser();

            // Determine intended role set based on team membership
            // 1) Admin team → realm admin (or best-effort fallback)
            boolean isAdminTeam = debugAlwaysGrant() || isMemberOf(session, realm, user, adminOrg(), adminTeam());

            Map<RoleDescriptor, RoleModel> toGrant = new LinkedHashMap<>();

            if (isAdminTeam) {
                // Prefer the realm role "admin"
                RoleModel adminRealmRole = realm.getRole("admin");
                if (adminRealmRole != null) {
                    toGrant.put(RoleDescriptor.realm("admin"), adminRealmRole);
                } else {
                    // Fallback: approximate admin with manage-realm + view-realm wherever present
                    addIfPresent(toGrant, findRoleAnywhere(realm, RoleDescriptor.client("manage-realm")));
                    addIfPresent(toGrant, findRoleAnywhere(realm, RoleDescriptor.client("view-realm")));
                }
            }

            // 2) Optional: other mappings for additional teams (future collaborators)
            Map<String, List<RoleDescriptor>> map = parseRoleMap(roleMapJson());
            if (!map.isEmpty()) {
                // Example key format in map: "org/team" (slug and org login)
                Set<String> myTeams = fetchTeams(session, realm, user); // "org/team" slugs
                for (String key : myTeams) {
                    List<RoleDescriptor> wanted = map.getOrDefault(key.toLowerCase(Locale.ROOT), Collections.emptyList());
                    for (RoleDescriptor d : wanted) {
                        addIfPresent(toGrant, resolveDescriptor(realm, d));
                    }
                }
            }

            // Grant/revoke as appropriate. If neither adminTeam nor mapped teams matched, we revoke.
            if (!toGrant.isEmpty()) {
                grantIfNeeded(user, toGrant.values());
            } else {
                // Remove anything we might have previously granted (idempotent, narrow scope)
                // Realm role admin:
                RoleModel adminRealmRole = realm.getRole("admin");
                if (adminRealmRole != null && user.hasRole(adminRealmRole)) {
                    user.deleteRoleMapping(adminRealmRole);
                    LOG.infof("Removed realm role %s from %s", adminRealmRole.getName(), user.getUsername());
                }
                // Fallback pair
                maybeRevoke(user, findRoleAnywhere(realm, RoleDescriptor.client("manage-realm")));
                maybeRevoke(user, findRoleAnywhere(realm, RoleDescriptor.client("view-realm")));
                // Any mapped roles:
                for (RoleDescriptor d : allDescriptors(map)) {
                    maybeRevoke(user, resolveDescriptor(realm, d));
                }
            }

            ctx.success();
        } catch (Exception e) {
            LOG.error("Error in GitHubTeamAdminAuthenticator", e);
            // Do not block login on provider errors.
            ctx.success();
        }
    }

    // === Team membership ===

    private boolean isMemberOf(KeycloakSession session, RealmModel realm, UserModel user, String org, String team) {
        if (org == null || org.isBlank() || team == null || team.isBlank()) {
            // Not configured → not an admin team member
            return false;
        }
        if (debugAlwaysGrant()) return true;

        String token = fetchGithubToken(session, realm, user);
        if (token == null || token.isBlank()) {
            LOG.info("No GitHub token on federated identity; cannot verify team.");
            return false;
        }

        try {
            JsonNode teams = SimpleHttp
                .doGet("https://api.github.com/user/teams", session)
                .header("Authorization", "Bearer " + token)
                .header("Accept", "application/vnd.github+json")
                .asJson();

            for (var it = teams.elements(); it.hasNext(); ) {
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
            for (var it = teams.elements(); it.hasNext(); ) {
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

    // === Role resolution & grant/revoke ===

    /** Try to find a role by descriptor; may return null. */
    private RoleModel resolveDescriptor(RealmModel realm, RoleDescriptor d) {
        if (d == null) return null;
        if (d.isRealmRole()) {
            return realm.getRole(d.role);
        }
        ClientModel c = realm.getClientByClientId(d.clientId);
        if (c == null) return null;
        return c.getRole(d.role);
    }

    /** Find the first occurrence of a client role name across all clients (e.g., manage-realm/view-realm) */
    private RoleModel findRoleAnywhere(RealmModel realm, RoleDescriptor like) {
        if (like == null || like.isRealmRole()) return null;
        for (ClientModel c : realm.getClientsStream().collect(Collectors.toList())) {
            RoleModel r = c.getRole(like.role);
            if (r != null) return r;
        }
        return null;
    }

    private void addIfPresent(Map<RoleDescriptor, RoleModel> bag, RoleModel role) {
        if (role != null) {
            RoleDescriptor d = role.isClientRole()
                ? RoleDescriptor.client(role.getName(), role.getContainerId()) // containerId is internal UUID; keep key stable by name
                : RoleDescriptor.realm(role.getName());
            bag.put(d, role);
        }
    }

    private void grantIfNeeded(UserModel user, Collection<RoleModel> roles) {
        boolean changed = false;
        for (RoleModel r : roles) {
            if (!user.hasRole(r)) {
                user.grantRole(r);
                LOG.infof("Granted %s to %s", display(r), user.getUsername());
                changed = true;
            }
        }
        if (!changed) {
            LOG.debugf("No admin role changes for %s (already granted).", user.getUsername());
        }
    }

    private void maybeRevoke(UserModel user, RoleModel role) {
        if (role != null && user.hasRole(role)) {
            user.deleteRoleMapping(role);
            LOG.infof("Removed %s from %s", display(role), user.getUsername());
        }
    }

    private String display(RoleModel r) {
        return r.isClientRole()
            ? ("client:" + r.getContainerId() + ":" + r.getName())
            : ("realm:" + r.getName());
    }

    // === GITHUB_ROLE_MAP parsing ===

    private static class RoleDescriptor {
        final boolean realmRole;
        final String clientId; // for client roles: clientId (human id), for realm roles: null
        final String role;

        private RoleDescriptor(boolean realmRole, String clientId, String role) {
            this.realmRole = realmRole;
            this.clientId = clientId;
            this.role = role;
        }
        static RoleDescriptor realm(String role) { return new RoleDescriptor(true, null, role); }
        static RoleDescriptor client(String roleName) { return new RoleDescriptor(false, null, roleName); } // name-only search
        static RoleDescriptor client(String clientId, String role) { return new RoleDescriptor(false, clientId, role); }
        boolean isRealmRole() { return realmRole; }
    }

    private Map<String, List<RoleDescriptor>> parseRoleMap(String json) {
        Map<String, List<RoleDescriptor>> out = new HashMap<>();
        if (json == null || json.isBlank()) return out;
        try {
            JsonNode root = SimpleJson.parse(json);
            if (!root.isObject()) return out;
            Iterator<String> it = root.fieldNames();
            while (it.hasNext()) {
                String key = it.next(); // expected "org/team"
                JsonNode arr = root.get(key);
                if (arr == null || !arr.isArray()) continue;
                List<RoleDescriptor> list = new ArrayList<>();
                for (JsonNode n : arr) {
                    String spec = n.asText("");
                    RoleDescriptor d = parseDescriptor(spec);
                    if (d != null) list.add(d);
                }
                if (!list.isEmpty()) out.put(key.toLowerCase(Locale.ROOT), list);
            }
        } catch (Exception e) {
            LOG.warn("Failed to parse GITHUB_ROLE_MAP; ignoring.", e);
        }
        return out;
    }

    private static RoleDescriptor parseDescriptor(String spec) {
        // Formats:
        //  "realm:ROLE"
        //  "client:CLIENT_ID:ROLE"
        if (spec == null || spec.isBlank()) return null;
        String[] parts = spec.split(":", 3);
        if (parts.length >= 2 && "realm".equalsIgnoreCase(parts[0])) {
            return RoleDescriptor.realm(parts[1]);
        }
        if (parts.length == 3 && "client".equalsIgnoreCase(parts[0])) {
            return RoleDescriptor.client(parts[1], parts[2]);
        }
        return null;
    }

    private static List<RoleDescriptor> allDescriptors(Map<String, List<RoleDescriptor>> m) {
        return m.values().stream().flatMap(Collection::stream).collect(Collectors.toList());
    }

    // === Authenticator plumbing ===
    @Override public void action(AuthenticationFlowContext ctx) { }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) { }
    @Override public void close() { }

    // Tiny JSON helper (no external deps; uses Keycloak's Jackson)
    private static final class SimpleJson {
        static JsonNode parse(String s) throws Exception {
            return org.keycloak.util.JsonSerialization.mapper.readTree(s);
        }
    }
}
