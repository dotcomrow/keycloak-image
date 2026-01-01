package systems.suncoast.kc.google;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.ServiceAccountCredentials;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

public class GoogleGroupsAuthenticator implements Authenticator {
    private static final Logger LOG = Logger.getLogger(GoogleGroupsAuthenticator.class);
    private static final String ATTR_GROUPS = "ggl.groups";
    private static final String ATTR_TS = "ggl.cachedAt";
    private static final long DEFAULT_TTL_SECONDS = 600;

    private static final String SCOPE_GROUPS = "https://www.googleapis.com/auth/admin.directory.group.readonly";
    private static final String SCOPE_MEMBERS = "https://www.googleapis.com/auth/admin.directory.group.member.readonly";
    private static final List<String> SCOPES = List.of(SCOPE_GROUPS, SCOPE_MEMBERS);

    private static final Object TOKEN_LOCK = new Object();
    private static volatile ServiceAccountCredentials cachedCreds;
    private static volatile AccessToken cachedToken;

    private static String getenv(String k, String def) {
        String v = System.getenv(k);
        return v != null ? v : def;
    }
    private static boolean isTrue(String k, boolean def) {
        String v = getenv(k, def ? "true" : "false");
        return "true".equalsIgnoreCase(v) || "1".equals(v);
    }
    private static long ttlSeconds() {
        String v = getenv("GOOGLE_GROUPS_TTL_SECONDS", Long.toString(DEFAULT_TTL_SECONDS));
        try {
            long t = Long.parseLong(v);
            return t > 0 ? t : DEFAULT_TTL_SECONDS;
        } catch (NumberFormatException e) {
            return DEFAULT_TTL_SECONDS;
        }
    }
    private static boolean autoRoles() { return isTrue("GOOGLE_AUTO_ROLES", true); }
    private static boolean strictRevoke() { return isTrue("GOOGLE_STRICT_REVOKE", true); }
    private static String rolePrefix() { return getenv("GOOGLE_ROLE_PREFIX", "ggl:"); }
    private static String roleMapJson() { return getenv("GOOGLE_GROUP_ROLE_MAP", "").trim(); }
    private static String adminEmail() {
        return getenv("GOOGLE_ADMIN_EMAIL", getenv("GOOGLE_DELEGATED_ADMIN", "")).trim();
    }
    private static String saJsonPath() { return getenv("GOOGLE_SA_JSON_PATH", "").trim(); }
    private static String saJsonInline() { return getenv("GOOGLE_SA_JSON", "").trim(); }

    @Override
    public void authenticate(AuthenticationFlowContext ctx) {
        UserModel user = ctx.getUser();
        if (user == null) { ctx.attempted(); return; }
        String email = user.getEmail();
        if (email == null || email.isBlank()) { ctx.attempted(); return; }

        RealmModel realm = ctx.getRealm();
        Map<String, List<RoleSpec>> roleMap = parseRoleMap(roleMapJson());
        Set<String> groupsToCheck = new LinkedHashSet<>();
        groupsToCheck.addAll(parseGroupsCsv(getenv("GOOGLE_GROUPS", "")));
        groupsToCheck.addAll(parseGroupsCsv(getenv("GOOGLE_GROUP_ALLOWLIST", "")));
        groupsToCheck.addAll(roleMap.keySet());

        if (groupsToCheck.isEmpty()) {
            LOG.warn("GoogleGroupsAuthenticator: no groups configured; set GOOGLE_GROUPS or GOOGLE_GROUP_ROLE_MAP.");
            ctx.success();
            return;
        }

        List<String> memberGroups = new ArrayList<>();
        boolean fromCache = false;
        boolean hadError = false;
        long now = Instant.now().getEpochSecond();
        String cachedAt = user.getFirstAttribute(ATTR_TS);
        if (cachedAt != null) {
            try {
                if (now - Long.parseLong(cachedAt) < ttlSeconds()) {
                    memberGroups = normalizeGroups(user.getAttributeStream(ATTR_GROUPS).toList());
                    fromCache = true;
                }
            } catch (NumberFormatException ignore) {
                // fall through
            }
        }

        if (!fromCache) {
            try {
                memberGroups = fetchGroups(ctx, email, groupsToCheck);
                user.setAttribute(ATTR_GROUPS, memberGroups);
                user.setSingleAttribute(ATTR_TS, Long.toString(now));
            } catch (Exception e) {
                hadError = true;
                LOG.warnf(e, "Google group lookup failed for email=%s", email);
                EventBuilder ev = ctx.getEvent();
                if (ev != null) {
                    ev.detail("google_groups_error", e.getClass().getSimpleName());
                }
            }
        }

        Set<RoleModel> target = new LinkedHashSet<>();
        if (autoRoles()) {
            for (String g : memberGroups) {
                String roleName = rolePrefix() + slug(g);
                RoleModel role = realm.getRole(roleName);
                if (role == null) {
                    role = ctx.getSession().roles().addRealmRole(realm, roleName);
                }
                target.add(role);
            }
        }

        if (!roleMap.isEmpty()) {
            for (String g : memberGroups) {
                List<RoleSpec> wants = roleMap.get(g);
                if (wants == null) continue;
                for (RoleSpec spec : wants) {
                    RoleModel r = resolve(realm, spec);
                    if (r != null) {
                        target.add(r);
                    } else {
                        LOG.warnf("Mapped role not found for spec=%s group=%s", specString(spec), g);
                    }
                }
            }
        }

        if (!target.isEmpty()) {
            grantIfMissing(user, target);
        }

        if (strictRevoke() && !hadError) {
            Set<RoleModel> managed = new LinkedHashSet<>();
            if (autoRoles()) {
                for (String g : groupsToCheck) {
                    String roleName = rolePrefix() + slug(g);
                    RoleModel r = realm.getRole(roleName);
                    if (r != null) managed.add(r);
                }
            }
            for (List<RoleSpec> specs : roleMap.values()) {
                for (RoleSpec spec : specs) {
                    RoleModel r = resolve(realm, spec);
                    if (r != null) managed.add(r);
                }
            }
            revokeIfMissing(user, managed, target);
        }

        ctx.success();
    }

    private List<String> fetchGroups(AuthenticationFlowContext ctx, String email, Set<String> groupsToCheck) throws Exception {
        List<String> out = new ArrayList<>();
        for (String g : groupsToCheck) {
            boolean member = hasMember(ctx.getSession(), g, email);
            LOG.infof("Google group membership: user=%s group=%s member=%s", email, g, member);
            if (member) out.add(g);
        }
        return out;
    }

    private boolean hasMember(KeycloakSession session, String groupKey, String memberEmail) throws Exception {
        HttpResp resp = directoryHasMember(session, accessToken(false), groupKey, memberEmail);
        if (resp.status == 401) {
            resp = directoryHasMember(session, accessToken(true), groupKey, memberEmail);
        }
        LOG.debugf("Google hasMember -> status=%d body=%s", resp.status, truncate(resp.body, 400));
        if (resp.status == 200) {
            JsonNode node = parseJsonQuiet(resp.body);
            return node != null && node.path("isMember").asBoolean(false);
        }
        if (resp.status == 404) return false;
        throw new IllegalStateException("Google Directory API error: status=" + resp.status);
    }

    private HttpResp directoryHasMember(KeycloakSession session, String token, String groupKey, String memberEmail) throws Exception {
        String url = String.format(
                "https://admin.googleapis.com/admin/directory/v1/groups/%s/hasMember/%s",
                urlEncode(groupKey), urlEncode(memberEmail));
        SimpleHttp req = SimpleHttp.doGet(url, session)
                .header("Authorization", "Bearer " + token)
                .header("Accept", "application/json");
        var resp = req.asResponse();
        return new HttpResp(resp.getStatus(), resp.asString());
    }

    private static String accessToken(boolean forceRefresh) throws Exception {
        ServiceAccountCredentials creds = serviceAccountCreds();
        synchronized (TOKEN_LOCK) {
            if (!forceRefresh && cachedToken != null) {
                Date expiresAt = cachedToken.getExpirationTime();
                if (expiresAt != null && expiresAt.toInstant().isAfter(Instant.now().plusSeconds(60))) {
                    return cachedToken.getTokenValue();
                }
            }
            AccessToken t = creds.refreshAccessToken();
            cachedToken = t;
            return t.getTokenValue();
        }
    }

    private static ServiceAccountCredentials serviceAccountCreds() throws Exception {
        ServiceAccountCredentials creds = cachedCreds;
        if (creds != null) return creds;
        synchronized (TOKEN_LOCK) {
            if (cachedCreds != null) return cachedCreds;
            String subject = adminEmail();
            if (subject.isBlank()) {
                throw new IllegalStateException("GOOGLE_ADMIN_EMAIL (or GOOGLE_DELEGATED_ADMIN) is required.");
            }
            try (InputStream in = serviceAccountStream()) {
                if (in == null) {
                    throw new IllegalStateException("GOOGLE_SA_JSON_PATH or GOOGLE_SA_JSON is required.");
                }
                cachedCreds = (ServiceAccountCredentials) ServiceAccountCredentials.fromStream(in)
                        .createScoped(SCOPES)
                        .createDelegated(subject);
                return cachedCreds;
            }
        }
    }

    private static InputStream serviceAccountStream() throws Exception {
        String path = saJsonPath();
        if (!path.isBlank()) return new FileInputStream(path);
        String json = saJsonInline();
        if (!json.isBlank()) return new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8));
        return null;
    }

    private static Set<String> parseGroupsCsv(String csv) {
        Set<String> out = new LinkedHashSet<>();
        if (csv == null || csv.isBlank()) return out;
        for (String part : csv.split(",")) {
            String g = part.trim().toLowerCase(Locale.ROOT);
            if (!g.isBlank()) out.add(g);
        }
        return out;
    }

    private static List<String> normalizeGroups(List<String> groups) {
        List<String> out = new ArrayList<>();
        if (groups == null) return out;
        for (String g : groups) {
            if (g == null) continue;
            String v = g.trim().toLowerCase(Locale.ROOT);
            if (!v.isBlank()) out.add(v);
        }
        return out;
    }

    private static String slug(String s) {
        return s.toLowerCase().replaceAll("[^a-z0-9]+", "-").replaceAll("(^-|-$)", "");
    }

    private static String urlEncode(String v) {
        String enc = URLEncoder.encode(v, StandardCharsets.UTF_8);
        return enc.replace("+", "%20");
    }

    private static final class HttpResp {
        final int status;
        final String body;
        HttpResp(int status, String body) { this.status = status; this.body = body; }
    }

    private static JsonNode parseJsonQuiet(String body) {
        try {
            return org.keycloak.util.JsonSerialization.mapper.readTree(body);
        } catch (Exception e) {
            return null;
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    private void grantIfMissing(UserModel user, Collection<RoleModel> roles) {
        for (RoleModel r : roles) {
            if (!user.hasRole(r)) {
                user.grantRole(r);
            }
        }
    }

    private void revokeIfMissing(UserModel user, Set<RoleModel> managed, Set<RoleModel> desired) {
        for (RoleModel r : managed) {
            if (!desired.contains(r) && user.hasRole(r)) {
                user.deleteRoleMapping(r);
            }
        }
    }

    private static final class RoleSpec {
        final boolean realm;
        final String clientId;
        final String role;
        RoleSpec(boolean realm, String clientId, String role) { this.realm = realm; this.clientId = clientId; this.role = role; }
        static RoleSpec realm(String role) { return new RoleSpec(true, null, role); }
        static RoleSpec client(String clientId, String role) { return new RoleSpec(false, clientId, role); }
    }

    private static String specString(RoleSpec s) {
        return s == null ? "null" : (s.realm ? "realm:" + s.role : "client:" + s.clientId + ":" + s.role);
    }

    private static RoleSpec parseRoleSpec(String spec) {
        if (spec == null || spec.isBlank()) return null;
        String[] parts = spec.split(":", 3);
        if (parts.length >= 2 && "realm".equalsIgnoreCase(parts[0])) return RoleSpec.realm(parts[1]);
        if (parts.length == 3 && "client".equalsIgnoreCase(parts[0])) return RoleSpec.client(parts[1], parts[2]);
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
                String key = it.next().toLowerCase(Locale.ROOT);
                JsonNode arr = root.get(key);
                if (arr == null || !arr.isArray()) continue;
                List<RoleSpec> specs = new ArrayList<>();
                for (JsonNode n : arr) {
                    RoleSpec s = parseRoleSpec(n.asText(""));
                    if (s != null) specs.add(s);
                }
                if (!specs.isEmpty()) out.put(key, specs);
            }
        } catch (Exception e) {
            LOG.warn("Failed to parse GOOGLE_GROUP_ROLE_MAP; ignoring.", e);
        }
        return out;
    }

    private RoleModel resolve(RealmModel realm, RoleSpec spec) {
        if (spec == null) return null;
        if (spec.realm) return realm.getRole(spec.role);
        ClientModel c = realm.getClientByClientId(spec.clientId);
        return (c != null) ? c.getRole(spec.role) : null;
    }

    @Override public void action(AuthenticationFlowContext ctx) { }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) { }
    @Override public void close() { }
}
