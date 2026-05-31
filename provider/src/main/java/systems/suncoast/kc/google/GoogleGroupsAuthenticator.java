package systems.suncoast.kc.google;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.ServiceAccountCredentials;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.events.EventBuilder;
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
    private static String rolePrefix() { return getenv("GOOGLE_ROLE_PREFIX", ""); }
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
        Set<String> groupsToCheck = new LinkedHashSet<>();
        groupsToCheck.addAll(parseGroupsCsv(getenv("GOOGLE_GROUPS", "")));
        groupsToCheck.addAll(parseGroupsCsv(getenv("GOOGLE_GROUP_ALLOWLIST", "")));

        if (groupsToCheck.isEmpty()) {
            LOG.warn("GoogleGroupsAuthenticator: no groups configured; set GOOGLE_GROUPS or GOOGLE_GROUP_ALLOWLIST.");
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
                String roleName = rolePrefix() + roleNameFromGroupKey(g);
                if (roleName.isBlank()) continue;
                RoleModel role = realm.getRole(roleName);
                if (role == null) {
                    role = ctx.getSession().roles().addRealmRole(realm, roleName);
                }
                target.add(role);
            }
        }

        if (!target.isEmpty()) {
            grantIfMissing(user, target);
        }

        if (strictRevoke() && !hadError) {
            Set<RoleModel> managed = new LinkedHashSet<>();
            if (autoRoles()) {
                for (String g : groupsToCheck) {
                    String roleName = rolePrefix() + roleNameFromGroupKey(g);
                    if (roleName.isBlank()) continue;
                    RoleModel r = realm.getRole(roleName);
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
        // External identities can trigger "Invalid Input: memberKey" on hasMember.
        // Fall back to direct member listing so external users can still be matched.
        if (resp.status == 400 && isInvalidMemberKey(resp.body)) {
            LOG.debugf("Google hasMember fallback to members.list for group=%s member=%s", groupKey, memberEmail);
            return hasMemberViaList(session, groupKey, memberEmail);
        }
        throw new IllegalStateException("Google Directory API error: status=" + resp.status);
    }

    private boolean hasMemberViaList(KeycloakSession session, String groupKey, String memberEmail) throws Exception {
        String target = canonicalEmail(memberEmail);
        String pageToken = null;
        Set<String> seen = new HashSet<>();
        while (true) {
            HttpResp resp = directoryListMembers(session, accessToken(false), groupKey, pageToken);
            if (resp.status == 401) {
                resp = directoryListMembers(session, accessToken(true), groupKey, pageToken);
            }
            LOG.debugf("Google members.list -> status=%d group=%s pageToken=%s body=%s",
                    resp.status, groupKey, pageToken, truncate(resp.body, 400));
            if (resp.status == 404) return false;
            if (resp.status != 200) {
                throw new IllegalStateException("Google Directory API members.list error: status=" + resp.status);
            }
            JsonNode root = parseJsonQuiet(resp.body);
            if (root == null) return false;
            JsonNode members = root.path("members");
            if (members.isArray()) {
                for (JsonNode m : members) {
                    String email = m.path("email").asText("");
                    if (!email.isBlank() && target.equals(canonicalEmail(email))) {
                        return true;
                    }
                }
            }
            String next = root.path("nextPageToken").asText("");
            if (next.isBlank() || !seen.add(next)) {
                return false;
            }
            pageToken = next;
        }
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

    private HttpResp directoryListMembers(KeycloakSession session, String token, String groupKey, String pageToken) throws Exception {
        StringBuilder url = new StringBuilder(String.format(
                "https://admin.googleapis.com/admin/directory/v1/groups/%s/members?maxResults=200",
                urlEncode(groupKey)));
        if (pageToken != null && !pageToken.isBlank()) {
            url.append("&pageToken=").append(urlEncode(pageToken));
        }
        SimpleHttp req = SimpleHttp.doGet(url.toString(), session)
                .header("Authorization", "Bearer " + token)
                .header("Accept", "application/json");
        var resp = req.asResponse();
        return new HttpResp(resp.getStatus(), resp.asString());
    }

    private static boolean isInvalidMemberKey(String body) {
        if (body == null) return false;
        String normalized = body.toLowerCase(Locale.ROOT);
        return normalized.contains("invalid input: memberkey") || normalized.contains("\"memberkey\"");
    }

    private static String canonicalEmail(String email) {
        if (email == null) return "";
        String normalized = email.trim().toLowerCase(Locale.ROOT);
        int at = normalized.indexOf('@');
        if (at <= 0 || at == normalized.length() - 1) return normalized;
        String local = normalized.substring(0, at);
        String domain = normalized.substring(at + 1);
        if ("googlemail.com".equals(domain)) {
            domain = "gmail.com";
        }
        if ("gmail.com".equals(domain)) {
            int plus = local.indexOf('+');
            if (plus >= 0) {
                local = local.substring(0, plus);
            }
            local = local.replace(".", "");
        }
        return local + "@" + domain;
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

    private static String roleNameFromGroupKey(String groupKey) {
        if (groupKey == null) return "";
        String normalized = groupKey.trim().toLowerCase(Locale.ROOT);
        if (normalized.isBlank()) return "";
        int atIdx = normalized.indexOf('@');
        if (atIdx > 0) normalized = normalized.substring(0, atIdx);
        int slashIdx = normalized.lastIndexOf('/');
        if (slashIdx >= 0 && slashIdx + 1 < normalized.length()) {
            normalized = normalized.substring(slashIdx + 1);
        }
        normalized = normalized.replaceAll("[^a-z0-9._-]+", "-");
        normalized = normalized.replaceAll("^-+|-+$", "");
        return normalized;
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

    @Override public void action(AuthenticationFlowContext ctx) { }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) { }
    @Override public void close() { }
}
