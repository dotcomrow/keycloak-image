package systems.suncoast.kc.membership;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.ServiceAccountCredentials;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class GoogleMembershipResolver implements IdpMembershipResolver {
    private static final Logger LOG = Logger.getLogger(GoogleMembershipResolver.class);

    private static final String SCOPE_GROUPS = "https://www.googleapis.com/auth/admin.directory.group.readonly";
    private static final String SCOPE_MEMBERS = "https://www.googleapis.com/auth/admin.directory.group.member.readonly";
    private static final List<String> SCOPES = List.of(SCOPE_GROUPS, SCOPE_MEMBERS);

    private static final Object TOKEN_LOCK = new Object();
    private static volatile ServiceAccountCredentials cachedCreds;
    private static volatile AccessToken cachedToken;

    private static final class HttpResp {
        final int status;
        final String body;

        private HttpResp(int status, String body) {
            this.status = status;
            this.body = body;
        }
    }

    @Override
    public String source() {
        return "google";
    }

    @Override
    public IdpMembershipResult resolve(KeycloakSession session, RealmModel realm, UserModel user) {
        String email = user == null ? "" : safe(user.getEmail());
        if (email.isBlank()) {
            return IdpMembershipResult.skipped(source(), "user has no email; google lookup skipped");
        }
        if (adminEmail().isBlank()) {
            return IdpMembershipResult.skipped(source(), "GOOGLE_ADMIN_EMAIL not configured");
        }
        if (saJsonPath().isBlank() && saJsonInline().isBlank()) {
            return IdpMembershipResult.skipped(source(), "GOOGLE_SA_JSON_PATH/GOOGLE_SA_JSON not configured");
        }

        try {
            Set<String> groups = fetchGroupsForUser(session, email);
            Set<String> roles = new LinkedHashSet<>();
            for (String group : groups) {
                String role = RoleNameNormalizer.fromGoogleGroupKey(group);
                if (!role.isBlank()) {
                    roles.add(role);
                }
            }

            return IdpMembershipResult.success(
                    source(),
                    "resolved google group memberships",
                    groups,
                    roles
            );
        } catch (Exception e) {
            LOG.warnf(e, "Google membership resolution failed for email=%s", email);
            return IdpMembershipResult.failed(source(), "google membership lookup failed: " + e.getClass().getSimpleName());
        }
    }

    private Set<String> fetchGroupsForUser(KeycloakSession session, String email) throws Exception {
        Set<String> groups = new LinkedHashSet<>();
        String pageToken = null;
        Set<String> seenPageTokens = new LinkedHashSet<>();

        while (true) {
            HttpResp resp = directoryGroupsForUser(session, accessToken(false), email, pageToken);
            if (resp.status == 401) {
                resp = directoryGroupsForUser(session, accessToken(true), email, pageToken);
            }

            if (resp.status == 404) {
                return groups;
            }
            if (resp.status / 100 != 2) {
                throw new IllegalStateException("google groups.list failed with status " + resp.status);
            }

            JsonNode root = parseJsonQuiet(resp.body);
            if (root == null) {
                throw new IllegalStateException("google groups.list returned invalid json");
            }

            JsonNode list = root.path("groups");
            if (list.isArray()) {
                for (var it = list.elements(); it.hasNext(); ) {
                    JsonNode group = it.next();
                    String key = safe(group.path("email").asText(""));
                    if (key.isBlank()) {
                        key = safe(group.path("name").asText(""));
                    }
                    if (!key.isBlank()) {
                        groups.add(key.toLowerCase(Locale.ROOT));
                    }
                }
            }

            String next = safe(root.path("nextPageToken").asText(""));
            if (next.isBlank() || !seenPageTokens.add(next)) {
                return groups;
            }
            pageToken = next;
        }
    }

    private HttpResp directoryGroupsForUser(KeycloakSession session, String token, String userEmail, String pageToken) throws Exception {
        StringBuilder url = new StringBuilder(
                "https://admin.googleapis.com/admin/directory/v1/groups?userKey="
                        + urlEncode(userEmail)
                        + "&maxResults=200"
        );
        if (pageToken != null && !pageToken.isBlank()) {
            url.append("&pageToken=").append(urlEncode(pageToken));
        }

        SimpleHttp req = SimpleHttp.doGet(url.toString(), session)
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
            AccessToken token = creds.refreshAccessToken();
            cachedToken = token;
            return token.getTokenValue();
        }
    }

    private static ServiceAccountCredentials serviceAccountCreds() throws Exception {
        ServiceAccountCredentials creds = cachedCreds;
        if (creds != null) {
            return creds;
        }

        synchronized (TOKEN_LOCK) {
            if (cachedCreds != null) {
                return cachedCreds;
            }

            String subject = adminEmail();
            if (subject.isBlank()) {
                throw new IllegalStateException("GOOGLE_ADMIN_EMAIL (or GOOGLE_DELEGATED_ADMIN) is required");
            }

            try (InputStream in = serviceAccountStream()) {
                if (in == null) {
                    throw new IllegalStateException("GOOGLE_SA_JSON_PATH or GOOGLE_SA_JSON is required");
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
        if (!path.isBlank()) {
            return new FileInputStream(path);
        }
        String json = saJsonInline();
        if (!json.isBlank()) {
            return new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8));
        }
        return null;
    }

    private static String adminEmail() {
        return getenv("GOOGLE_ADMIN_EMAIL", getenv("GOOGLE_DELEGATED_ADMIN", "")).trim();
    }

    private static String saJsonPath() {
        return getenv("GOOGLE_SA_JSON_PATH", "").trim();
    }

    private static String saJsonInline() {
        return getenv("GOOGLE_SA_JSON", "").trim();
    }

    private static String getenv(String key, String defaultValue) {
        String value = System.getenv(key);
        return value != null ? value : defaultValue;
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }

    private static String urlEncode(String value) {
        String encoded = URLEncoder.encode(value, StandardCharsets.UTF_8);
        return encoded.replace("+", "%20");
    }

    private static JsonNode parseJsonQuiet(String body) {
        try {
            return org.keycloak.util.JsonSerialization.mapper.readTree(body);
        } catch (Exception ignored) {
            return null;
        }
    }
}
