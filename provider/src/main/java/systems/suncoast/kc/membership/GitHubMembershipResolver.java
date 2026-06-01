package systems.suncoast.kc.membership;

import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

public class GitHubMembershipResolver implements IdpMembershipResolver {
    private static final Logger LOG = Logger.getLogger(GitHubMembershipResolver.class);

    private enum AuthScheme { BEARER, TOKEN }

    private static final class AccessToken {
        final String token;
        final AuthScheme preferredScheme;

        private AccessToken(String token, AuthScheme preferredScheme) {
            this.token = token;
            this.preferredScheme = preferredScheme;
        }
    }

    private static final class HttpResp {
        final int status;
        final String body;
        final AuthScheme schemeUsed;

        private HttpResp(int status, String body, AuthScheme schemeUsed) {
            this.status = status;
            this.body = body;
            this.schemeUsed = schemeUsed;
        }
    }

    @Override
    public String source() {
        return "github";
    }

    @Override
    public IdpMembershipResult resolve(KeycloakSession session, RealmModel realm, UserModel user) {
        try {
            FederatedIdentityModel identity = session.users().getFederatedIdentity(realm, user, "github");
            if (identity == null) {
                return IdpMembershipResult.skipped(source(), "no github federated identity for user");
            }

            AccessToken token = extractGithubAccessToken(identity);
            if (token == null || token.token == null || token.token.isBlank()) {
                return IdpMembershipResult.failed(source(), "github federated identity has no usable access token");
            }

            Set<String> teams = fetchTeams(session, token);
            Set<String> roles = new LinkedHashSet<>();
            for (String team : teams) {
                String role = RoleNameNormalizer.fromGitHubTeamKey(team);
                if (!role.isBlank()) {
                    roles.add(role);
                }
            }

            return IdpMembershipResult.success(
                    source(),
                    "resolved github team memberships",
                    teams,
                    roles
            );
        } catch (Exception e) {
            LOG.warnf(e, "GitHub membership resolution failed for user=%s", user == null ? "" : user.getUsername());
            return IdpMembershipResult.failed(source(), "github membership lookup failed: " + e.getClass().getSimpleName());
        }
    }

    private Set<String> fetchTeams(KeycloakSession session, AccessToken token) throws Exception {
        Set<String> out = new LinkedHashSet<>();
        int page = 1;
        while (page <= 20) {
            String url = "https://api.github.com/user/teams?per_page=100&page=" + page;
            HttpResp resp = ghGetTryBoth(session, token, url);

            if (resp.status == 401) {
                throw new IllegalStateException("github token rejected by /user/teams");
            }
            if (resp.status / 100 != 2) {
                throw new IllegalStateException("github /user/teams request failed with status " + resp.status);
            }

            JsonNode node = parseJsonQuiet(resp.body);
            if (node == null || !node.isArray()) {
                throw new IllegalStateException("github /user/teams response was not an array");
            }

            int seen = 0;
            for (var it = node.elements(); it.hasNext(); ) {
                JsonNode team = it.next();
                seen++;
                String slug = team.path("slug").asText("").trim();
                String org = team.path("organization").path("login").asText("").trim();
                if (!slug.isBlank() && !org.isBlank()) {
                    out.add((org + "/" + slug).toLowerCase(Locale.ROOT));
                }
            }

            if (seen < 100) {
                break;
            }
            page++;
        }

        return out;
    }

    private static AccessToken extractGithubAccessToken(FederatedIdentityModel identity) {
        String raw = identity.getToken();
        if (raw == null || raw.isBlank()) {
            return null;
        }

        // JSON payload: {"access_token":"...", "token_type":"bearer"}
        if (raw.startsWith("{")) {
            JsonNode node = parseJsonQuiet(raw);
            if (node != null) {
                String token = orNull(node.path("access_token").asText());
                String tokenType = orNull(node.path("token_type").asText());
                if (token != null) {
                    AuthScheme scheme = "token".equalsIgnoreCase(tokenType) ? AuthScheme.TOKEN : AuthScheme.BEARER;
                    return new AccessToken(token, scheme);
                }
            }
        }

        // URL encoded payload: access_token=...&token_type=bearer
        if (raw.startsWith("access_token=")) {
            String token = null;
            String tokenType = null;
            for (String pair : raw.split("&")) {
                int idx = pair.indexOf('=');
                if (idx <= 0) {
                    continue;
                }
                String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
                String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
                if ("access_token".equalsIgnoreCase(key)) {
                    token = value;
                } else if ("token_type".equalsIgnoreCase(key)) {
                    tokenType = value;
                }
            }
            if (token != null) {
                AuthScheme scheme = "token".equalsIgnoreCase(tokenType) ? AuthScheme.TOKEN : AuthScheme.BEARER;
                return new AccessToken(token, scheme);
            }
        }

        return new AccessToken(raw, AuthScheme.BEARER);
    }

    private HttpResp ghGetTryBoth(KeycloakSession session, AccessToken token, String url) throws Exception {
        HttpResp first = ghGet(session, token.token, token.preferredScheme, url);
        if (first.status != 401) {
            return first;
        }

        AuthScheme alternate = token.preferredScheme == AuthScheme.BEARER ? AuthScheme.TOKEN : AuthScheme.BEARER;
        HttpResp second = ghGet(session, token.token, alternate, url);
        return second.status == 401 ? first : second;
    }

    private HttpResp ghGet(KeycloakSession session, String token, AuthScheme scheme, String url) throws Exception {
        SimpleHttp req = SimpleHttp.doGet(url, session)
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", userAgent());

        String version = apiVersion();
        if (!version.isBlank()) {
            req.header("X-GitHub-Api-Version", version);
        }

        String authHeader = (scheme == AuthScheme.TOKEN ? "token " : "Bearer ") + token;
        req.header("Authorization", authHeader);

        var resp = req.asResponse();
        return new HttpResp(resp.getStatus(), resp.asString(), scheme);
    }

    private static String getenv(String key, String defaultValue) {
        String value = System.getenv(key);
        return value != null ? value : defaultValue;
    }

    private static String apiVersion() {
        return getenv("GITHUB_API_VERSION", "").trim();
    }

    private static String userAgent() {
        return getenv("GITHUB_USER_AGENT", "keycloak-github-membership-resolver/1.0").trim();
    }

    private static JsonNode parseJsonQuiet(String body) {
        try {
            return org.keycloak.util.JsonSerialization.mapper.readTree(body);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static String orNull(String value) {
        if (value == null || value.isBlank() || "null".equalsIgnoreCase(value)) {
            return null;
        }
        return value;
    }
}
