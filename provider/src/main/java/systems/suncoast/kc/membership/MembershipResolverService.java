package systems.suncoast.kc.membership;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class MembershipResolverService {
    private static final Logger LOG = Logger.getLogger(MembershipResolverService.class);

    private static final List<IdpMembershipResolver> RESOLVERS = List.of(
            new GitHubMembershipResolver(),
            new GoogleMembershipResolver()
    );

    private MembershipResolverService() {
    }

    public static MembershipResolution resolve(KeycloakSession session, RealmModel realm, UserModel user) {
        Set<String> roles = new LinkedHashSet<>();
        List<IdpMembershipResult> sourceResults = new ArrayList<>();

        for (IdpMembershipResolver resolver : RESOLVERS) {
            if (!isEnabled(resolver.source())) {
                sourceResults.add(IdpMembershipResult.skipped(resolver.source(), "resolver disabled by environment"));
                continue;
            }

            IdpMembershipResult result = resolver.resolve(session, realm, user);
            sourceResults.add(result);
            roles.addAll(result.roles());
        }

        MembershipResolution resolution = new MembershipResolution(roles, sourceResults);
        LOG.infof("Membership resolution complete for user=%s realm=%s sources=%d roles=%d",
                user == null ? "" : user.getUsername(),
                realm == null ? "" : realm.getName(),
                sourceResults.size(),
                resolution.roles().size());

        return resolution;
    }

    private static boolean isEnabled(String source) {
        if ("github".equalsIgnoreCase(source)) {
            return isTrue("GITHUB_MEMBERSHIP_ENABLED", true);
        }
        if ("google".equalsIgnoreCase(source)) {
            return isTrue("GOOGLE_MEMBERSHIP_ENABLED", true);
        }
        return true;
    }

    private static boolean isTrue(String key, boolean defaultValue) {
        String raw = System.getenv(key);
        if (raw == null || raw.isBlank()) {
            return defaultValue;
        }
        return "true".equalsIgnoreCase(raw) || "1".equals(raw);
    }
}
