package systems.suncoast.kc.google;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import systems.suncoast.kc.membership.GoogleMembershipResolver;
import systems.suncoast.kc.membership.IdpMembershipResult;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Resolves Google group memberships and stores the current snapshot on user attributes.
 *
 * This authenticator intentionally avoids persisting role mappings in Keycloak.
 */
public class GoogleGroupsAuthenticator implements Authenticator {
    private static final Logger LOG = Logger.getLogger(GoogleGroupsAuthenticator.class);
    private static final GoogleMembershipResolver RESOLVER = new GoogleMembershipResolver();

    private static final String ATTR_GROUPS = "ggl.groups";
    private static final String ATTR_ROLES = "ggl.roles";
    private static final String ATTR_TS = "ggl.cachedAt";

    @Override
    public void authenticate(AuthenticationFlowContext ctx) {
        try {
            KeycloakSession session = ctx.getSession();
            RealmModel realm = ctx.getRealm();
            UserModel user = ctx.getUser();

            if (user == null) {
                ctx.attempted();
                return;
            }

            IdpMembershipResult google = RESOLVER.resolve(session, realm, user);

            if (google != null) {
                user.setAttribute(ATTR_GROUPS, toMutableList(google.membershipsList()));
                user.setAttribute(ATTR_ROLES, toMutableList(google.rolesList()));
                user.setSingleAttribute(ATTR_TS, Long.toString(Instant.now().getEpochSecond()));
                LOG.infof(
                        "Google membership resolved for user=%s attempted=%s success=%s groups=%d roles=%d message=%s",
                        user.getUsername(),
                        google.attempted(),
                        google.success(),
                        google.memberships().size(),
                        google.roles().size(),
                        google.message()
                );
            } else {
                user.setAttribute(ATTR_GROUPS, Collections.emptyList());
                user.setAttribute(ATTR_ROLES, Collections.emptyList());
                user.setSingleAttribute(ATTR_TS, Long.toString(Instant.now().getEpochSecond()));
                LOG.warnf("Google membership resolver result missing for user=%s", user.getUsername());
            }

            ctx.success();
        } catch (Exception e) {
            LOG.warn("GoogleGroupsAuthenticator failed; keeping flow non-blocking", e);
            ctx.success();
        }
    }

    private static List<String> toMutableList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return new ArrayList<>();
        }
        return new ArrayList<>(values);
    }

    @Override
    public void action(AuthenticationFlowContext ctx) {
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
