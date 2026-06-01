package systems.suncoast.kc.github;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import systems.suncoast.kc.membership.GitHubMembershipResolver;
import systems.suncoast.kc.membership.IdpMembershipResult;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Resolves GitHub team membership and stores it on the user as transient metadata.
 *
 * This authenticator intentionally does not create, grant, or revoke Keycloak role mappings.
 * Roles are derived dynamically from current IdP membership by the shared membership resolver.
 */
public class GitHubTeamAdminAuthenticator implements Authenticator {
    private static final Logger LOG = Logger.getLogger(GitHubTeamAdminAuthenticator.class);
    private static final GitHubMembershipResolver RESOLVER = new GitHubMembershipResolver();

    private static final String ATTR_TEAMS = "gh.teams";
    private static final String ATTR_ROLES = "gh.roles";

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

            IdpMembershipResult github = RESOLVER.resolve(session, realm, user);

            if (github != null) {
                user.setAttribute(ATTR_TEAMS, toMutableList(github.membershipsList()));
                user.setAttribute(ATTR_ROLES, toMutableList(github.rolesList()));
                LOG.infof(
                        "GitHub membership resolved for user=%s attempted=%s success=%s teams=%d roles=%d message=%s",
                        user.getUsername(),
                        github.attempted(),
                        github.success(),
                        github.memberships().size(),
                        github.roles().size(),
                        github.message()
                );
            } else {
                user.setAttribute(ATTR_TEAMS, Collections.emptyList());
                user.setAttribute(ATTR_ROLES, Collections.emptyList());
                LOG.warnf("GitHub membership resolver result missing for user=%s", user.getUsername());
            }

            ctx.success();
        } catch (Exception e) {
            LOG.error("GitHubTeamAdminAuthenticator failed; keeping flow non-blocking.", e);
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
