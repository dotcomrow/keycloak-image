package systems.suncoast.kc.google;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class GoogleGroupsAuthenticator implements Authenticator {
    private static final Logger LOG = Logger.getLogger(GoogleGroupsAuthenticator.class);
    private static final String ATTR_GROUPS = "ggl.groups";
    private static final String ATTR_TS     = "ggl.cachedAt";
    private static final long   TTL_SECONDS = 600; // adjust as desired

    @Override
    public void authenticate(AuthenticationFlowContext ctx) {
        UserModel user = ctx.getUser();
        if (user == null) { ctx.attempted(); return; }
        String email = user.getEmail();
        if (email == null || email.isBlank()) { ctx.attempted(); return; }

        long now = Instant.now().getEpochSecond();
        String cachedAt = user.getFirstAttribute(ATTR_TS);
        if (cachedAt != null) {
            try {
                if (now - Long.parseLong(cachedAt) < TTL_SECONDS) {
                    ctx.success(); return;
                }
            } catch (NumberFormatException ignore) { /* fall through */ }
        }

        try {
            // TODO: implement using your service-account + domain-wide delegation
            // List<String> groups = GoogleDirectoryClient.forSession(ctx).groupsForUser(email);
            List<String> groups = fetchGroupsStub(email); // replace with real call

            // Map to roles (compact) or join KC groups; here we create realm roles with prefix.
            RealmModel realm = ctx.getRealm();
            for (String g : groups) {
                String roleName = "ggl:" + slug(g);
                var role = realm.getRole(roleName);
                if (role == null) role = ctx.getSession().roles().addRealmRole(realm, roleName);
                user.grantRole(role);
            }
            user.setAttribute(ATTR_GROUPS, groups);
            user.setSingleAttribute(ATTR_TS, Long.toString(now));

            ctx.success();
        } catch (Exception e) {
            // Log it
            LOG.warnf(e, "Google group lookup failed for email=%s", email);

            // Attach a detail to the login event (if available)
            EventBuilder ev = ctx.getEvent();
            if (ev != null) {
                ev.detail("google_groups_error", e.getClass().getSimpleName());
            }

            // continue or fail closed—your policy
            ctx.success();
        }
    }

    private static List<String> fetchGroupsStub(String email) {
        return new ArrayList<>(); // replace with API result
    }
    private static String slug(String s) {
        return s.toLowerCase().replaceAll("[^a-z0-9]+","-").replaceAll("(^-|-$)", "");
    }

    @Override public void action(AuthenticationFlowContext ctx) { }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) { }
    @Override public void close() { }
}
