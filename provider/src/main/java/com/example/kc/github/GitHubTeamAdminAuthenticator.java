package com.example.kc.github;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.*;
import org.jboss.logging.Logger;

import java.util.Set;
import java.util.stream.Collectors;

public class GitHubTeamAdminAuthenticator implements Authenticator {
    private static final Logger LOG = Logger.getLogger(GitHubTeamAdminAuthenticator.class);

    // Config via env to keep container-only proof simple
    private static String wantOrg()  { return System.getenv().getOrDefault("GITHUB_ORG", "").trim(); }
    private static String wantTeam() { return System.getenv().getOrDefault("GITHUB_TEAM", "").trim(); }
    private static boolean debugAlwaysGrant() {
        return "true".equalsIgnoreCase(System.getenv().getOrDefault("DEBUG_ALWAYS_GRANT", "false"));
    }

    @Override
    public void authenticate(AuthenticationFlowContext ctx) {
        try {
            UserModel user = ctx.getUser();
            RealmModel realm = ctx.getRealm();
            KeycloakSession session = ctx.getSession();

            ClientModel rm = realm.getClientByClientId("realm-management");
            if (rm == null) { LOG.warn("realm-management client not found"); ctx.success(); return; }
            RoleModel adminRole = rm.getRole("realm-admin");
            if (adminRole == null) { LOG.warn("realm-admin role not found"); ctx.success(); return; }

            if (debugAlwaysGrant()) {
                LOG.info("DEBUG_ALWAYS_GRANT=true → granting realm-admin unconditionally");
                ensureOnlyIfMember(user, adminRole, true);
                ctx.success();
                return;
            }

            String org = wantOrg();
            String team = wantTeam();
            if (org.isEmpty() || team.isEmpty()) {
                LOG.warn("GITHUB_ORG or GITHUB_TEAM not set; skipping.");
                ctx.success(); return;
            }

            // Pull broker token from federated identity "github"
            BrokeredIdentityContext fed = session.users().getFederatedIdentitiesStream(realm, user)
                    .filter(id -> "github".equals(id.getIdentityProvider()))
                    .map(id -> new BrokeredIdentityContext(id.getUserId())) // just a handle
                    .findFirst().orElse(null);

            String token = null;
            if (fed != null) {
                // keycloak stores token as federated token; simpler path: use user federation link
                // Here we fetch via UserSession notes is not trivial; instead query the social store:
                FederatedIdentityModel fi = session.users().getFederatedIdentity(realm, user, "github");
                if (fi != null) token = fi.getToken();
            }

            if (token == null || token.isBlank()) {
                LOG.info("No GitHub token on federated identity; skipping role grant.");
                ctx.success(); return;
            }

            // Call GitHub API
            var resp = SimpleHttp.doGet("https://api.github.com/user/teams", session)
                    .header("Authorization", "Bearer " + token)
                    .asJson();

            boolean isMember = false;
            var it = resp.elements();
            while (it.hasNext()) {
                var t = it.next();
                String slug = t.get("slug").asText("");
                String o = t.get("organization").get("login").asText("");
                LOG.debugf("Team seen: %s/%s", o, slug);
                if (team.equalsIgnoreCase(slug) && org.equalsIgnoreCase(o)) { isMember = true; break; }
            }

            ensureOnlyIfMember(user, adminRole, isMember);
            ctx.success();
        } catch (Exception e) {
            LOG.error("Error in GitHubTeamAdminAuthenticator", e);
            ctx.success(); // do not block login on failure
        }
    }

    private void ensureOnlyIfMember(UserModel user, RoleModel adminRole, boolean isMember) {
        Set<RoleModel> current = user.getRoleMappingsStream().collect(Collectors.toSet());
        boolean has = current.contains(adminRole);

        if (isMember && !has) {
            user.grantRole(adminRole);
            LOG.infof("Granted realm-admin to %s", user.getUsername());
        } else if (!isMember && has) {
            user.deleteRoleMapping(adminRole);
            LOG.infof("Removed realm-admin from %s", user.getUsername());
        } else {
            LOG.debugf("No change for %s (member=%s, has=%s)", user.getUsername(), isMember, has);
        }
    }

    @Override public void action(AuthenticationFlowContext ctx) { }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) { }
    @Override public void close() { }
}
