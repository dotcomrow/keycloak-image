package systems.suncoast.kc.membership.api;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import systems.suncoast.kc.membership.IdpMembershipResult;
import systems.suncoast.kc.membership.MembershipResolution;
import systems.suncoast.kc.membership.MembershipResolverService;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Path("")
public class MembershipsResource {
    private static final Logger LOG = Logger.getLogger(MembershipsResource.class);

    private final KeycloakSession session;

    public MembershipsResource(KeycloakSession session) {
        this.session = session;
    }

    @GET
    @Path("me")
    @Produces(MediaType.APPLICATION_JSON)
    public Response me() {
        RealmModel realm = session.getContext().getRealm();
        if (realm == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "realm context missing"))
                    .build();
        }

        AuthenticationManager.AuthResult auth = authenticate(realm);
        if (auth == null || auth.getUser() == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of("error", "unauthorized"))
                    .build();
        }

        UserModel user = auth.getUser();
        MembershipResolution resolution = MembershipResolverService.resolve(session, realm, user);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("resolvedAt", Instant.now().toString());
        payload.put("realm", realm.getName());

        Map<String, Object> userData = new LinkedHashMap<>();
        userData.put("id", user.getId());
        userData.put("username", user.getUsername());
        userData.put("email", user.getEmail());
        payload.put("user", userData);

        payload.put("roles", resolution.rolesList());
        payload.put("rolesCount", resolution.roles().size());

        List<Map<String, Object>> sources = new ArrayList<>();
        for (IdpMembershipResult source : resolution.sources()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("source", source.source());
            item.put("attempted", source.attempted());
            item.put("success", source.success());
            item.put("message", source.message());
            item.put("memberships", source.membershipsList());
            item.put("membershipCount", source.memberships().size());
            item.put("roles", source.rolesList());
            item.put("roleCount", source.roles().size());
            sources.add(item);
        }
        payload.put("sources", sources);

        return Response.ok(payload).build();
    }

    private AuthenticationManager.AuthResult authenticate(RealmModel realm) {
        try {
            AuthenticationManager.AuthResult bearer = new AppAuthManager.BearerTokenAuthenticator(session)
                    .setRealm(realm)
                    .setConnection(session.getContext().getConnection())
                    .setHeaders(session.getContext().getRequestHeaders())
                    .authenticate();
            if (bearer != null) {
                return bearer;
            }
        } catch (Exception e) {
            LOG.debug("Bearer authentication failed for membership endpoint", e);
        }

        try {
            return new AppAuthManager().authenticateIdentityCookie(session, realm);
        } catch (Exception e) {
            LOG.debug("Identity cookie authentication failed for membership endpoint", e);
            return null;
        }
    }
}
