package systems.suncoast.kc.membership;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public interface IdpMembershipResolver {
    String source();

    IdpMembershipResult resolve(KeycloakSession session, RealmModel realm, UserModel user);
}
