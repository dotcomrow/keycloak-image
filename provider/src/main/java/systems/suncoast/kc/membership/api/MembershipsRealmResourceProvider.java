package systems.suncoast.kc.membership.api;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class MembershipsRealmResourceProvider implements RealmResourceProvider {
    private final KeycloakSession session;

    public MembershipsRealmResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new MembershipsResource(session);
    }

    @Override
    public void close() {
    }
}
