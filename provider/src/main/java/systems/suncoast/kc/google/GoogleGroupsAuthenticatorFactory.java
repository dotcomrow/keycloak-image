package systems.suncoast.kc.google;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

@AutoService(AuthenticatorFactory.class)
public class GoogleGroupsAuthenticatorFactory implements AuthenticatorFactory {
    public static final String ID = "google-groups-authenticator"; // <-- use this in kcadm

    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "Google Groups (by email)"; }
    @Override public String getHelpText() { return "Fetches Google Workspace groups by user email at login."; }
    @Override public boolean isConfigurable() { return false; } // flip to true if you add per-exec config
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public Authenticator create(KeycloakSession session) { return new GoogleGroupsAuthenticator(); }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override public List<ProviderConfigProperty> getConfigProperties() { return Collections.emptyList(); }
    @Override public String getReferenceCategory() { return null; }
}
