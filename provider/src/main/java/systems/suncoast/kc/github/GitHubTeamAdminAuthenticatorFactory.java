package systems.suncoast.kc.github;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.provider.ProviderConfigProperty;
import java.util.List;
import com.google.auto.service.AutoService;

@AutoService(AuthenticatorFactory.class)
public class GitHubTeamAdminAuthenticatorFactory implements AuthenticatorFactory {
    public static final String ID = "github-team-admin";

    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "GitHub Team → realm-admin"; }
    @Override public String getHelpText() { return "Grants realm-admin if user is in configured GitHub org/team"; }
    @Override public boolean isConfigurable() { return false; }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public Authenticator create(KeycloakSession session) { return new GitHubTeamAdminAuthenticator(); }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return java.util.Collections.emptyList();
    }
}
