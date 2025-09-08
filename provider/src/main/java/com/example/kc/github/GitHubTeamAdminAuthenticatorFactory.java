package com.example.kc.github;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import java.util.List;

public class GitHubTeamAdminAuthenticatorFactory implements AuthenticatorFactory {

    public static final String ID = "github-team-admin";
    private static final GitHubTeamAdminAuthenticator SINGLETON = new GitHubTeamAdminAuthenticator();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayType() {
        return "GitHub Team Admin";
    }

    @Override
    public String getReferenceCategory() {
        return "Post Broker Login";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Grants realm-admin to users who meet GitHub team membership criteria (stub in CI).";
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) { }

    @Override
    public void postInit(KeycloakSessionFactory factory) { }

    @Override
    public void close() { }

    @Override
    public List<org.keycloak.provider.ProviderConfigProperty> getConfigProperties() {
        return java.util.Collections.emptyList();
    }

    @Override
    public org.keycloak.models.AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new org.keycloak.models.AuthenticationExecutionModel.Requirement[]{
            org.keycloak.models.AuthenticationExecutionModel.Requirement.REQUIRED,
            org.keycloak.models.AuthenticationExecutionModel.Requirement.DISABLED
        };
    }
}
