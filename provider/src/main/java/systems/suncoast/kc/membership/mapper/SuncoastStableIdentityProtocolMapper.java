package systems.suncoast.kc.membership.mapper;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.TokenIntrospectionTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Emits a rebuild-stable Suncoast subject instead of exposing Keycloak's
 * database-generated user UUID as an application identity.
 */
public class SuncoastStableIdentityProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper, TokenIntrospectionTokenMapper {
    public static final String PROVIDER_ID = "suncoast-stable-identity-mapper";
    public static final String DEFAULT_CLAIM_NAME = "suncoast_identity_id";

    private static final String GOOGLE_SUB_ATTRIBUTE = "google_sub";
    private static final String GITHUB_ID_ATTRIBUTE = "github_id";
    private static final String SERVICE_ACCOUNT_PREFIX = "service-account-";
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(CONFIG_PROPERTIES);
        OIDCAttributeMapperHelper.addJsonTypeConfig(CONFIG_PROPERTIES);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG_PROPERTIES, SuncoastStableIdentityProtocolMapper.class);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Suncoast stable identity";
    }

    @Override
    public String getHelpText() {
        return "Emits a stable identity derived from the external IdP subject or service client instead of the Keycloak user UUID.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token,
                                            ProtocolMapperModel mappingModel,
                                            KeycloakSession session,
                                            UserSessionModel userSession,
                                            ClientSessionContext clientSessionCtx) {
        if (include(mappingModel, OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, true)) {
            setIdentityClaim(token, mappingModel, session, userSession);
        }
        return token;
    }

    @Override
    public IDToken transformIDToken(IDToken token,
                                    ProtocolMapperModel mappingModel,
                                    KeycloakSession session,
                                    UserSessionModel userSession,
                                    ClientSessionContext clientSessionCtx) {
        if (include(mappingModel, OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, true)) {
            setIdentityClaim(token, mappingModel, session, userSession);
        }
        return token;
    }

    @Override
    public AccessToken transformUserInfoToken(AccessToken token,
                                              ProtocolMapperModel mappingModel,
                                              KeycloakSession session,
                                              UserSessionModel userSession,
                                              ClientSessionContext clientSessionCtx) {
        if (include(mappingModel, OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, true)) {
            setIdentityClaim(token, mappingModel, session, userSession);
        }
        return token;
    }

    @Override
    public AccessToken transformIntrospectionToken(AccessToken token,
                                                   ProtocolMapperModel mappingModel,
                                                   KeycloakSession session,
                                                   UserSessionModel userSession,
                                                   ClientSessionContext clientSessionCtx) {
        if (include(mappingModel, OIDCAttributeMapperHelper.INCLUDE_IN_INTROSPECTION, true)) {
            setIdentityClaim(token, mappingModel, session, userSession);
        }
        return token;
    }

    private void setIdentityClaim(IDToken token,
                                  ProtocolMapperModel mappingModel,
                                  KeycloakSession session,
                                  UserSessionModel userSession) {
        if (token == null || userSession == null || userSession.getUser() == null) {
            return;
        }
        String identity = stableIdentity(userSession.getUser(), session.getContext().getRealm());
        if (!identity.isBlank()) {
            OIDCAttributeMapperHelper.mapClaim(token, mappingModel, identity);
        }
    }

    static String stableIdentity(UserModel user, RealmModel realm) {
        String realmName = realm == null ? "unknown" : clean(realm.getName());
        String googleSub = clean(user.getFirstAttribute(GOOGLE_SUB_ATTRIBUTE));
        String githubId = clean(user.getFirstAttribute(GITHUB_ID_ATTRIBUTE));

        if ("external".equals(realmName) && !googleSub.isBlank()) {
            return "google:" + googleSub;
        }
        if (("internal".equals(realmName) || "master".equals(realmName)) && !githubId.isBlank()) {
            return "github:" + githubId;
        }
        if (!googleSub.isBlank()) {
            return "google:" + googleSub;
        }
        if (!githubId.isBlank()) {
            return "github:" + githubId;
        }

        String username = clean(user.getUsername());
        if (username.startsWith(SERVICE_ACCOUNT_PREFIX) && username.length() > SERVICE_ACCOUNT_PREFIX.length()) {
            return "service:" + realmName + ":" + username.substring(SERVICE_ACCOUNT_PREFIX.length());
        }
        return username.isBlank() ? "" : "local:" + realmName + ":" + username;
    }

    private static String clean(String value) {
        return value == null ? "" : value.trim();
    }

    private boolean include(ProtocolMapperModel mappingModel, String key, boolean defaultValue) {
        Map<String, String> config = mappingModel.getConfig();
        if (config == null || !config.containsKey(key)) {
            return defaultValue;
        }
        return Boolean.parseBoolean(config.get(key));
    }

    @Override
    public String getProtocol() {
        return OIDCLoginProtocol.LOGIN_PROTOCOL;
    }
}
