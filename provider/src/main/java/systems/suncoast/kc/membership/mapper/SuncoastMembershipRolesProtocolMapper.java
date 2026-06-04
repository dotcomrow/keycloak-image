package systems.suncoast.kc.membership.mapper;

import org.jboss.logging.Logger;
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
import systems.suncoast.kc.membership.MembershipAttributeCache;
import systems.suncoast.kc.membership.MembershipResolution;
import systems.suncoast.kc.membership.MembershipResolverService;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

public class SuncoastMembershipRolesProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper, TokenIntrospectionTokenMapper {
    public static final String PROVIDER_ID = "suncoast-membership-roles-mapper";
    public static final String CACHE_TTL_SECONDS = "cache.ttl.seconds";
    public static final String DEFAULT_CLAIM_NAME = "suncoast_roles";
    public static final String DEFAULT_CACHE_TTL_SECONDS = "300";

    private static final Logger LOG = Logger.getLogger(SuncoastMembershipRolesProtocolMapper.class);
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(CONFIG_PROPERTIES);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG_PROPERTIES, SuncoastMembershipRolesProtocolMapper.class);
        CONFIG_PROPERTIES.add(new ProviderConfigProperty(
                CACHE_TTL_SECONDS,
                "Membership cache TTL seconds",
                "How long cached IdP membership roles may be reused before refreshing during token issuance. Use 0 to refresh every token issuance.",
                ProviderConfigProperty.INTEGER_TYPE,
                DEFAULT_CACHE_TTL_SECONDS
        ));
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
        return "Suncoast IdP membership roles";
    }

    @Override
    public String getHelpText() {
        return "Emits roles derived from cached GitHub/Google IdP memberships and refreshes that cache on token issuance when stale.";
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
            setMembershipClaim(token, mappingModel, session, userSession);
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
            setMembershipClaim(token, mappingModel, session, userSession);
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
            setMembershipClaim(token, mappingModel, session, userSession);
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
            setMembershipClaim(token, mappingModel, session, userSession);
        }
        return token;
    }

    private void setMembershipClaim(IDToken token,
                                    ProtocolMapperModel mappingModel,
                                    KeycloakSession session,
                                    UserSessionModel userSession) {
        if (token == null || userSession == null || userSession.getUser() == null) {
            return;
        }

        UserModel user = userSession.getUser();
        refreshCacheIfStale(session, user, ttlSeconds(mappingModel));
        List<String> roles = MembershipAttributeCache.readCachedRoles(user)
                .stream()
                .filter(role -> role != null && !role.isBlank())
                .map(String::trim)
                .sorted(Comparator.naturalOrder())
                .toList();
        token.setOtherClaims(claimName(mappingModel), roles);
    }

    private void refreshCacheIfStale(KeycloakSession session, UserModel user, long ttlSeconds) {
        if (!MembershipAttributeCache.isStale(user, ttlSeconds)) {
            return;
        }

        try {
            RealmModel realm = session.getContext().getRealm();
            MembershipResolution resolution = MembershipResolverService.resolve(session, realm, user);
            MembershipAttributeCache.storeResolution(user, resolution);
            LOG.infof("Refreshed Suncoast membership role cache for user=%s roles=%d ttl=%d",
                    user.getUsername(), resolution.roles().size(), ttlSeconds);
        } catch (Exception e) {
            LOG.warnf(e, "Failed to refresh Suncoast membership role cache for user=%s", user.getUsername());
            user.setAttribute(MembershipAttributeCache.ATTR_SUNCOAST_ROLES, List.of());
            user.setSingleAttribute(MembershipAttributeCache.ATTR_SUNCOAST_TS, Long.toString(System.currentTimeMillis() / 1000L));
        }
    }

    private String claimName(ProtocolMapperModel mappingModel) {
        Map<String, String> config = mappingModel.getConfig();
        String configured = config == null ? "" : config.getOrDefault(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, "");
        if (configured == null || configured.isBlank()) {
            return DEFAULT_CLAIM_NAME;
        }
        return configured.trim();
    }

    private long ttlSeconds(ProtocolMapperModel mappingModel) {
        Map<String, String> config = mappingModel.getConfig();
        String configured = config == null ? "" : config.getOrDefault(CACHE_TTL_SECONDS, "");
        if (configured == null || configured.isBlank()) {
            configured = System.getenv().getOrDefault("SUNCOAST_MEMBERSHIP_TOKEN_CACHE_TTL_SECONDS", DEFAULT_CACHE_TTL_SECONDS);
        }
        try {
            return Math.max(0L, Long.parseLong(configured.trim()));
        } catch (NumberFormatException ignored) {
            return Long.parseLong(DEFAULT_CACHE_TTL_SECONDS);
        }
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
