package systems.suncoast.kc.membership;

import org.keycloak.models.UserModel;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public final class MembershipAttributeCache {
    public static final String ATTR_GITHUB_TEAMS = "gh.teams";
    public static final String ATTR_GITHUB_ROLES = "gh.roles";
    public static final String ATTR_GITHUB_TS = "gh.cachedAt";
    public static final String ATTR_GOOGLE_GROUPS = "ggl.groups";
    public static final String ATTR_GOOGLE_ROLES = "ggl.roles";
    public static final String ATTR_GOOGLE_TS = "ggl.cachedAt";
    public static final String ATTR_SUNCOAST_ROLES = "suncoast.roles";
    public static final String ATTR_SUNCOAST_TS = "suncoast.roles.cachedAt";

    private MembershipAttributeCache() {
    }

    public static void storeResolution(UserModel user, MembershipResolution resolution) {
        long now = Instant.now().getEpochSecond();
        for (IdpMembershipResult source : resolution.sources()) {
            storeSourceResult(user, source, now);
        }
        storeMergedRolesFromCachedSources(user, now);
    }

    public static void storeSourceResult(UserModel user, IdpMembershipResult source) {
        storeSourceResult(user, source, Instant.now().getEpochSecond());
        storeMergedRolesFromCachedSources(user, Instant.now().getEpochSecond());
    }

    public static Set<String> readCachedRoles(UserModel user) {
        return readAttributeSet(user, ATTR_SUNCOAST_ROLES);
    }

    public static boolean isStale(UserModel user, long ttlSeconds) {
        if (ttlSeconds <= 0) {
            return true;
        }
        long cachedAt = parseLong(user.getFirstAttribute(ATTR_SUNCOAST_TS));
        if (cachedAt <= 0) {
            return true;
        }
        long now = Instant.now().getEpochSecond();
        return now - cachedAt >= ttlSeconds;
    }

    static void storeSourceResult(UserModel user, IdpMembershipResult source, long timestamp) {
        if (source == null) {
            return;
        }
        if ("github".equalsIgnoreCase(source.source())) {
            user.setAttribute(ATTR_GITHUB_TEAMS, mutableList(source.membershipsList()));
            user.setAttribute(ATTR_GITHUB_ROLES, mutableList(source.rolesList()));
            user.setSingleAttribute(ATTR_GITHUB_TS, Long.toString(timestamp));
        } else if ("google".equalsIgnoreCase(source.source())) {
            user.setAttribute(ATTR_GOOGLE_GROUPS, mutableList(source.membershipsList()));
            user.setAttribute(ATTR_GOOGLE_ROLES, mutableList(source.rolesList()));
            user.setSingleAttribute(ATTR_GOOGLE_TS, Long.toString(timestamp));
        }
    }

    private static void storeMergedRolesFromCachedSources(UserModel user, long timestamp) {
        Set<String> roles = new LinkedHashSet<>();
        roles.addAll(readAttributeSet(user, ATTR_GITHUB_ROLES));
        roles.addAll(readAttributeSet(user, ATTR_GOOGLE_ROLES));
        user.setAttribute(ATTR_SUNCOAST_ROLES, mutableList(roles));
        user.setSingleAttribute(ATTR_SUNCOAST_TS, Long.toString(timestamp));
    }

    private static Set<String> readAttributeSet(UserModel user, String attribute) {
        return user.getAttributeStream(attribute)
                .filter(value -> value != null && !value.isBlank())
                .map(String::trim)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private static List<String> mutableList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return new ArrayList<>();
        }
        return new ArrayList<>(values);
    }

    private static List<String> mutableList(Set<String> values) {
        if (values == null || values.isEmpty()) {
            return new ArrayList<>();
        }
        return new ArrayList<>(values);
    }

    private static long parseLong(String value) {
        if (value == null || value.isBlank()) {
            return 0;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }
}
