package systems.suncoast.kc.membership;

import java.util.Locale;

public final class RoleNameNormalizer {
    private RoleNameNormalizer() {
    }

    public static String fromGitHubTeamKey(String teamKey) {
        String value = normalize(teamKey);
        if (value.isBlank()) {
            return "";
        }
        int slash = value.lastIndexOf('/');
        if (slash >= 0 && slash + 1 < value.length()) {
            value = value.substring(slash + 1);
        }
        return sanitize(value);
    }

    public static String fromGoogleGroupKey(String groupKey) {
        String value = normalize(groupKey);
        if (value.isBlank()) {
            return "";
        }
        int at = value.indexOf('@');
        if (at > 0) {
            value = value.substring(0, at);
        }
        int slash = value.lastIndexOf('/');
        if (slash >= 0 && slash + 1 < value.length()) {
            value = value.substring(slash + 1);
        }
        return sanitize(value);
    }

    private static String normalize(String raw) {
        if (raw == null) {
            return "";
        }
        return raw.trim().toLowerCase(Locale.ROOT);
    }

    private static String sanitize(String raw) {
        String value = raw.replaceAll("[^a-z0-9._-]+", "-");
        value = value.replaceAll("^-+|-+$", "");
        return value;
    }
}
