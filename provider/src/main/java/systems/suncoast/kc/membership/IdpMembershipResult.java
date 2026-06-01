package systems.suncoast.kc.membership;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class IdpMembershipResult {
    private final String source;
    private final boolean attempted;
    private final boolean success;
    private final String message;
    private final Set<String> memberships;
    private final Set<String> roles;

    public IdpMembershipResult(String source,
                               boolean attempted,
                               boolean success,
                               String message,
                               Set<String> memberships,
                               Set<String> roles) {
        this.source = source;
        this.attempted = attempted;
        this.success = success;
        this.message = message == null ? "" : message;
        this.memberships = toSortedSet(memberships);
        this.roles = toSortedSet(roles);
    }

    public static IdpMembershipResult skipped(String source, String message) {
        return new IdpMembershipResult(source, false, true, message, Collections.emptySet(), Collections.emptySet());
    }

    public static IdpMembershipResult failed(String source, String message) {
        return new IdpMembershipResult(source, true, false, message, Collections.emptySet(), Collections.emptySet());
    }

    public static IdpMembershipResult success(String source, String message, Set<String> memberships, Set<String> roles) {
        return new IdpMembershipResult(source, true, true, message, memberships, roles);
    }

    public String source() {
        return source;
    }

    public boolean attempted() {
        return attempted;
    }

    public boolean success() {
        return success;
    }

    public String message() {
        return message;
    }

    public Set<String> memberships() {
        return memberships;
    }

    public Set<String> roles() {
        return roles;
    }

    public List<String> membershipsList() {
        return toSortedList(memberships);
    }

    public List<String> rolesList() {
        return toSortedList(roles);
    }

    private static Set<String> toSortedSet(Set<String> values) {
        if (values == null || values.isEmpty()) {
            return Collections.emptySet();
        }
        Set<String> out = new LinkedHashSet<>();
        List<String> sorted = new ArrayList<>();
        for (String value : values) {
            if (value == null || value.isBlank()) {
                continue;
            }
            sorted.add(value);
        }
        Collections.sort(sorted);
        out.addAll(sorted);
        return Collections.unmodifiableSet(out);
    }

    private static List<String> toSortedList(Set<String> values) {
        if (values == null || values.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> out = new ArrayList<>(values);
        Collections.sort(out);
        return Collections.unmodifiableList(out);
    }
}
