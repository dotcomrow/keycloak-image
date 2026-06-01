package systems.suncoast.kc.membership;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class MembershipResolution {
    private final Set<String> roles;
    private final List<IdpMembershipResult> sources;

    public MembershipResolution(Set<String> roles, List<IdpMembershipResult> sources) {
        this.roles = toSortedSet(roles);
        this.sources = toSortedList(sources);
    }

    public Set<String> roles() {
        return roles;
    }

    public List<String> rolesList() {
        List<String> out = new ArrayList<>(roles);
        Collections.sort(out);
        return Collections.unmodifiableList(out);
    }

    public List<IdpMembershipResult> sources() {
        return sources;
    }

    private static Set<String> toSortedSet(Set<String> values) {
        if (values == null || values.isEmpty()) {
            return Collections.emptySet();
        }
        List<String> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        return Collections.unmodifiableSet(new LinkedHashSet<>(sorted));
    }

    private static List<IdpMembershipResult> toSortedList(List<IdpMembershipResult> values) {
        if (values == null || values.isEmpty()) {
            return Collections.emptyList();
        }
        List<IdpMembershipResult> out = new ArrayList<>(values);
        out.sort((a, b) -> a.source().compareToIgnoreCase(b.source()));
        return Collections.unmodifiableList(out);
    }
}
