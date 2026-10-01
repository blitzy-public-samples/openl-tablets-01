package org.openl.studio.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Objects;
import java.util.function.BiFunction;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;

import org.openl.rules.security.Group;
import org.openl.rules.security.Privileges;
import org.openl.rules.webstudio.service.GroupManagementService;
import org.openl.rules.webstudio.service.UserManagementService;
import org.openl.util.StringUtils;

/**
 * Get all privileges for the given user, including group-based privileges.
 * Used in ad, saml, and oauth2 modes where groups are managed externally.
 *
 * <p>V12: when an external group name matches an OpenL group that holds {@code ADMIN}, {@link #apply} logs a
 * WARN, because the user gains administrator rights through that name match alone. The mapping itself is not
 * changed. {@link #withoutAdminMatchWarning()} gives the same mapping without the warning, for requests that
 * replay stored groups instead of receiving them from the identity provider.
 */
@Slf4j // V12: logger for the ADMIN name-match warning
@RequiredArgsConstructor
public class GetUserPrivileges implements BiFunction<String, Collection<? extends GrantedAuthority>, Collection<GrantedAuthority>> {
    private final UserManagementService userManagementService;
    private final GroupManagementService groupManagementService;
    private final String defaultGroup;

    @Override
    public Collection<GrantedAuthority> apply(String user, Collection<? extends GrantedAuthority> authorities) {
        // V12: the identity provider supplies these groups at login, so an ADMIN name match is warned about
        return map(user, authorities, true);
    }

    /**
     * V12: the same mapping without the ADMIN name-match warning, for requests that replay stored groups
     * (personal access tokens) instead of receiving them from the identity provider at login.
     */
    public BiFunction<String, Collection<? extends GrantedAuthority>, Collection<GrantedAuthority>>
            withoutAdminMatchWarning() {
        return (u, a) -> map(u, a, false);
    }

    // V12: the former body of apply(), unchanged except that it passes the user and the warning switch on
    private Collection<GrantedAuthority> map(String user,
                                             Collection<? extends GrantedAuthority> authorities,
                                             boolean warn) {

        var privileges = new ArrayList<GrantedAuthority>();

        // Add a default group if it presents
        var defaultUserGroup = getDefaultGroup();
        if (defaultUserGroup != null) {
            privileges.add(defaultUserGroup);
        }

        // Map external authorities to OpenL privileges
        mapAuthorities(user, authorities, privileges, warn);

        // Add authorities from the DB if exists
        var userDetails = userManagementService.getUser(user);
        if (userDetails != null) {
            privileges.addAll(userDetails.getAuthorities());
        }

        return privileges;
    }

    // V12: takes the user and the warning switch, so an ADMIN name match can be logged
    private void mapAuthorities(String user,
                                Collection<? extends GrantedAuthority> authorities,
                                Collection<GrantedAuthority> privileges,
                                boolean warn) {
        for (GrantedAuthority authority : authorities) {
            var authorityName = authority.getAuthority();
            var group = groupManagementService.getGroupByName(authorityName);
            // V12: a name match with an ADMIN-holding OpenL group silently grants administrator rights.
            // Only names are logged, never credentials; the warning repeats at every IdP-backed login.
            if (warn && group != null && group.hasPrivilege(Privileges.ADMIN.name())) {
                // V12: the identity provider supplies these names and the log layouts print them as they are,
                // so only loggable() copies are logged; the mapping keeps using the names unchanged.
                log.warn(
                        "External group '{}' of user '{}' matches OpenL group '{}', which holds ADMIN; "
                                + "the user gains administrator rights through this name match.",
                        loggable(authorityName),
                        loggable(user),
                        loggable(group.getAuthority()));
            }
            // Expand priveleges from the DB
            privileges.add(Objects.requireNonNullElse(group, authority));
        }
    }

    private Group getDefaultGroup() {
        if (StringUtils.isBlank(defaultGroup)) {
            return null;
        }
        var group = groupManagementService.getGroupByName(defaultGroup);
        if (group != null) {
            return group;
        }
        // Create if absent
        groupManagementService.addGroup(defaultGroup, "A default group for authenticated users");
        return groupManagementService.getGroupByName(defaultGroup);

    }

    /**
     * V12: returns a copy of an identity-provider name that stays on one log line. Every ISO control character
     * (CR, LF and TAB included) and the Unicode line and paragraph separators U+2028 and U+2029 become
     * {@code '_'}, so a name cannot end the warning line and start a forged one.
     *
     * @param name the name as the identity provider supplied it, or {@code null}
     * @return the name with those characters replaced, or {@code null} when {@code name} is {@code null}
     */
    private static @Nullable String loggable(@Nullable String name) {
        if (name == null) {
            return null;
        }
        var safe = new StringBuilder(name.length());
        for (var i = 0; i < name.length(); i++) {
            var c = name.charAt(i);
            safe.append(Character.isISOControl(c) || c == '\u2028' || c == '\u2029' ? '_' : c);
        }
        return safe.toString();
    }

}
