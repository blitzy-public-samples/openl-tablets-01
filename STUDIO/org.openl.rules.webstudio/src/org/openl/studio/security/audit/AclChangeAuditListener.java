package org.openl.studio.security.audit;

import java.util.SortedSet;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import org.openl.security.acl.AclChangeListener;

/**
 * Writes one {@code acl.change} line of the security audit trail (V11) for every ACL change that the ACL
 * persistence boundary reports.
 *
 * <p>{@code JdbcMutableAclService} publishes each completed ACL transaction, or each mutation made outside a
 * transaction, through {@link AclChangeListener}, because the ACL module cannot depend on this one. This bean is
 * the only place where ACL changes are audited, so the ACL controllers and services that make the changes log
 * nothing themselves and no change is logged twice. It is found by the component scan of {@code org.openl.studio}
 * and must stay the only {@link AclChangeListener} bean in the context.
 *
 * <p>The notice carries only the outcome, the number of mutations, the mutator names and the object-identity type
 * names, all code-defined. Object identifiers, SIDs, project names, repository paths and group names never reach
 * this class, because they are free text that could hold a password or a token. The acting user and the address
 * are resolved by {@link SecurityAuditLog#aclChange} from the security context of the completing thread, which is
 * still the request thread of the user who made the change, or {@code system} when there is no authentication,
 * as for grants made at start-up.
 *
 * <p>The listener runs after the transaction has completed, so it must never throw: a failure to write the line is
 * reported with a fixed message and swallowed, a failure of the logging backend while reporting it is swallowed
 * too, and the ACL write and its caller are never affected. The class is stateless and thread-safe.
 */
@Slf4j
@Component
public class AclChangeAuditListener implements AclChangeListener {

    @Override
    public void aclChanged(String outcome, int changes, SortedSet<String> kinds, SortedSet<String> objectTypes) {
        try {
            SecurityAuditLog.aclChange(outcome, changes, kinds, objectTypes);
        } catch (RuntimeException e) {
            // Only the exception class is logged: its message, or the notice itself, could quote the values the
            // change was about.
            try {
                log.warn("Failed to write the ACL change audit event ({}).", e.getClass().getSimpleName());
            } catch (RuntimeException ignored) {
                // The logging backend itself failed, so nothing is left to report to, and the caller must not fail.
            }
        }
    }
}
