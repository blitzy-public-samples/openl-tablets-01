package org.openl.security.acl;

import java.util.Collections;
import java.util.Objects;
import java.util.SortedSet;
import java.util.TreeSet;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Receives a notice of every ACL change once it is complete. This is the V11 extension point that lets the
 * security audit trail record ACL changes without this module depending on the one that writes the trail.
 *
 * <p>{@link JdbcMutableAclService} reports each mutation through {@link #record}. One event is either one
 * completed transaction, committed or rolled back, that performed at least one mutation, or one mutation made
 * outside any transaction. A bulk overwrite that runs in a single transaction is therefore one event, however
 * many repositories, projects and SIDs it touches.
 *
 * <p>The listener is called on the thread that completes the transaction, after completion, so the transaction
 * is no longer usable from inside {@link #aclChanged}. The thread still carries its security context, which is
 * how an implementation learns the acting user.
 *
 * <p>The listener never receives object identifiers, SIDs, paths, project or group names, or any other
 * user-controlled value: such values are free text and could hold a password or a token. It receives only
 * counts and code-defined names.
 *
 * <p>Implementations must not throw. A {@link RuntimeException} is swallowed and logged anyway, so it can never
 * break the ACL write or the caller that made it.
 *
 * <pre>{@code
 * // inside JdbcMutableAclService, after the parent has created the ACL
 * AclChangeListener.record(aclChangeListener, "createAcl", objectIdentity.getType(), false);
 * }</pre>
 */
public interface AclChangeListener {

    /**
     * The outcome of an event whose transaction committed and whose mutations all succeeded.
     */
    String SUCCESS = "success";

    /**
     * The outcome of an event whose transaction rolled back or ended in an unknown state, or in which a
     * mutation failed.
     */
    String FAILURE = "failure";

    /**
     * Called once per event, after the transaction that holds its mutations has completed.
     *
     * @param outcome {@link #SUCCESS} or {@link #FAILURE}
     * @param changes the number of mutations in the event, at least 1
     * @param kinds the sorted, distinct mutator names: {@code createAcl}, {@code updateAcl}, {@code deleteAcl},
     *            {@code deleteSid} and {@code updateSid}. Unmodifiable
     * @param objectTypes the sorted, distinct simple class names of the object-identity types involved, such as
     *            {@code ProjectArtifact}, {@code RepositoryObjectIdentity} and {@code Root}, plus {@code sid} for SID
     *            mutations and {@code unknown} for a missing type. Unmodifiable
     */
    void aclChanged(String outcome, int changes, SortedSet<String> kinds, SortedSet<String> objectTypes);

    /**
     * Reports one ACL mutation.
     *
     * <p>Outside a transaction synchronization the listener is notified at once. Inside one, the mutation joins
     * the accumulator of the current transaction, which notifies the listener once when the transaction completes.
     * A {@code null} listener makes this a no-op.
     *
     * @param listener the listener to notify, or {@code null} when none is defined
     * @param kind the mutator name, for example {@code createAcl}; {@code null} is reported as {@code unknown}
     * @param objectType the object-identity type, either a fully qualified class name, which is reduced to its
     *            simple name, or {@code sid}; {@code null} or blank is reported as {@code unknown}
     * @param failed whether the mutation threw
     */
    static void record(@Nullable AclChangeListener listener,
                       @Nullable String kind,
                       @Nullable String objectType,
                       boolean failed) {
        if (listener == null) {
            return;
        }
        var safeKind = Objects.requireNonNullElse(kind, Accumulator.UNKNOWN);
        var type = simpleType(objectType);
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            var once = new Accumulator(listener);
            once.add(safeKind, type, failed);
            Accumulator.notifySafely(listener, failed ? FAILURE : SUCCESS, once.changes, once.kinds, once.objectTypes);
            return;
        }
        // One accumulator per transaction, keyed by the listener: bound and registered on the first mutation only,
        // because bindResource rejects a key that is already bound.
        var accumulator = (Accumulator) TransactionSynchronizationManager.getResource(listener);
        if (accumulator == null) {
            accumulator = new Accumulator(listener);
            TransactionSynchronizationManager.bindResource(listener, accumulator);
            TransactionSynchronizationManager.registerSynchronization(accumulator);
        }
        accumulator.add(safeKind, type, failed);
    }

    /**
     * Reduces an object-identity type to its simple class name, so {@code org.openl.security.acl.repository.Root}
     * becomes {@code Root} and {@code sid} stays {@code sid}. A missing or blank type becomes {@code unknown}.
     */
    private static String simpleType(@Nullable String type) {
        var simple = type == null ? "" : type.substring(type.lastIndexOf('.') + 1);
        return simple.isBlank() ? Accumulator.UNKNOWN : simple;
    }

    /**
     * Gathers the mutations of one transaction and notifies the listener once, after completion.
     *
     * <p>Its state belongs to the one thread that runs the transaction, so it needs no locking.
     */
    final class Accumulator implements TransactionSynchronization {

        private static final Logger LOG = LoggerFactory.getLogger(AclChangeListener.class);
        private static final String UNKNOWN = "unknown";

        private final AclChangeListener listener;
        private final TreeSet<String> kinds = new TreeSet<>();
        private final TreeSet<String> objectTypes = new TreeSet<>();
        private int changes;
        private boolean anyFailed;

        private Accumulator(AclChangeListener listener) {
            this.listener = listener;
        }

        private void add(String kind, String objectType, boolean failed) {
            changes++;
            kinds.add(kind);
            objectTypes.add(objectType);
            anyFailed |= failed;
        }

        /**
         * Releases the key while an inner {@code REQUIRES_NEW} transaction runs. Spring suspends synchronizations
         * but not foreign resources, so without this the inner transaction would join this accumulator.
         */
        @Override
        public void suspend() {
            TransactionSynchronizationManager.unbindResourceIfPossible(listener);
        }

        /**
         * Takes the key back once the inner transaction has completed and unbound its own accumulator.
         */
        @Override
        public void resume() {
            TransactionSynchronizationManager.bindResource(listener, this);
        }

        /**
         * Unbinds the key first, so nothing leaks into the thread's next transaction, then notifies the listener.
         * A rollback and an unknown status both count as a failure. {@code afterCommit} is not used, because it is
         * skipped on rollback.
         */
        @Override
        public void afterCompletion(int status) {
            TransactionSynchronizationManager.unbindResourceIfPossible(listener);
            var outcome = (status == STATUS_COMMITTED && !anyFailed) ? SUCCESS : FAILURE;
            notifySafely(listener, outcome, changes, kinds, objectTypes);
        }

        /**
         * The only route to {@link AclChangeListener#aclChanged}. It hands out unmodifiable copies and contains a
         * listener failure, logging fixed text that carries no ACL data.
         */
        private static void notifySafely(AclChangeListener listener,
                                         String outcome,
                                         int changes,
                                         SortedSet<String> kinds,
                                         SortedSet<String> objectTypes) {
            try {
                listener.aclChanged(outcome,
                    changes,
                    Collections.unmodifiableSortedSet(new TreeSet<>(kinds)),
                    Collections.unmodifiableSortedSet(new TreeSet<>(objectTypes)));
            } catch (RuntimeException e) {
                LOG.warn("ACL change listener failed.", e);
            }
        }
    }
}
