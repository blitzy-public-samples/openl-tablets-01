package org.openl.security.acl;

import java.util.Collections;
import java.util.SortedSet;
import java.util.TreeSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * The per-transaction aggregator behind {@link AclChangeListener#record} (V11). It gathers the mutations of one
 * transaction and notifies the listener once, after completion.
 *
 * <p>It is package-private, so {@link AclChangeListener#record} stays the only way to report an ACL change. Its
 * state belongs to the one thread that runs the transaction, so it needs no locking.
 */
final class AclChangeAccumulator implements TransactionSynchronization {

    private static final Logger LOG = LoggerFactory.getLogger(AclChangeListener.class);
    static final String UNKNOWN = "unknown";

    private final AclChangeListener listener;
    final TreeSet<String> kinds = new TreeSet<>();
    final TreeSet<String> objectTypes = new TreeSet<>();
    int changes;
    private boolean anyFailed;

    AclChangeAccumulator(AclChangeListener listener) {
        this.listener = listener;
    }

    void add(String kind, String objectType, boolean failed) {
        changes++;
        kinds.add(kind);
        objectTypes.add(objectType);
        anyFailed |= failed;
    }

    /**
     * Releases the key while an inner {@code REQUIRES_NEW} transaction runs. Spring suspends synchronizations but
     * not foreign resources, so without this the inner transaction would join this accumulator.
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
     * Unbinds the key first, so nothing leaks into the thread's next transaction, then notifies the listener. A
     * rollback and an unknown status both count as a failure. {@code afterCommit} is not used, because it is skipped
     * on rollback.
     */
    @Override
    public void afterCompletion(int status) {
        TransactionSynchronizationManager.unbindResourceIfPossible(listener);
        var outcome = (status == STATUS_COMMITTED && !anyFailed) ? AclChangeListener.SUCCESS
            : AclChangeListener.FAILURE;
        notifySafely(listener, outcome, changes, kinds, objectTypes);
    }

    /**
     * The only route to {@link AclChangeListener#aclChanged}. It hands out unmodifiable copies and contains a
     * listener failure: the exception is swallowed, never rethrown, and only fixed text and the exception's class
     * name are logged, never its message or stack trace, because either could quote the values the change
     * concerned.
     */
    static void notifySafely(AclChangeListener listener,
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
            LOG.warn("ACL change listener failed ({}).", e.getClass().getSimpleName());
        }
    }
}
