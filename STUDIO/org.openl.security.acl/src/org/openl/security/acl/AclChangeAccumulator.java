package org.openl.security.acl;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.SortedSet;
import java.util.TreeSet;

import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * The per-transaction aggregator behind {@link AclChangeListener#record} (V11). It gathers the mutations of one
 * transaction and notifies the listener once, after completion.
 *
 * <p>A rollback to a savepoint, which is how a {@code PROPAGATION_NESTED} transaction rolls back, undoes the
 * mutations made since that savepoint, so the accumulator forgets them as well: it keeps a snapshot of its state at
 * each savepoint and restores that snapshot when the transaction rolls back to it. A transaction left with no
 * mutation is not reported.
 *
 * <p>It is package-private, so {@link AclChangeListener#record} stays the only way to report an ACL change. Its
 * state belongs to the one thread that runs the transaction, so it needs no locking.
 */
@Slf4j(topic = "org.openl.security.acl.AclChangeListener")
final class AclChangeAccumulator implements TransactionSynchronization {

    static final String UNKNOWN = "unknown";

    /**
     * The state before the first mutation, which is also the state at any savepoint taken before this accumulator
     * was registered.
     */
    private static final Snapshot EMPTY = new Snapshot(0,
        Collections.emptySortedSet(),
        Collections.emptySortedSet(),
        false);

    private final AclChangeListener listener;
    final TreeSet<String> kinds = new TreeSet<>();
    final TreeSet<String> objectTypes = new TreeSet<>();
    int changes;
    private boolean anyFailed;
    private final IdentityHashMap<Object, Snapshot> snapshots = new IdentityHashMap<>();

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
     * Keeps a snapshot of the current state for the savepoint, so that a rollback to it can restore that state.
     * Spring calls this on the synchronizations registered at that moment, when a {@code PROPAGATION_NESTED}
     * transaction starts or a savepoint is created through the transaction status.
     */
    @Override
    public void savepoint(Object savepoint) {
        snapshots.put(savepoint, new Snapshot(changes, new TreeSet<>(kinds), new TreeSet<>(objectTypes), anyFailed));
    }

    /**
     * Forgets the mutations made since the savepoint, because the rollback that Spring performs right after this
     * call undoes them. A savepoint without a snapshot was taken before this accumulator was registered, which
     * happens on the transaction's first mutation, so every mutation held here came after it and the empty state is
     * restored. The snapshot is kept, because a savepoint created through the transaction status can be rolled back
     * to again. The sets are refilled in place, so they stay the fields {@link AclChangeListener#record} reads.
     */
    @Override
    public void savepointRollback(Object savepoint) {
        var snapshot = snapshots.getOrDefault(savepoint, EMPTY);
        changes = snapshot.changes();
        kinds.clear();
        kinds.addAll(snapshot.kinds());
        objectTypes.clear();
        objectTypes.addAll(snapshot.objectTypes());
        anyFailed = snapshot.anyFailed();
    }

    /**
     * Unbinds the key first, so nothing leaks into the thread's next transaction, then notifies the listener, unless
     * rollbacks to savepoints undid every mutation: such a transaction changed nothing and is not reported. A
     * rollback and an unknown status both count as a failure. {@code afterCommit} is not used, because it is skipped
     * on rollback.
     */
    @Override
    public void afterCompletion(int status) {
        TransactionSynchronizationManager.unbindResourceIfPossible(listener);
        if (changes == 0) {
            return;
        }
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
            log.warn("ACL change listener failed ({}).", e.getClass().getSimpleName());
        }
    }

    /**
     * The state at one savepoint: only counts and code-defined names, like the rest of the state. Its sets are
     * copies that nothing modifies.
     */
    private record Snapshot(int changes, SortedSet<String> kinds, SortedSet<String> objectTypes, boolean anyFailed) {
    }
}
