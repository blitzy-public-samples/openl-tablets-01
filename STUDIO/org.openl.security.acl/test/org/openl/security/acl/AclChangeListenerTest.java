package org.openl.security.acl;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static org.openl.security.acl.AclChangeListener.FAILURE;
import static org.openl.security.acl.AclChangeListener.SUCCESS;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.UUID;
import javax.sql.DataSource;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.CannotGetJdbcConnectionException;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.SavepointManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import org.openl.security.acl.repository.ProjectArtifact;
import org.openl.security.acl.repository.RepositoryObjectIdentity;
import org.openl.security.acl.repository.Root;

/**
 * An ACL change reaches the security audit trail as one notice per completed transaction, whatever the number of
 * mutations it made, and the notice never carries an identifier: only an outcome, a count, mutator names and
 * code-defined type names. A rollback, a commit in an unknown state or a failed mutation is a failure. Mutations
 * undone by a rollback to a savepoint are not counted, and a transaction left with none is not reported. A mutation
 * made outside any transaction is reported at once. A listener that throws never breaks the ACL write.
 *
 * <p>The transactions run on a stub transaction manager with Spring's real synchronization lifecycle, and the
 * {@link JdbcMutableAclService} hooks run against a mocked JDBC chain, so the test needs no database.
 */
class AclChangeListenerTest {

    private static final String PROJECT_TYPE = ProjectArtifact.class.getName();
    private static final String ROOT_TYPE = Root.class.getName();

    private NoOpTransactionManager transactionManager;
    private RecordingListener listener;
    private AclCache aclCache;
    private LookupStrategy lookupStrategy;
    private final List<String> generatedValues = new ArrayList<>();

    @BeforeEach
    void setUp() {
        transactionManager = new NoOpTransactionManager();
        listener = new RecordingListener();
        aclCache = mock(AclCache.class);
        lookupStrategy = mock(LookupStrategy.class);
        generatedValues.clear();
    }

    @AfterEach
    void tearDown() {
        // Capture first and clean up before asserting, so one leaking test never poisons the next on this thread.
        var leakedResources = !TransactionSynchronizationManager.getResourceMap().isEmpty();
        var leakedSynchronization = TransactionSynchronizationManager.isSynchronizationActive();
        if (leakedSynchronization) {
            TransactionSynchronizationManager.clear();
        }
        for (var key : List.copyOf(TransactionSynchronizationManager.getResourceMap().keySet())) {
            TransactionSynchronizationManager.unbindResourceIfPossible(key);
        }
        SecurityContextHolder.clearContext();
        assertFalse(leakedResources, "A transaction resource is still bound after the test");
        assertFalse(leakedSynchronization, "A transaction synchronization is still active after the test");
    }

    @Test
    void outcomeConstantsAreTheAuditTrailValues() {
        assertEquals("success", SUCCESS);
        assertEquals("failure", FAILURE);
    }

    @Test
    void threeMutationsInOneTransactionNotifyOnceAfterCommit() {
        transaction().executeWithoutResult(status -> {
            AclChangeListener.record(listener, "createAcl", PROJECT_TYPE, false);
            AclChangeListener.record(listener, "updateAcl", PROJECT_TYPE, false);
            AclChangeListener.record(listener, "deleteSid", "sid", false);

            assertTrue(listener.notifications.isEmpty(), "Nothing is reported before the transaction completes");
            assertEquals(1, TransactionSynchronizationManager.getSynchronizations().size());
            assertTrue(TransactionSynchronizationManager.hasResource(listener));
        });

        assertEquals(List.of(new Notification(SUCCESS,
            3,
            List.of("createAcl", "deleteSid", "updateAcl"),
            List.of("ProjectArtifact", "sid"))), listener.notifications);
        assertEquals(1, transactionManager.commits);
    }

    @Test
    void rollbackOnlyTransactionNotifiesOneFailure() {
        transaction().executeWithoutResult(status -> {
            AclChangeListener.record(listener, "createAcl", ROOT_TYPE, false);
            AclChangeListener.record(listener, "deleteAcl", ROOT_TYPE, false);
            status.setRollbackOnly();
        });

        assertEquals(List.of(new Notification(FAILURE, 2, List.of("createAcl", "deleteAcl"), List.of("Root"))),
            listener.notifications);
        assertEquals(1, transactionManager.rollbacks);
        assertEquals(0, transactionManager.commits);
    }

    @Test
    void transactionRolledBackByAnExceptionNotifiesOneFailure() {
        var failure = new IllegalStateException("rolled back");

        var thrown = assertThrows(IllegalStateException.class, () -> transaction().executeWithoutResult(status -> {
            AclChangeListener.record(listener, "updateAcl", PROJECT_TYPE, false);
            throw failure;
        }));

        assertSame(failure, thrown);
        assertEquals(List.of(new Notification(FAILURE, 1, List.of("updateAcl"), List.of("ProjectArtifact"))),
            listener.notifications);
        assertEquals(1, transactionManager.rollbacks);
    }

    @Test
    void failedMutationInACommittedTransactionIsAFailure() {
        transaction().executeWithoutResult(status -> {
            AclChangeListener.record(listener, "createAcl", PROJECT_TYPE, true);
            AclChangeListener.record(listener, "updateAcl", PROJECT_TYPE, false);
        });

        assertEquals(1, transactionManager.commits);
        assertEquals(List.of(new Notification(FAILURE,
            2,
            List.of("createAcl", "updateAcl"),
            List.of("ProjectArtifact"))), listener.notifications);
    }

    @Test
    void commitEndingInAnUnknownStateIsAFailure() {
        transactionManager.failCommit = true;

        assertThrows(TransactionSystemException.class,
            () -> transaction().executeWithoutResult(
                status -> AclChangeListener.record(listener, "deleteAcl", PROJECT_TYPE, false)));

        assertEquals(List.of(new Notification(FAILURE, 1, List.of("deleteAcl"), List.of("ProjectArtifact"))),
            listener.notifications);
    }

    @Test
    void mutationOutsideATransactionNotifiesAtOnce() {
        assertFalse(TransactionSynchronizationManager.isSynchronizationActive());

        AclChangeListener.record(listener, "deleteAcl", ROOT_TYPE, false);
        assertEquals(List.of(new Notification(SUCCESS, 1, List.of("deleteAcl"), List.of("Root"))),
            listener.notifications);

        AclChangeListener.record(listener, "deleteAcl", ROOT_TYPE, true);
        assertEquals(List.of(new Notification(SUCCESS, 1, List.of("deleteAcl"), List.of("Root")),
            new Notification(FAILURE, 1, List.of("deleteAcl"), List.of("Root"))), listener.notifications);
    }

    @Test
    void nullListenerIsANoOpOutsideATransaction() {
        assertDoesNotThrow(() -> AclChangeListener.record(null, "createAcl", PROJECT_TYPE, false));
        assertDoesNotThrow(() -> AclChangeListener.record(null, "createAcl", PROJECT_TYPE, true));
    }

    @Test
    void nullListenerBindsAndRegistersNothingInsideATransaction() {
        transaction().executeWithoutResult(status -> {
            AclChangeListener.record(null, "createAcl", PROJECT_TYPE, false);

            assertTrue(TransactionSynchronizationManager.getSynchronizations().isEmpty());
            assertTrue(TransactionSynchronizationManager.getResourceMap().isEmpty());
        });

        assertTrue(listener.notifications.isEmpty());
    }

    @Test
    void throwingListenerDoesNotPropagateOutsideATransaction() {
        var throwing = new ThrowingListener();

        assertDoesNotThrow(() -> AclChangeListener.record(throwing, "deleteSid", "sid", false));

        assertEquals(1, throwing.calls);
    }

    @Test
    void throwingListenerDoesNotPropagateAfterCommit() {
        var throwing = new ThrowingListener();
        var callbackResult = new Object();

        var result = transaction().execute(status -> {
            AclChangeListener.record(throwing, "updateSid", "sid", false);
            return callbackResult;
        });

        assertSame(callbackResult, result);
        assertEquals(1, throwing.calls);
        assertEquals(1, transactionManager.commits);
        assertTrue(TransactionSynchronizationManager.getResourceMap().isEmpty());
    }

    @Test
    void fullyQualifiedTypeIsReducedToItsSimpleName() {
        assertEquals(List.of("RepositoryObjectIdentity"),
            recordOutsideTransaction("createAcl", RepositoryObjectIdentity.class.getName()).objectTypes());
        assertEquals(List.of("ProjectArtifact"), recordOutsideTransaction("createAcl", PROJECT_TYPE).objectTypes());
    }

    @Test
    void unqualifiedTypeIsKeptAsItIs() {
        assertEquals(List.of("Root"), recordOutsideTransaction("deleteAcl", "Root").objectTypes());
        assertEquals(List.of("sid"), recordOutsideTransaction("deleteSid", "sid").objectTypes());
    }

    @Test
    void missingOrBlankTypeIsReportedAsUnknown() {
        assertEquals(List.of("unknown"), recordOutsideTransaction("updateAcl", null).objectTypes());
        assertEquals(List.of("unknown"), recordOutsideTransaction("updateAcl", "  ").objectTypes());
        assertEquals(List.of("unknown"), recordOutsideTransaction("updateAcl", "org.example.").objectTypes());
    }

    @Test
    void missingKindIsReportedAsUnknown() {
        assertEquals(List.of("unknown"), recordOutsideTransaction(null, ROOT_TYPE).kinds());
    }

    @Test
    void requiresNewTransactionIsItsOwnEvent() {
        transaction().executeWithoutResult(outer -> {
            AclChangeListener.record(listener, "createAcl", PROJECT_TYPE, false);

            requiresNewTransaction().executeWithoutResult(inner -> {
                AclChangeListener.record(listener, "updateAcl", ROOT_TYPE, false);
                assertEquals(1, TransactionSynchronizationManager.getSynchronizations().size());
            });
            assertEquals(List.of(new Notification(SUCCESS, 1, List.of("updateAcl"), List.of("Root"))),
                listener.notifications,
                "The inner transaction is reported when it commits, on its own");

            AclChangeListener.record(listener, "deleteAcl", PROJECT_TYPE, false);
        });

        assertEquals(List.of(new Notification(SUCCESS, 1, List.of("updateAcl"), List.of("Root")),
            new Notification(SUCCESS, 2, List.of("createAcl", "deleteAcl"), List.of("ProjectArtifact"))),
            listener.notifications);
        assertEquals(1, transactionManager.suspends);
        assertEquals(1, transactionManager.resumes);
        assertEquals(2, transactionManager.commits);
    }

    @Test
    void rolledBackRequiresNewTransactionDoesNotFailTheOuterOne() {
        transaction().executeWithoutResult(outer -> {
            AclChangeListener.record(listener, "createAcl", PROJECT_TYPE, false);
            requiresNewTransaction().executeWithoutResult(inner -> {
                AclChangeListener.record(listener, "deleteSid", "sid", false);
                inner.setRollbackOnly();
            });
        });

        assertEquals(List.of(new Notification(FAILURE, 1, List.of("deleteSid"), List.of("sid")),
            new Notification(SUCCESS, 1, List.of("createAcl"), List.of("ProjectArtifact"))), listener.notifications);
    }

    @Test
    void mutationsOfARolledBackNestedTransactionAreNotCounted() {
        transaction().executeWithoutResult(outer -> {
            AclChangeListener.record(listener, "createAcl", PROJECT_TYPE, false);
            nestedTransaction().executeWithoutResult(nested -> {
                AclChangeListener.record(listener, "deleteSid", "sid", true);
                AclChangeListener.record(listener, "updateAcl", ROOT_TYPE, false);
                assertEquals(1, TransactionSynchronizationManager.getSynchronizations().size());
                nested.setRollbackOnly();
            });
        });

        assertEquals(List.of(new Notification(SUCCESS, 1, List.of("createAcl"), List.of("ProjectArtifact"))),
            listener.notifications,
            "Neither the rolled-back mutations nor their failure reach the committed event");
        assertEquals(1, transactionManager.savepoints);
        assertEquals(1, transactionManager.savepointRollbacks);
        assertEquals(1, transactionManager.commits);
        assertEquals(0, transactionManager.rollbacks);
    }

    @Test
    void committedNestedTransactionJoinsTheOuterEvent() {
        transaction().executeWithoutResult(outer -> {
            AclChangeListener.record(listener, "createAcl", PROJECT_TYPE, false);
            nestedTransaction().executeWithoutResult(
                nested -> AclChangeListener.record(listener, "updateAcl", ROOT_TYPE, false));
        });

        assertEquals(List.of(new Notification(SUCCESS,
            2,
            List.of("createAcl", "updateAcl"),
            List.of("ProjectArtifact", "Root"))), listener.notifications);
        assertEquals(1, transactionManager.savepoints);
        assertEquals(0, transactionManager.savepointRollbacks);
        assertEquals(1, transactionManager.savepointReleases);
        assertEquals(1, transactionManager.commits);
    }

    @Test
    void nestedRollbackBeforeTheFirstOuterMutationKeepsOnlyTheLaterOnes() {
        transaction().executeWithoutResult(outer -> {
            nestedTransaction().executeWithoutResult(nested -> {
                // The accumulator is registered here, after the savepoint, so it holds no snapshot of it.
                AclChangeListener.record(listener, "deleteAcl", ROOT_TYPE, true);
                nested.setRollbackOnly();
            });
            AclChangeListener.record(listener, "createAcl", PROJECT_TYPE, false);
        });

        assertEquals(List.of(new Notification(SUCCESS, 1, List.of("createAcl"), List.of("ProjectArtifact"))),
            listener.notifications);
        assertEquals(1, transactionManager.savepointRollbacks);
        assertEquals(1, transactionManager.commits);
    }

    @Test
    void transactionWhoseMutationsWereAllRolledBackToASavepointIsNotReported() {
        transaction().executeWithoutResult(outer -> nestedTransaction().executeWithoutResult(nested -> {
            AclChangeListener.record(listener, "updateSid", "sid", false);
            nested.setRollbackOnly();
        }));
        transaction().executeWithoutResult(outer -> {
            var savepoint = outer.createSavepoint();
            AclChangeListener.record(listener, "deleteSid", "sid", false);
            nestedTransaction().executeWithoutResult(nested -> {
                AclChangeListener.record(listener, "deleteAcl", ROOT_TYPE, false);
                nested.setRollbackOnly();
            });
            outer.rollbackToSavepoint(savepoint);
            outer.setRollbackOnly();
        });

        assertTrue(listener.notifications.isEmpty(), "A committed and a rolled-back transaction, neither reported");
        assertEquals(1, transactionManager.commits);
        assertEquals(1, transactionManager.rollbacks);
        assertTrue(TransactionSynchronizationManager.getResourceMap().isEmpty());
        assertFalse(TransactionSynchronizationManager.isSynchronizationActive());
    }

    @Test
    void mutationsRolledBackToAProgrammaticSavepointAreNotCounted() {
        transaction().executeWithoutResult(status -> {
            AclChangeListener.record(listener, "createAcl", PROJECT_TYPE, false);
            var savepoint = status.createSavepoint();
            AclChangeListener.record(listener, "updateAcl", ROOT_TYPE, true);
            status.rollbackToSavepoint(savepoint);
            AclChangeListener.record(listener, "deleteAcl", ROOT_TYPE, false);
            AclChangeListener.record(listener, "deleteSid", "sid", false);
            status.rollbackToSavepoint(savepoint);
            status.releaseSavepoint(savepoint);
            AclChangeListener.record(listener, "updateSid", "sid", false);
        });

        assertEquals(List.of(new Notification(SUCCESS,
            2,
            List.of("createAcl", "updateSid"),
            List.of("ProjectArtifact", "sid"))), listener.notifications);
        assertEquals(1, transactionManager.savepoints);
        assertEquals(2, transactionManager.savepointRollbacks);
        assertEquals(1, transactionManager.savepointReleases);
        assertEquals(1, transactionManager.commits);
    }

    @Test
    void outerRollbackAfterANestedRollbackReportsOnlyTheSurvivingMutations() {
        transaction().executeWithoutResult(outer -> {
            AclChangeListener.record(listener, "createAcl", ROOT_TYPE, false);
            AclChangeListener.record(listener, "updateAcl", ROOT_TYPE, false);
            nestedTransaction().executeWithoutResult(nested -> {
                AclChangeListener.record(listener, "deleteSid", "sid", false);
                nested.setRollbackOnly();
            });
            outer.setRollbackOnly();
        });

        assertEquals(List.of(new Notification(FAILURE, 2, List.of("createAcl", "updateAcl"), List.of("Root"))),
            listener.notifications);
        assertEquals(1, transactionManager.savepointRollbacks);
        assertEquals(1, transactionManager.rollbacks);
        assertEquals(0, transactionManager.commits);
    }

    @Test
    void sequentialTransactionsOnOneThreadAreSeparateEvents() {
        transaction().executeWithoutResult(status -> AclChangeListener.record(listener, "createAcl", ROOT_TYPE, false));
        transaction().executeWithoutResult(status -> {
            AclChangeListener.record(listener, "updateAcl", ROOT_TYPE, false);
            AclChangeListener.record(listener, "updateAcl", ROOT_TYPE, false);
        });

        assertEquals(List.of(new Notification(SUCCESS, 1, List.of("createAcl"), List.of("Root")),
            new Notification(SUCCESS, 2, List.of("updateAcl"), List.of("Root"))), listener.notifications);
    }

    @Test
    void receivedSetsAreUnmodifiableOutsideATransaction() {
        AclChangeListener.record(listener, "deleteAcl", ROOT_TYPE, false);

        assertReceivedSetsAreUnmodifiable();
    }

    @Test
    void receivedSetsAreUnmodifiableAfterCommit() {
        transaction().executeWithoutResult(status -> AclChangeListener.record(listener, "createAcl", ROOT_TYPE, false));

        assertReceivedSetsAreUnmodifiable();
    }

    @Test
    void eachListenerReceivesOnlyItsOwnChanges() {
        var other = new RecordingListener();

        transaction().executeWithoutResult(status -> {
            AclChangeListener.record(listener, "createAcl", PROJECT_TYPE, false);
            AclChangeListener.record(other, "deleteSid", "sid", false);
            AclChangeListener.record(other, "updateSid", "sid", false);
            assertEquals(2, TransactionSynchronizationManager.getSynchronizations().size());
        });

        assertEquals(List.of(new Notification(SUCCESS, 1, List.of("createAcl"), List.of("ProjectArtifact"))),
            listener.notifications);
        assertEquals(List.of(new Notification(SUCCESS, 2, List.of("deleteSid", "updateSid"), List.of("sid"))),
            other.notifications);
    }


    @Test
    void failedCreateAclIsReportedAndRethrown() throws SQLException {
        var service = service(unavailableDataSource(), true);
        authenticate();

        assertThrows(CannotGetJdbcConnectionException.class,
            () -> service.createAcl(new ObjectIdentityImpl(ProjectArtifact.class, generated())));

        assertEquals(List.of(new Notification(FAILURE, 1, List.of("createAcl"), List.of("ProjectArtifact"))),
            listener.notifications);
        assertNoGeneratedValueReported();
    }

    @Test
    @SuppressWarnings("NullAway") // passes null on purpose to check that the hook reports it instead of failing
    void createAclOfAMissingIdentityIsReportedAsUnknown() throws SQLException {
        var service = service(unavailableDataSource(), true);

        assertThrows(IllegalArgumentException.class, () -> service.createAcl(null));

        assertEquals(List.of(new Notification(FAILURE, 1, List.of("createAcl"), List.of("unknown"))),
            listener.notifications);
    }

    @Test
    void failedUpdateAclIsReportedWithItsIdentityType() throws SQLException {
        var service = service(unavailableDataSource(), true);
        var acl = mock(MutableAcl.class);
        when(acl.getObjectIdentity()).thenReturn(new ObjectIdentityImpl(ProjectArtifact.class, generated()));

        assertThrows(IllegalArgumentException.class, () -> service.updateAcl(acl));

        assertEquals(List.of(new Notification(FAILURE, 1, List.of("updateAcl"), List.of("ProjectArtifact"))),
            listener.notifications);
        assertNoGeneratedValueReported();
    }

    @Test
    @SuppressWarnings("NullAway") // passes null on purpose to check that the hook reports it instead of failing
    void updateAclWithoutAnIdentityIsReportedAsUnknown() throws SQLException {
        var service = service(unavailableDataSource(), true);

        assertThrows(IllegalArgumentException.class, () -> service.updateAcl(mock(MutableAcl.class)));
        assertThrows(NullPointerException.class, () -> service.updateAcl(null));

        var unknownUpdate = new Notification(FAILURE, 1, List.of("updateAcl"), List.of("unknown"));
        assertEquals(List.of(unknownUpdate, unknownUpdate), listener.notifications);
    }

    @Test
    @SuppressWarnings("NullAway") // passes null on purpose to check that the hook reports it instead of failing
    void failedDeleteAclIsReportedAndRethrown() throws SQLException {
        var service = service(unavailableDataSource(), true);

        assertThrows(CannotGetJdbcConnectionException.class,
            () -> service.deleteAcl(new ObjectIdentityImpl(ProjectArtifact.class, generated()), true));
        assertThrows(IllegalArgumentException.class, () -> service.deleteAcl(null, false));

        assertEquals(List.of(new Notification(FAILURE, 1, List.of("deleteAcl"), List.of("ProjectArtifact")),
            new Notification(FAILURE, 1, List.of("deleteAcl"), List.of("unknown"))), listener.notifications);
        assertNoGeneratedValueReported();
    }

    @Test
    void createAclIsReportedOnceItSucceeds() throws SQLException {
        var jdbc = connectedJdbc(false);
        // The identity is new, its owner SID exists, and its class is found in one row.
        when(jdbc.resultSet().next()).thenReturn(false, true, true, false);
        var service = service(jdbc.dataSource(), true);
        authenticate();
        var identity = new ObjectIdentityImpl(ProjectArtifact.class, generated());
        var acl = mock(MutableAcl.class);
        when(lookupStrategy.readAclsById(any(), any())).thenReturn(Map.of(identity, acl));

        assertSame(acl, service.createAcl(identity));

        assertEquals(List.of(new Notification(SUCCESS, 1, List.of("createAcl"), List.of("ProjectArtifact"))),
            listener.notifications);
        assertNoGeneratedValueReported();
    }

    @Test
    void deleteAclIsReportedOnceItSucceeds() throws SQLException {
        var jdbc = connectedJdbc(false);
        // Children are left to the database's foreign keys; the identity's own primary key is found in one row.
        when(jdbc.resultSet().next()).thenReturn(true, false);
        var service = service(jdbc.dataSource(), true);
        var identity = new ObjectIdentityImpl(ProjectArtifact.class, generated());

        service.deleteAcl(identity, false);

        assertEquals(List.of(new Notification(SUCCESS, 1, List.of("deleteAcl"), List.of("ProjectArtifact"))),
            listener.notifications);
        verify(aclCache).evictFromCache(identity);
        assertNoGeneratedValueReported();
    }

    @Test
    void updateSidOfAPrincipalIsReported() throws SQLException {
        var service = service(connectedJdbc(true).dataSource(), true);

        service.updateSid(new PrincipalSid(generated()), generated());

        assertEquals(List.of(new Notification(SUCCESS, 1, List.of("updateSid"), List.of("sid"))),
            listener.notifications);
        verify(aclCache).clearCache();
        assertNoGeneratedValueReported();
    }

    @Test
    void updateSidOfAnAuthorityIsReported() throws SQLException {
        var service = service(connectedJdbc(true).dataSource(), true);

        service.updateSid(new GrantedAuthoritySid(generated()), generated());

        assertEquals(List.of(new Notification(SUCCESS, 1, List.of("updateSid"), List.of("sid"))),
            listener.notifications);
        verify(aclCache).clearCache();
        assertNoGeneratedValueReported();
    }

    @Test
    @SuppressWarnings("NullAway") // passes null on purpose to check the rejection of an unsupported SID
    void updateSidOfAnUnsupportedSidIsNotReported() throws SQLException {
        var service = service(connectedJdbc(true).dataSource(), true);
        var newSidName = generated();

        assertThrows(IllegalStateException.class, () -> service.updateSid(mock(Sid.class), newSidName));
        assertThrows(IllegalStateException.class, () -> service.updateSid(null, newSidName));

        assertTrue(listener.notifications.isEmpty());
        verify(aclCache, never()).clearCache();
    }

    @Test
    void failedUpdateSidIsReportedAndRethrown() throws SQLException {
        var service = service(unavailableDataSource(), true);

        assertThrows(CannotGetJdbcConnectionException.class,
            () -> service.updateSid(new PrincipalSid(generated()), generated()));

        assertEquals(List.of(new Notification(FAILURE, 1, List.of("updateSid"), List.of("sid"))),
            listener.notifications);
        verify(aclCache, never()).clearCache();
        assertNoGeneratedValueReported();
    }

    @Test
    void deleteSidOfAnUnknownSidIsNotReported() throws SQLException {
        var service = service(connectedJdbc(false).dataSource(), true);

        assertDoesNotThrow(() -> service.deleteSid(new PrincipalSid(generated())));

        assertTrue(listener.notifications.isEmpty());
        verify(aclCache, never()).clearCache();
    }

    @Test
    void deleteSidOfAKnownSidIsReported() throws SQLException {
        var service = service(connectedJdbc(true).dataSource(), true);

        service.deleteSid(new PrincipalSid(generated()));

        assertEquals(List.of(new Notification(SUCCESS, 1, List.of("deleteSid"), List.of("sid"))),
            listener.notifications);
        verify(aclCache, times(1)).clearCache();
        assertNoGeneratedValueReported();
    }

    @Test
    void deleteSidThatCreatesTheSystemSidIsStillOneChange() throws SQLException {
        var jdbc = connectedJdbc(true);
        // The SID is found, the system-wide SID is not, so it is inserted and then read back.
        when(jdbc.resultSet().next()).thenReturn(true, false, true);
        var service = service(jdbc.dataSource(), true);

        service.deleteSid(new PrincipalSid(generated()));

        verify(jdbc.statement(), times(4)).executeUpdate();
        assertEquals(List.of(new Notification(SUCCESS, 1, List.of("deleteSid"), List.of("sid"))),
            listener.notifications);
        verify(aclCache, times(1)).clearCache();
        assertNoGeneratedValueReported();
    }

    @Test
    void deleteSidWhoseSystemSidIsInsertedConcurrentlyIsStillOneChange() throws SQLException {
        var jdbc = connectedJdbc(true);
        // The SID is found; the system-wide SID is not, another thread inserts it first, and it is then read back.
        when(jdbc.resultSet().next()).thenReturn(true, false, true);
        when(jdbc.statement().executeUpdate()).thenReturn(1)
            .thenThrow(new SQLException("duplicate", "23505"))
            .thenReturn(1);
        var savepoint = mock(Savepoint.class);
        when(jdbc.connection().getAutoCommit()).thenReturn(false);
        when(jdbc.connection().setSavepoint()).thenReturn(savepoint);
        doThrow(new SQLException("released")).when(jdbc.connection()).releaseSavepoint(savepoint);
        var service = service(jdbc.dataSource(), true);

        service.deleteSid(new PrincipalSid(generated()));

        verify(jdbc.connection()).rollback(savepoint);
        assertEquals(List.of(new Notification(SUCCESS, 1, List.of("deleteSid"), List.of("sid"))),
            listener.notifications);
        verify(aclCache).clearCache();
        assertNoGeneratedValueReported();
    }

    @Test
    void deleteSidWhoseSystemSidCannotBeCreatedIsAFailure() throws SQLException {
        var jdbc = connectedJdbc(true);
        when(jdbc.resultSet().next()).thenReturn(true, false);
        when(jdbc.statement().executeUpdate()).thenReturn(1).thenThrow(new SQLException("insert failed"));
        var service = service(jdbc.dataSource(), true);

        assertThrows(DataAccessException.class, () -> service.deleteSid(new PrincipalSid(generated())));

        assertEquals(List.of(new Notification(FAILURE, 1, List.of("deleteSid"), List.of("sid"))),
            listener.notifications);
        verify(aclCache, never()).clearCache();
        assertNoGeneratedValueReported();
    }

    @Test
    void deleteSidWhoseConcurrentSystemSidCannotBeReadIsAFailure() throws SQLException {
        var jdbc = connectedJdbc(true);
        // The insert reports a duplicate, yet the system-wide SID is still not found afterwards.
        when(jdbc.resultSet().next()).thenReturn(true, false, false);
        when(jdbc.statement().executeUpdate()).thenReturn(1).thenThrow(new SQLException("duplicate", "23505"));
        var service = service(jdbc.dataSource(), true);

        assertThrows(DataAccessException.class, () -> service.deleteSid(new GrantedAuthoritySid(generated())));

        assertEquals(List.of(new Notification(FAILURE, 1, List.of("deleteSid"), List.of("sid"))),
            listener.notifications);
        verify(aclCache, never()).clearCache();
    }

    @Test
    void failedDeleteSidIsReportedAndRethrown() throws SQLException {
        var jdbc = connectedJdbc(true);
        var failure = new IllegalStateException("update failed");
        when(jdbc.statement().executeUpdate()).thenThrow(failure);
        var service = service(jdbc.dataSource(), true);

        var thrown = assertThrows(IllegalStateException.class,
            () -> service.deleteSid(new GrantedAuthoritySid(generated())));

        assertSame(failure, thrown);
        assertEquals(List.of(new Notification(FAILURE, 1, List.of("deleteSid"), List.of("sid"))),
            listener.notifications);
        verify(aclCache, never()).clearCache();
        assertNoGeneratedValueReported();
    }

    @Test
    void failedDeleteSidLookupIsReportedAndRethrown() throws SQLException {
        var dataSource = unavailableDataSource();
        var unavailable = assertThrows(SQLException.class, dataSource::getConnection);
        var service = service(dataSource, true);

        var thrown = assertThrows(CannotGetJdbcConnectionException.class,
            () -> service.deleteSid(new PrincipalSid(generated())));

        assertSame(unavailable, thrown.getCause(), "The lookup's own failure is rethrown, not a new one");
        assertEquals(List.of(new Notification(FAILURE, 1, List.of("deleteSid"), List.of("sid"))),
            listener.notifications);
        verify(aclCache, never()).clearCache();
        assertNoGeneratedValueReported();
    }

    @Test
    @SuppressWarnings("NullAway") // passes null on purpose to check that the failure is unchanged without a listener
    void serviceWithoutListenerRethrowsTheSameFailures() throws SQLException {
        var service = service(unavailableDataSource(), false);
        authenticate();

        assertThrows(CannotGetJdbcConnectionException.class,
            () -> service.createAcl(new ObjectIdentityImpl(ProjectArtifact.class, generated())));
        assertThrows(IllegalArgumentException.class, () -> service.createAcl(null));
        assertThrows(IllegalArgumentException.class, () -> service.updateAcl(mock(MutableAcl.class)));
        assertThrows(CannotGetJdbcConnectionException.class,
            () -> service.deleteAcl(new ObjectIdentityImpl(ProjectArtifact.class, generated()), true));
        assertThrows(CannotGetJdbcConnectionException.class,
            () -> service.updateSid(new PrincipalSid(generated()), generated()));
        assertThrows(CannotGetJdbcConnectionException.class, () -> service.deleteSid(new PrincipalSid(generated())));

        assertTrue(listener.notifications.isEmpty());
    }

    @Test
    void serviceWithoutListenerCompletesSidChanges() throws SQLException {
        var service = service(connectedJdbc(true).dataSource(), false);

        assertDoesNotThrow(() -> service.updateSid(new PrincipalSid(generated()), generated()));
        assertDoesNotThrow(() -> service.deleteSid(new GrantedAuthoritySid(generated())));

        verify(aclCache, times(2)).clearCache();
        assertTrue(listener.notifications.isEmpty());
    }

    private TransactionTemplate transaction() {
        return new TransactionTemplate(transactionManager);
    }

    private TransactionTemplate requiresNewTransaction() {
        var template = new TransactionTemplate(transactionManager);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        return template;
    }

    private TransactionTemplate nestedTransaction() {
        var template = new TransactionTemplate(transactionManager);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_NESTED);
        return template;
    }

    private static Notification recordOutsideTransaction(@Nullable String kind, @Nullable String objectType) {
        var single = new RecordingListener();
        AclChangeListener.record(single, kind, objectType, false);
        assertEquals(1, single.notifications.size());
        return single.notifications.getFirst();
    }

    private void assertReceivedSetsAreUnmodifiable() {
        assertEquals(1, listener.receivedKinds.size());
        assertThrows(UnsupportedOperationException.class, () -> listener.receivedKinds.getFirst().add("x"));
        assertThrows(UnsupportedOperationException.class, () -> listener.receivedObjectTypes.getFirst().add("x"));
    }

    /**
     * A random value for a user name, SID name or object identifier, remembered so that no notification may carry it.
     */
    private String generated() {
        var value = UUID.randomUUID().toString();
        generatedValues.add(value);
        return value;
    }

    private void authenticate() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(generated(), null));
    }

    private void assertNoGeneratedValueReported() {
        for (var notification : listener.notifications) {
            var reported = new ArrayList<String>();
            reported.add(notification.outcome());
            reported.addAll(notification.kinds());
            reported.addAll(notification.objectTypes());
            for (var value : generatedValues) {
                for (var text : reported) {
                    assertFalse(text.contains(value), "A notification carries a generated identifier");
                }
            }
        }
    }

    private JdbcMutableAclService service(DataSource dataSource, boolean withListener) {
        // ADMIN is the system-wide role SID the application configures; it is a role name, not a credential.
        var service = new JdbcMutableAclService(dataSource,
            lookupStrategy,
            aclCache,
            new GrantedAuthoritySid("ADMIN"));
        if (withListener) {
            service.setAclChangeListener(listener);
        }
        return service;
    }

    private static DataSource unavailableDataSource() throws SQLException {
        var dataSource = mock(DataSource.class);
        when(dataSource.getConnection()).thenThrow(new SQLException("unavailable"));
        return dataSource;
    }

    /**
     * A JDBC chain whose every query finds one row with key 1 ({@code sidExists}) or none, and whose every update
     * succeeds; a test re-stubs the sequence it needs. Every argument the service passes is non-null, so
     * {@code JdbcTemplate} never asks for parameter metadata.
     */
    private static Jdbc connectedJdbc(boolean sidExists) throws SQLException {
        var metaData = mock(ResultSetMetaData.class);
        when(metaData.getColumnCount()).thenReturn(1);
        var resultSet = mock(ResultSet.class);
        when(resultSet.next()).thenReturn(sidExists);
        when(resultSet.getLong(1)).thenReturn(1L);
        when(resultSet.getMetaData()).thenReturn(metaData);
        var statement = mock(PreparedStatement.class);
        when(statement.executeQuery()).thenReturn(resultSet);
        when(statement.executeUpdate()).thenReturn(1);
        var connection = mock(Connection.class);
        when(connection.getAutoCommit()).thenReturn(true);
        when(connection.prepareStatement(anyString())).thenReturn(statement);
        var dataSource = mock(DataSource.class);
        when(dataSource.getConnection()).thenReturn(connection);
        return new Jdbc(dataSource, connection, statement, resultSet);
    }

    private record Jdbc(DataSource dataSource,
                        Connection connection,
                        PreparedStatement statement,
                        ResultSet resultSet) {
    }

    /**
     * One received notice. The sets are copied into lists, so comparing with a list also proves the sorted order.
     */
    private record Notification(String outcome, int changes, List<String> kinds, List<String> objectTypes) {
    }

    private static final class RecordingListener implements AclChangeListener {

        private final List<Notification> notifications = new ArrayList<>();
        private final List<SortedSet<String>> receivedKinds = new ArrayList<>();
        private final List<SortedSet<String>> receivedObjectTypes = new ArrayList<>();

        @Override
        public void aclChanged(String outcome, int changes, SortedSet<String> kinds, SortedSet<String> objectTypes) {
            notifications.add(new Notification(outcome, changes, List.copyOf(kinds), List.copyOf(objectTypes)));
            receivedKinds.add(kinds);
            receivedObjectTypes.add(objectTypes);
        }
    }

    private static final class ThrowingListener implements AclChangeListener {

        private int calls;

        @Override
        public void aclChanged(String outcome, int changes, SortedSet<String> kinds, SortedSet<String> objectTypes) {
            calls++;
            throw new IllegalStateException("listener failure");
        }
    }

    /**
     * A transaction manager without a resource: it counts what Spring asks of it, so the real synchronization
     * lifecycle (init, suspend, resume, savepoint, savepoint rollback, completion) runs around the code under test.
     * Suspension is supported, so {@code PROPAGATION_REQUIRES_NEW} works. Nesting is allowed and every transaction
     * object is a savepoint manager, so {@code PROPAGATION_NESTED} runs on savepoints, and the savepoints of a
     * transaction status can be created and rolled back to programmatically.
     */
    private static final class NoOpTransactionManager extends AbstractPlatformTransactionManager {

        private int depth;
        private int commits;
        private int rollbacks;
        private int suspends;
        private int resumes;
        private int savepoints;
        private int savepointRollbacks;
        private int savepointReleases;
        private boolean failCommit;

        private NoOpTransactionManager() {
            setNestedTransactionAllowed(true);
        }

        @Override
        protected Object doGetTransaction() {
            return new NoOpTransaction();
        }

        @Override
        protected boolean isExistingTransaction(Object transaction) {
            return depth > 0;
        }

        @Override
        protected void doBegin(Object transaction, TransactionDefinition definition) {
            depth++;
        }

        @Override
        protected Object doSuspend(Object transaction) {
            suspends++;
            return new Object();
        }

        @Override
        protected void doResume(Object transaction, Object suspendedResources) {
            resumes++;
        }

        @Override
        protected void doCommit(DefaultTransactionStatus status) {
            if (failCommit) {
                throw new TransactionSystemException("commit failed");
            }
            commits++;
        }

        @Override
        protected void doRollback(DefaultTransactionStatus status) {
            rollbacks++;
        }

        @Override
        protected void doCleanupAfterCompletion(Object transaction) {
            depth--;
        }

        /**
         * The transaction object. A savepoint is opaque to Spring, so a fresh object stands for each one.
         */
        private final class NoOpTransaction implements SavepointManager {

            @Override
            public Object createSavepoint() {
                savepoints++;
                return new Object();
            }

            @Override
            public void rollbackToSavepoint(Object savepoint) {
                savepointRollbacks++;
            }

            @Override
            public void releaseSavepoint(Object savepoint) {
                savepointReleases++;
            }
        }
    }
}
