package org.openl.security.acl;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Savepoint;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.lang.Nullable;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;

public class JdbcMutableAclService extends org.springframework.security.acls.jdbc.JdbcMutableAclService implements MutableAclService {

    private static final String SELECT_SID_QUERY = "select id from acl_sid where principal=? and sid=?";
    private static final String INSERT_SID_QUERY = "insert into acl_sid (principal, sid) values (?, ?)";
    private static final String DELETE_SID_QUERY = "delete from acl_sid where id=?";
    private static final String UPDATE_OWNER_QUERY = "update acl_object_identity set owner_sid = ? where owner_sid = ?";
    private static final String DELETE_ENTRIES_BY_SID_QUERY = "delete from acl_entry where sid=?";
    private static final String UPDATE_SID_QUERY = "update acl_sid set sid = ? where sid = ? and principal=?";

    private final AclCache aclCache;
    private final Sid relevantSystemWideSid;
    // V11: optional listener told about ACL changes; null when none is defined
    private AclChangeListener aclChangeListener;

    public JdbcMutableAclService(DataSource dataSource,
                                 LookupStrategy lookupStrategy,
                                 AclCache aclCache,
                                 Sid relevantSystemWideSid) {
        super(dataSource, lookupStrategy, aclCache);
        this.aclCache = aclCache;
        this.relevantSystemWideSid = relevantSystemWideSid;
    }

    // V11: injected when an AclChangeListener bean exists; absent otherwise
    @Autowired(required = false)
    public void setAclChangeListener(AclChangeListener aclChangeListener) {
        this.aclChangeListener = aclChangeListener;
    }

    /**
     * Overrides Spring's default implementation to handle concurrent SID creation.
     * <p>
     * The parent implementation uses a non-atomic check-then-act pattern (SELECT, then INSERT),
     * which causes duplicate key errors when multiple threads concurrently grant permissions
     * for the same user/group on different projects.
     * <p>
     * This override executes all SQL on a single JDBC connection using a SAVEPOINT.
     * If the INSERT fails with a duplicate key (another thread inserted the same SID concurrently),
     * the savepoint is rolled back (required by PostgreSQL, which aborts the entire transaction
     * on constraint violations) and the existing SID is retrieved via SELECT.
     */
    @Override
    protected @Nullable Long createOrRetrieveSidPrimaryKey(String sidName, boolean sidIsPrincipal,
            boolean allowCreate) {
        return jdbcOperations.execute((ConnectionCallback<Long>) connection -> {
            // Try to find existing SID
            Long id = selectSidId(connection, sidName, sidIsPrincipal);
            if (id != null) {
                return id;
            }
            if (!allowCreate) {
                return null;
            }
            return insertSidId(connection, sidName, sidIsPrincipal);
        });
    }

    /**
     * Inserts the SID and returns its primary key. A SID inserted concurrently by another thread is taken as it is.
     */
    private static @Nullable Long insertSidId(Connection connection, String sidName, boolean sidIsPrincipal)
            throws SQLException {
        // SID not found — try to insert it with a savepoint to handle concurrent inserts
        var useSavepoint = !connection.getAutoCommit();
        Savepoint savepoint = useSavepoint ? connection.setSavepoint() : null;
        try {
            insertSid(connection, sidName, sidIsPrincipal);
        } catch (SQLException e) {
            if (!isDuplicateKey(e)) {
                throw e;
            }
            // Duplicate key — another thread inserted the same SID concurrently.
            // Rollback to savepoint to restore the transaction state
            // (required by PostgreSQL which aborts after constraint violations).
            if (savepoint != null) {
                connection.rollback(savepoint);
            }
            Long existingId = selectSidId(connection, sidName, sidIsPrincipal);
            if (existingId != null) {
                return existingId;
            }
            throw e;
        } finally {
            if (savepoint != null) {
                try {
                    connection.releaseSavepoint(savepoint);
                } catch (SQLException ignored) {
                    // Savepoint may already be released after rollback
                }
            }
        }
        // Re-select to get the generated id
        return selectSidId(connection, sidName, sidIsPrincipal);
    }

    /**
     * Checks if the SQLException is caused by a duplicate key / unique constraint violation.
     * SQL state class "23" covers integrity constraint violations across all supported databases.
     */
    private static boolean isDuplicateKey(SQLException e) {
        var sqlState = e.getSQLState();
        return sqlState != null && sqlState.startsWith("23");
    }

    private static @Nullable Long selectSidId(Connection connection, String sidName,
            boolean sidIsPrincipal) throws SQLException {
        try (var ps = connection.prepareStatement(SELECT_SID_QUERY)) {
            ps.setBoolean(1, sidIsPrincipal);
            ps.setString(2, sidName);
            try (var rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getLong(1);
                }
            }
        }
        return null;
    }

    private static void insertSid(Connection connection, String sidName,
            boolean sidIsPrincipal) throws SQLException {
        try (var ps = connection.prepareStatement(INSERT_SID_QUERY)) {
            ps.setBoolean(1, sidIsPrincipal);
            ps.setString(2, sidName);
            ps.executeUpdate();
        }
    }

    @Override
    public void deleteSid(Sid sid) {
        var sidId = createOrRetrieveSidPrimaryKey(sid, false);
        if (sidId == null) {
            return;
        }
        // V11: report the SID removal, and a failed one as a failure; the exception is rethrown unchanged
        try {
            jdbcOperations.update(DELETE_ENTRIES_BY_SID_QUERY, sidId);

            var newOwnerSid = createOrRetrieveSidPrimaryKey(relevantSystemWideSid, true);
            jdbcOperations.update(UPDATE_OWNER_QUERY, newOwnerSid, sidId);
            jdbcOperations.update(DELETE_SID_QUERY, sidId);
            aclCache.clearCache();
            AclChangeListener.record(aclChangeListener, "deleteSid", "sid", false);
        } catch (RuntimeException e) {
            AclChangeListener.record(aclChangeListener, "deleteSid", "sid", true);
            throw e;
        }
    }

    public void updateSid(Sid sid, String newSidName) {
        String currentSidName;
        boolean isPrincipal;
        switch (sid) {
            case GrantedAuthoritySid authoritySid -> {
                currentSidName = authoritySid.getGrantedAuthority();
                isPrincipal = false;
            }
            case PrincipalSid principalSid -> {
                currentSidName = principalSid.getPrincipal();
                isPrincipal = true;
            }
            case null, default -> throw new IllegalStateException("Sid type is not supported");
        }

        // V11: report the SID rename, and a failed one as a failure; the exception is rethrown unchanged
        try {
            jdbcOperations.update(UPDATE_SID_QUERY, newSidName, currentSidName, isPrincipal);
            aclCache.clearCache();
            AclChangeListener.record(aclChangeListener, "updateSid", "sid", false);
        } catch (RuntimeException e) {
            AclChangeListener.record(aclChangeListener, "updateSid", "sid", true);
            throw e;
        }
    }

    // V11: report the created ACL to the listener; the parent's exception is rethrown unchanged
    @Override
    public MutableAcl createAcl(ObjectIdentity objectIdentity) {
        try {
            var acl = super.createAcl(objectIdentity);
            AclChangeListener.record(aclChangeListener, "createAcl", typeOf(objectIdentity), false);
            return acl;
        } catch (RuntimeException e) {
            AclChangeListener.record(aclChangeListener, "createAcl", typeOf(objectIdentity), true);
            throw e;
        }
    }

    // V11: report the updated ACL to the listener; the parent's exception is rethrown unchanged
    @Override
    public MutableAcl updateAcl(MutableAcl acl) {
        var objectType = acl == null ? null : typeOf(acl.getObjectIdentity());
        try {
            var updated = super.updateAcl(acl);
            AclChangeListener.record(aclChangeListener, "updateAcl", objectType, false);
            return updated;
        } catch (RuntimeException e) {
            AclChangeListener.record(aclChangeListener, "updateAcl", objectType, true);
            throw e;
        }
    }

    // V11: report the deleted ACL to the listener; the parent recurses into this override for each child
    @Override
    public void deleteAcl(ObjectIdentity objectIdentity, boolean deleteChildren) {
        try {
            super.deleteAcl(objectIdentity, deleteChildren);
            AclChangeListener.record(aclChangeListener, "deleteAcl", typeOf(objectIdentity), false);
        } catch (RuntimeException e) {
            AclChangeListener.record(aclChangeListener, "deleteAcl", typeOf(objectIdentity), true);
            throw e;
        }
    }

    // V11: only the code-defined type name reaches the listener, never the identifier
    private static @Nullable String typeOf(@Nullable ObjectIdentity oid) {
        return oid == null ? null : oid.getType();
    }
}
