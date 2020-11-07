/*
 * Njiwa Open Source Embedded M2M UICC Remote Subscription Manager
 *
 *
 * Copyright (C) 2019 - , Digital Solutions Ltd. - http://www.dsmagic.com
 *
 * Njiwa Dev <dev@njiwa.io>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License.
 */

package io.njiwa.common.rest.auth;

import io.njiwa.common.Utils;
import io.njiwa.common.model.RealmEntity;
import io.njiwa.common.model.RpaEntity;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.PartitionManager;
import org.picketlink.idm.credential.Password;
import org.picketlink.idm.model.AbstractPartition;
import org.picketlink.idm.model.Attribute;
import org.picketlink.idm.model.Partition;
import org.picketlink.idm.model.annotation.AttributeProperty;
import org.picketlink.idm.model.annotation.IdentityPartition;
import org.picketlink.idm.model.annotation.Unique;
import org.picketlink.idm.model.basic.Group;
import org.picketlink.idm.model.basic.Role;
import org.picketlink.idm.model.basic.User;
import org.picketlink.idm.query.IdentityQuery;
import org.picketlink.idm.query.IdentityQueryBuilder;
import org.picketlink.idm.query.QueryParameter;

import javax.persistence.EntityManager;
import java.io.Serializable;


// @brief custom realm. Each RpaEntity defines one realm. The loginName should be user@realm (could be a domain)
@IdentityPartition(supportedTypes = {User.class, Role.class, Group.class})
public class Realm extends AbstractPartition {

    public static final QueryParameter ENTITY = QUERY_ATTRIBUTE.byName("entityId");
    public static final String ADMIN_ATTRIBUTE = "isAdmin";
    public static final String DEFAULT_REALM = "default"; // Empty string as default realm
    public static final long DEFAULT_REALM_ENTITY_ID = -1;
    @AttributeProperty()
    @Unique
    private long entityId; // Id into the DB for the thingie. Default entity has id <= 0

    private Realm() {
        this(null);
    }

    public Realm(String name) {
        super(name);
        entityId = DEFAULT_REALM_ENTITY_ID;
    }

    public static Partition getPartitionFromUser(PartitionManager partitionManager, String user) {
        int i = user.indexOf("@");
        if (i < 0) return partitionManager.getPartition(Realm.class, DEFAULT_REALM);
        else {
            String domain = user.substring(i + 1);
            return getOrCreate(partitionManager, domain);
        }
    }

    /**
     * @param u
     * @return
     * @brief check if user is an admin  - See https://docs.jboss.org/picketlink/2/2.6.0.Beta2/reference/html_single/
     * Sec 6.3
     */
    public static boolean isUserAdmin(User u) {
        try {
            Attribute<Serializable> p = u.getAttribute(ADMIN_ATTRIBUTE);
            return (Boolean) p.getValue();
        } catch (Exception ex) {
            return false;
        }
    }

    /**
     * @param u
     * @param flag
     * @brief mark a user as an admin
     */
    public static void setUserAdminFlag(User u, boolean flag) {
        u.setAttribute(new Attribute<Boolean>(ADMIN_ATTRIBUTE, flag));
    }

    public static User getUser(String user, IdentityManager identityManager) {
        IdentityQueryBuilder identityQueryBuilder = identityManager.getQueryBuilder();
        IdentityQuery<User> identityQuery = identityQueryBuilder.createIdentityQuery(User.class);
        identityQuery.where(identityQueryBuilder.equal(User.LOGIN_NAME, user));

        return identityQuery.getResultCount() > 0 ? identityQuery.getResultList().get(0) : null;
    }

    public static Utils.Pair<Partition, RpaEntity> getUserPartition(EntityManager em,
                                                                    PartitionManager partitionManager, String user) {

        int i = user.indexOf("@");
        if (i < 0)
            // Default partition
            return new Utils.Pair<>(partitionManager.getPartition(Realm.class, DEFAULT_REALM), null);
        // Get domain, look up entity
        String domain = user.substring(i + 1);
        try {
            RpaEntity rpa = RpaEntity.getByDNS(em, domain);
            long rid = rpa.getId();
            String partionId = RealmEntity.getPartitionIdForRpaEntity(em, rid);

            Partition partition = partitionManager.getPartition(Realm.class, partionId);
            return new Utils.Pair<>(partition, rpa);
        } catch (Exception ex) {
            Utils.lg.warning(String.format("Error: %s", ex));
        }
        return null;
    }

    public static String getUserDomain(String user)
    {
        int i = user.indexOf("@");
        if (i < 0)
            return "";
        return user.substring(i + 1);
    }

    public static void addUser(PartitionManager partitionManager, String user, String password, boolean isAdmin) {

        User u = new User(user);

        Partition partition = getPartitionFromUser(partitionManager, user);
        IdentityManager identityManager = partitionManager.createIdentityManager(partition); // Add to default partition

        setUserAdminFlag(u, isAdmin);
        identityManager.add(u);
        identityManager.updateCredential(u, new Password(password));
    }

    public static void setUserPassword(PartitionManager partitionManager, String user, String password) {
        Partition partition = getPartitionFromUser(partitionManager, user);
        IdentityManager identityManager = partitionManager.createIdentityManager(partition);
        User u = getUser(user, identityManager);
        identityManager.updateCredential(u, new Password(password));
    }

    public static Partition getOrCreate(PartitionManager partitionManager, String realm) {
        Partition partition;
        try {
            partition = partitionManager.getPartition(Realm.class, realm);
        } catch (Exception ex) {
            partition = null;
        }
        if (partition == null) {
            partitionManager.add(new Realm(realm));
            partition = partitionManager.getPartition(Realm.class, realm);
        }
        return partition;
    }

    public long getEntityId() {
        return entityId;
    }

    public void setEntityId(long entityId) {
        this.entityId = entityId;
    }
}
