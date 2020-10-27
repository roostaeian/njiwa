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

import org.picketlink.idm.model.AbstractPartition;
import org.picketlink.idm.model.annotation.AttributeProperty;
import org.picketlink.idm.model.annotation.IdentityPartition;
import org.picketlink.idm.model.annotation.Unique;
import org.picketlink.idm.model.basic.Group;
import org.picketlink.idm.model.basic.Role;
import org.picketlink.idm.model.basic.User;
import org.picketlink.idm.query.QueryParameter;


// @brief custom realm. Each RpaEntity defines one realm. The loginName should be user@realm (could be a domain)
@IdentityPartition(supportedTypes = {User.class, Role.class, Group.class})
public class Realm extends AbstractPartition {

    public static final QueryParameter ENTITY = QUERY_ATTRIBUTE.byName("entityId");
    @AttributeProperty()
    @Unique
    private long entityId; // Id into the DB for the thingie. Default entity has id <= 0

    public static final String DEFAULT_REALM = "default"; // Empty string as default realm
    public static final long DEFAULT_REALM_ENTITY_ID = -1;
    private Realm() {
        this(null);
    }
    public Realm(String name) {
        super(name);
        entityId = DEFAULT_REALM_ENTITY_ID;
    }
    public long getEntityId() {
        return entityId;
    }

    public void setEntityId(long entityId) {
        this.entityId = entityId;
    }
}
