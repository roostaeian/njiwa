package io.njiwa.common.model;

import io.njiwa.common.rest.auth.Realm;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.picketlink.idm.jpa.annotations.AttributeValue;
import org.picketlink.idm.jpa.annotations.entity.IdentityManaged;
import org.picketlink.idm.jpa.model.sample.simple.PartitionTypeEntity;


import javax.persistence.*;

// @brief JPA mapping for picketlink realm..
// See http://picketlink.org/gettingstarted/custom_idm_model/ - jump to "mapping jpa entities to store the identity model"
@IdentityManaged(Realm.class)
@Entity
@Table(name="ui_user_realms",  uniqueConstraints = {
        @UniqueConstraint(columnNames = {"entity_id"})
})
@DynamicUpdate
@DynamicInsert
public class RealmEntity extends PartitionTypeEntity {
    private static final long serialVersionUID = -537779599507513419L;

    @AttributeValue(name="entityId")
    @Column(name="entity_id")
    private Long entityId; // link to entities


    public Long getEntityId() {
        return entityId;
    }

    public void setEntityId(Long entityId) {
        this.entityId = entityId;
    }
}
