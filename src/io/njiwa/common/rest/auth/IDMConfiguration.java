package io.njiwa.common.rest.auth;

import org.picketlink.annotations.PicketLink;
import org.picketlink.idm.PartitionManager;
import org.picketlink.idm.config.IdentityConfiguration;
import org.picketlink.idm.config.IdentityConfigurationBuilder;
import org.picketlink.idm.internal.DefaultPartitionManager;
import org.picketlink.idm.model.Partition;
import org.picketlink.idm.model.Relationship;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.picketlink.idm.jpa.model.sample.simple.*;

@ApplicationScoped
public class IDMConfiguration {
    @Produces
    @PersistenceContext(unitName = "default")
    private EntityManager em;

    @Inject
    private PartitionManager partitionManager;

    private IdentityConfiguration identityConfiguration;

    /*
     * Since we are using JPAIdentityStore to store identity-related data, we must provide it with an EntityManager
     * via a
     * producer method or field annotated with the @PicketLink qualifier.
     */
    @Produces
    @PicketLink
    public EntityManager getPicketLinkEntityManager() {
        return em;
    }

    /**
     * This method uses the IdentityConfigurationBuilder to create an IdentityConfiguration, which
     * defines how PicketLink stores identity-related data.  In this particular example, a
     * JPAIdentityStore is configured to allow the identity data to be stored in a relational database
     * using JPA.
     */
    @Produces
    IdentityConfiguration initConfig() {
        IdentityConfigurationBuilder builder = new IdentityConfigurationBuilder();
        builder.named("default").stores().jpa().supportType(Realm.class).mappedEntity(AccountTypeEntity.class,
                RoleTypeEntity.class, GroupTypeEntity.class, IdentityTypeEntity.class, RelationshipTypeEntity.class,
                RelationshipIdentityTypeEntity.class, PartitionTypeEntity.class, PasswordCredentialTypeEntity.class,
                AttributeTypeEntity.class).supportGlobalRelationship(Relationship.class)
                //  .addContextInitializer(this.contextInitializer)
                .supportAllFeatures();
        identityConfiguration = builder.build();


        return identityConfiguration;
    }

    @PostConstruct
    public void initDefaultPartition() {

        // Create the default realm
        // See https://docs.jboss.org/picketlink/2/latest/reference/html-single
        ///#Interacting_with_PicketLink_IDM_During_Application_Startup
        // Sec 7.1.3
        try {
            Realm defaultPartition = partitionManager.getPartition(Realm.class, Realm.DEFAULT_REALM);
            if (defaultPartition == null) {
                defaultPartition = new Realm(Realm.DEFAULT_REALM);
                partitionManager.add(defaultPartition);
            }
        } catch (Exception ex) {
            String xs = ex.getLocalizedMessage();
        }
    }
}
