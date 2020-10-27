package io.njiwa.common.rest.auth;

import io.njiwa.common.PersistenceUtility;
import io.njiwa.common.ServerSettings;
import io.njiwa.common.model.Group;
import io.njiwa.common.rest.types.Roles;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.PartitionManager;
import org.picketlink.idm.credential.Password;
import org.picketlink.idm.model.Partition;
import org.picketlink.idm.model.basic.BasicModel;
import org.picketlink.idm.model.basic.User;

import javax.annotation.PostConstruct;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import java.util.HashSet;

@Singleton
@Startup
public class Initialiser {
    private static final String DEFAULT_ADMIN_GROUP = "Administrators";

    @Inject
    PersistenceUtility po;
    @Inject
    EntityManager em;

    @Inject
    private PartitionManager partitionManager;

    // Create users

    public void createUsers() {

        try {
            createGroup(DEFAULT_ADMIN_GROUP);
        } catch (Exception ex) {
        } // Ignore error

        try {
            assignGroupRoles(DEFAULT_ADMIN_GROUP, new String[]{Roles.EntityUser, Roles.EntityAdminUser});
        } catch (Exception ex) {
        } // Ignore error


        try {
          // delUser("admin");
            createUser("admin", DEFAULT_ADMIN_GROUP);
        } catch (Exception ex) {
        } // Ignore error

    }

    @PostConstruct
    public void initFn() {
        try {
            ServerSettings.loadProps(em); // load server settings
        } catch (Exception ex) {}
        createUsers();
    }

    private  void delUser(String admin)
    {
        IdentityManager identityManager = partitionManager.createIdentityManager();
        User u = BasicModel.getUser(identityManager,admin);
        identityManager.remove(u);
    }

    private void createUser(String admin, final String defaultAdminGroup) {
        User u = new User(admin);
        Partition partition = partitionManager.getPartition(Realm.class,Realm.DEFAULT_REALM);
        IdentityManager identityManager = partitionManager.createIdentityManager(partition); // Add to default partition

        identityManager.add(u);
        identityManager.updateCredential(u, new Password("test"));

        po.doTransaction((po, em) -> {
            Group g = Group.getByName(em, defaultAdminGroup);
            g.assignUser(admin);
            return null;
        });
    }

    private void assignGroupRoles(String defaultAdminGroup, final String[] slist) {
        po.doTransaction((po, em) -> {
            Group g = Group.getByName(em, defaultAdminGroup);
            HashSet<String> sh = new HashSet<>();
            for (String s : slist)
                sh.add(s);
            g.setRoles(sh);
            return null;
        });
    }

    private void createGroup(String defaultAdminGroup) {
        final Group g = new Group();
        g.setName(defaultAdminGroup);
        po.doTransaction((po, em) -> {
            em.persist(g);
            return g;
        });
    }

}
