package io.njiwa.common.rest.auth;

import io.njiwa.common.Utils;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.rest.types.Roles;
import org.picketlink.annotations.PicketLink;
import org.picketlink.authentication.BaseAuthenticator;
import org.picketlink.credential.DefaultLoginCredentials;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.PartitionManager;
import org.picketlink.idm.credential.Credentials;
import org.picketlink.idm.credential.Password;
import org.picketlink.idm.credential.UsernamePasswordCredentials;
import org.picketlink.idm.model.Partition;
import org.picketlink.idm.model.basic.User;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

// See https://stackoverflow.com/questions/24764526/picketlink-not-picking-my-user-defined-authenticator
@PicketLink
@Named
@RequestScoped
// @brief The web authenticator thingie...
public class Authenticator extends BaseAuthenticator {
    public static final String OWNER_ENTITY_TYPE = "OwnerEntityType";
    public static final String OWNER_ENTITY_ID = "OwnerEntityId";
    protected Logger log = Logger.getLogger(this.getClass().getSimpleName());
    @Inject
    private DefaultLoginCredentials credentials;
    @PersistenceContext
    private EntityManager em;
    @Inject
    private PartitionManager partitionManager;
    @Inject
    private UserData userData;

    @Override
    public void authenticate() {
        String user = credentials.getUserId();
        String passwd = credentials.getPassword();
        log.info(String.format("User auth req %s", user));
        // We need to find the correct partition to use...
        Partition p = Realm.getPartitionFromUser(partitionManager, user);
        if (p == null) {
            setStatus(AuthenticationStatus.FAILURE);
            log.info(String.format("Failed to authenticate user %s=>No such domain", user));
        } else {
            // See http://picketlink.org/gettingstarted/custom_idm_model/ "Creating an Account Type"
            IdentityManager identityManager = partitionManager.createIdentityManager(p);
            User account = Realm.getUser(user, identityManager);
            UsernamePasswordCredentials usernamePasswordCredentials = new UsernamePasswordCredentials(user,
                    new Password(passwd));
            try {
                identityManager.validateCredentials(usernamePasswordCredentials);
            } catch (Exception ex) {
                log.warning(String.format("Error validating credentials: %s", ex));
            }
            if (usernamePasswordCredentials.getStatus() == Credentials.Status.VALID) {
                setStatus(AuthenticationStatus.SUCCESS);
                log.info("User authenticated successfully");
                setAccount(account); // Record it.
                // Update session data. Right?
                if (userData != null) {
                    try {
                        String domain = Realm.getUserDomain(user);
                        RpaEntity rpa = RpaEntity.getByDNS(em, domain);
                        userData.setEntityId(rpa.getId());
                        userData.setEntityType(rpa.getType().toString());
                    } catch (Exception ex) {}
                    // Set roles.
                    Set<String> l = new HashSet<>();
                    boolean isAdmin = Realm.isUserAdmin(account);
                    if (userData.getEntityType().length() == 0) // sys user
                        l.add(isAdmin ? Roles.SystemAdminUser : Roles.SystemUser);
                    else l.add(isAdmin ? Roles.EntityAdminUser : Roles.EntityUser);
                    userData.setRoles(l);
                    userData.setAdmin(isAdmin);
                    userData.setUser(user);
                }
            } else {
                setStatus(AuthenticationStatus.FAILURE);
                log.info("User authentication failed");
            }
        }
    }

}
