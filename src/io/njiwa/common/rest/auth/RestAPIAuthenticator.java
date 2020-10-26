package io.njiwa.common.rest.auth;

import io.njiwa.common.Utils;
import io.njiwa.common.model.RpaEntity;
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
import org.picketlink.idm.query.IdentityQuery;
import org.picketlink.idm.query.IdentityQueryBuilder;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.List;
import java.util.logging.Logger;
// See https://stackoverflow.com/questions/24764526/picketlink-not-picking-my-user-defined-authenticator
@PicketLink
@Named
@RequestScoped
// @brief The web authenticator thingie...
public class RestAPIAuthenticator extends BaseAuthenticator {
    @Inject
    private DefaultLoginCredentials credentials;
    @PersistenceContext
    private EntityManager em;

    @Inject
    private PartitionManager partitionManager;
    protected Logger log = Logger.getLogger(this.getClass().getSimpleName());

    @Override
    public void authenticate() {
        String user = credentials.getUserId();
        String passwd = credentials.getPassword();
        log.info(String.format("User auth req %s", user));
        // We need to find the correct partition to use...
        Utils.Pair<Partition,RpaEntity> xp = getPartition(user);
        if (xp == null) {
            setStatus(AuthenticationStatus.FAILURE);
            log.info(String.format("Failed to authenticate user %s=>No such domain", user ));
        } else {
            Partition p = xp.k;
            // See http://picketlink.org/gettingstarted/custom_idm_model/ "Creating an Account Type"
            IdentityManager identityManager = partitionManager.createIdentityManager(p);
            User account = getUser(user,identityManager);
            UsernamePasswordCredentials usernamePasswordCredentials = new UsernamePasswordCredentials(user,new Password(passwd));
            try {
                identityManager.validateCredentials(usernamePasswordCredentials);
            } catch (Exception ex) {
                log.warning(String.format("Error validating credentials: %s", ex));
            }
            if (usernamePasswordCredentials.getStatus() == Credentials.Status.VALID) {
                setStatus(AuthenticationStatus.SUCCESS);
                log.info("User authenticated successfully");
                setAccount(account); // Record it.
            } else {
                setStatus(AuthenticationStatus.FAILURE);
                log.info("User authentication failed");
            }
        }
    }

    private Utils.Pair<Partition,RpaEntity> getPartition(String user)
    {

        int i = user.indexOf("@");
        if (i < 0)
            // Default partition
            return new Utils.Pair<>( partitionManager.getPartition(Realm.class,Realm.DEFAULT_REALM),null);
        // Get domain, look up entity
        String domain = user.substring(i+1);
        try {
            RpaEntity rpa = RpaEntity.getByDNS(em, domain);
            long rid = rpa.getId();
            List<Realm> rl = partitionManager.getPartitions(Realm.class);
            // Look for it. Must be a better way.
            for (Realm r: rl)
                if (r.getEntityId() == rid)
                    return new Utils.Pair<>(r, rpa);
        } catch (Exception ex){
            log.warning(String.format("Error: %s", ex));
        }
        return null;
    }

    private User getUser(String user, IdentityManager identityManager)  {
        IdentityQueryBuilder identityQueryBuilder = identityManager.getQueryBuilder();
       IdentityQuery<User>  identityQuery =  identityQueryBuilder.createIdentityQuery(User.class);
       identityQuery.where(identityQueryBuilder.equal(User.LOGIN_NAME,user));

       return identityQuery.getResultCount() > 0 ?  identityQuery.getResultList().get(0) : null;
    }
}
