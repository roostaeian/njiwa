package io.njiwa.common.rest.auth;

import io.njiwa.common.PersistenceUtility;
import io.njiwa.common.Utils;
import io.njiwa.common.model.Group;
import io.njiwa.common.rest.annotations.RestRoles;
import io.njiwa.common.rest.types.Roles;
import org.apache.deltaspike.security.api.authorization.Secures;
import org.picketlink.Identity;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.RelationshipManager;
import org.picketlink.idm.model.Attribute;
import org.picketlink.idm.model.basic.BasicModel;
import org.picketlink.idm.model.basic.User;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.interceptor.InvocationContext;
import java.io.Serializable;

/*
 * This manages the picketlink RestRoles annotation where used
 */
@ApplicationScoped
public class Authoriser {
    @Inject
    private PersistenceUtility po;

    @Secures
    @RestRoles
    public boolean hasRoles(InvocationContext invocationContext, Identity identity, IdentityManager identityManager, RelationshipManager relationshipManager) {

        if (identity != null && identity.isLoggedIn() && identity.getAccount() != null) {
            User u = (User) identity.getAccount();
            String uid = u.getLoginName();
            boolean isAdmin = isUserAdmin(u);
            // Check if the user is an admin.
            Utils.lg.info(String.format("Checking role for user [%s][is_admin=%s]", uid, isAdmin));
            if (isAdmin)
                return true;
            if (invocationContext.getMethod().isAnnotationPresent(RestRoles.class)) {
                RestRoles ra = invocationContext.getMethod().getAnnotation(RestRoles.class);
                String[] xrl = ra.value();
                for (String xr : xrl) {
                    if (xr.equals(Roles.ALLOWALL))
                        return  true; // ANY is allowed for all users
                    boolean res = po.doTransaction((po, em) -> Group.hasRole(em, uid, xr));
                    if (res) {
                        Utils.lg.info("User [" + uid + "] has role [" + xr + "]");
                        return true;
                    }
                }

            }

            Utils.lg.info("User [" + uid + "] failed ");
        } else
            Utils.lg.info("Not logged on ");

        return false;
    }
    public static final String ADMIN_ATTRIBUTE = "isAdmin";
    // @ check if a user is an admin
    // See https://docs.jboss.org/picketlink/2/2.6.0.Beta2/reference/html_single/ Sec 6.3
    public static boolean isUserAdmin(User u) {
        try{
            Attribute<Serializable> p = u.getAttribute(ADMIN_ATTRIBUTE);
            return (Boolean)p.getValue();
        } catch (Exception ex) {
            return false;
        }
    }
    // @brief mark a user as an admin
    public static void setUserAdminFlag(User u, boolean flag) {
        u.setAttribute(new Attribute<Boolean>(ADMIN_ATTRIBUTE,flag));
    }
}
