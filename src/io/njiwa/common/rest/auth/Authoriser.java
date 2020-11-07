package io.njiwa.common.rest.auth;

import io.njiwa.common.Utils;
import io.njiwa.common.rest.annotations.RestRoles;
import io.njiwa.common.rest.types.Roles;
import org.apache.deltaspike.security.api.authorization.Secures;
import org.picketlink.Identity;
import org.picketlink.idm.model.basic.User;

import javax.enterprise.context.ApplicationScoped;
import javax.interceptor.InvocationContext;
import java.util.Set;

/*
 * This manages the picketlink RestRoles annotation where used
 */
@ApplicationScoped
public class Authoriser {

    @Secures
    @RestRoles
    public boolean hasRoles(InvocationContext invocationContext, Identity identity,
                            UserData userData) {

        if (identity != null && identity.isLoggedIn() && identity.getAccount() != null) {
            User u = (User) identity.getAccount();
            String uid = u.getLoginName();
            boolean isAdmin = userData.getAdmin(); // isUserAdmin(u);

            // Check if the user is an admin.
            Utils.lg.info(String.format("Checking role for user [%s][is_admin=%s]", uid, isAdmin));
            if (isAdmin)
                return true;
            if (invocationContext.getMethod().isAnnotationPresent(RestRoles.class)) {
                RestRoles ra = invocationContext.getMethod().getAnnotation(RestRoles.class);
                Set<String> roles = userData.getRoles();
                String[] xrl = ra.value();
                for (String xr : xrl) {
                    if (xr.equals(Roles.ALLOWALL))
                        return  true; // ANY is allowed for all users
                    if (roles.contains(xr))
                        return true;

                }

            }
            Utils.lg.info("User [" + uid + "] failed ");
        } else
            Utils.lg.info("Not logged on ");

        return false;
    }

}
