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

package io.njiwa.common.rest;

import io.njiwa.common.PersistenceUtility;
import io.njiwa.common.Utils;
import io.njiwa.common.rest.annotations.RestRoles;
import io.njiwa.common.rest.auth.Realm;
import io.njiwa.common.rest.auth.UserData;
import io.njiwa.common.rest.types.*;
import org.picketlink.idm.PartitionManager;

import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceContextType;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.KeyStore;
import java.text.DateFormat;
import java.util.List;
import java.util.Locale;

/**
 * Created by bagyenda on 30/05/2017.
 */

@Path("/rpa")
public class RpaEntity {
    @Inject
    PersistenceUtility po;

    @PersistenceContext(type = PersistenceContextType.TRANSACTION)
    private EntityManager em;

    @Inject
    private UserData userData;

    @Inject
    PartitionManager partitionManager;

    private static String[] headers = new String[] {
      "id", "OID",  "DNS Name","Type", "Date"
    };

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/get/{id}")
    @RestRoles({Roles.SystemUser})
    public RpsElement get(@PathParam("id") Long id) {
        try {
            io.njiwa.common.model.RpaEntity rpa = em.find(io.njiwa.common.model.RpaEntity.class, id);
            return RpsElement.fromEntity(rpa);
        } catch (Exception ex) {
            return null;
        }
    }

    @DELETE
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/delete/{id}")
    @RestRoles({Roles.SystemUser})
    public Boolean delete(@PathParam("id") Long id) {

        Boolean res = po.doTransaction((PersistenceUtility po, EntityManager em) -> {
            io.njiwa.common.model.RpaEntity rpa = em.find(io.njiwa.common.model.RpaEntity.class, id);
            // Delete key store entries then delete it
            if (rpa != null) {
                // XXX partition and users should go, right?
                partitionManager.remove(Realm.getOrCreate(partitionManager,rpa.getDns_name()));

                KeyStore ks = Utils.getKeyStore();
                String xs;
                if ((xs = rpa.getWskeyStoreAlias()) != null) ks.deleteEntry(xs);
                if ((xs = rpa.getsMkeyStoreAlias()) != null) ks.deleteEntry(xs);
                em.remove(rpa);

                return true;
            }
            return false;
        });

        return Utils.toBool(res);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/list")
    @RestRoles({Roles.SystemAdminUser})
    public Object all() {

        List<io.njiwa.common.model.RpaEntity> l = em.createQuery("from RpaEntity ",
                io.njiwa.common.model.RpaEntity.class).getResultList();
        ValueListing result = new ValueListing(headers);
        try {
            for (io.njiwa.common.model.RpaEntity rpa : l) {
                Object[] row = new Object[] {
                       rpa.getId(),
                       rpa.getOid(),
                        rpa.getDns_name(),
                        rpa.getType().toString(),
                        DateFormat.getDateInstance(DateFormat.MEDIUM, Locale.getDefault()).format(rpa.getDateAdded())
                };
                result.addRow(row);
            }
        } catch (Exception ex) {
        }
        return result;
    }


    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/update")
    @RestRoles({Roles.SystemUser})
    public Response update(final RpsElement element) {
        return po.doTransaction((PersistenceUtility po, EntityManager em) -> {
            try {
                io.njiwa.common.model.RpaEntity rpaEntity = element.toEntity(em,partitionManager);
            } catch (RestException ex) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(new RestResponse(RestResponse.Status.Failed,ex.getMessage(),
                                ex.field))
                        .build();
            } catch (Exception ex) {
                Utils.lg.severe("Error creating RPA entity: " + ex.getMessage());
                // ex.printStackTrace();
                return Response.ok(Utils.buildJSON("Error: " + ex.getLocalizedMessage())).build();
            }
           return Response.ok(new RestResponse(RestResponse.Status.Success,"OK") ).build();
        });
    }
}
