package io.njiwa.common.rest;

import io.njiwa.common.ECKeyAgreementEG;
import io.njiwa.common.ServerSettings;
import io.njiwa.common.Utils;
import io.njiwa.common.rest.annotations.RestRoles;
import io.njiwa.common.rest.auth.UserData;
import io.njiwa.common.rest.types.BasicSettings;
import io.njiwa.common.rest.types.RestResponse;
import io.njiwa.common.rest.types.Roles;

import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceContextType;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

@Path("/settings")
public class Settings {
    @PersistenceContext(type = PersistenceContextType.TRANSACTION)
    private EntityManager em;

    @Inject
    private UserData userData;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/get")
    @RestRoles({Roles.SystemAdminUser})
    public BasicSettings get() {
        return BasicSettings.get();
    }


    @POST
    @Produces(MediaType.APPLICATION_JSON)
    // @Consumes(MediaType.APPLICATION_JSON)
    @Path("/validatecert")
    @RestRoles({Roles.ALLOWALL})
    public Response validate(String certData) {

        try {

            BasicSettings.CertificateInfo certificateInfo = BasicSettings.CertificateInfo.create(certData);
            return Response.ok(certificateInfo).build();
        } catch (Exception ex) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed,
                    ex.getLocalizedMessage())).build();
        }
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/update")
    @RestRoles({Roles.SystemAdminUser})
    public Response save(BasicSettings settings) {
        // Load stuff in order:
        // - ci Cert,  crl, our server cet, our server key, signed data..
        if (settings.oid != null) try {
            ServerSettings.updateOid(em, settings.oid);
        } catch (Exception ex) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed,
                    ex.getLocalizedMessage(), "oid")).build();
        }
        if (settings.ciCertificate != null) {
            X509Certificate ciCert;
            try {
                ciCert = Utils.certificateFromBytes(Utils.Http.decodeDataUri(settings.ciCertificate));
            } catch (Exception ex) {
                return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "ciCertificate")).build();
            }
            try {
                ServerSettings.updateCiCert(em, ciCert);
            } catch (Exception ex) {
                return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "ciCertificate")).build();
            }
        }
        if (settings.serverCertificate != null) {
            X509Certificate cert;
            // Read and validate it.
            try {
                cert = Utils.certificateFromBytes(Utils.Http.decodeDataUri(settings.serverCertificate));
                Utils.checkCertificateTrust(cert);
            } catch (Exception ex) {
                return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "serverCertificate")).build();
            }
            try {
                ServerSettings.updateServerCert(em, cert);
            } catch (Exception ex) {
                return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "serverCertificate")).build();
            }
        }

        if (settings.serverPrivateKey != null) {
            ECPrivateKey key;
            try {
                // First get the certificate, then use the public key params therein to load the skey
                X509Certificate cert = ServerSettings.getServerCert();
                byte[] input = Utils.HEX.h2b(Utils.Http.decodeDataUri(settings.serverPrivateKey));
                key = Utils.ECC.decodePrivateKey(input, cert);
            } catch (Exception ex) {
                return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "serverPrivateKey")).build();
            }
            try {
                ServerSettings.updateServerECDAPrivateKey(em, key);
            } catch (Exception ex) {
                return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "serverPrivateKey")).build();
            }
        }

        // Try and validate signed data
        if (settings.smdpSignedData != null) try {
            byte[] data = Utils.Http.decodeDataUri(settings.smdpSignedData);
            validateSignedData(data, ECKeyAgreementEG.SM_DP_CERTIFICATE_TYPE);
            ServerSettings.updateSMDPSignedData(em, Utils.HEX.b2H(data));
        } catch (Exception ex) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed,
                    ex.getLocalizedMessage(), "smdpSignedData")).build();
        }

        if (settings.smsrSignedData != null) try {
            byte[] data = Utils.Http.decodeDataUri(settings.smsrSignedData);
            validateSignedData(data, ECKeyAgreementEG.SM_SR_CERTIFICATE_TYPE);
            ServerSettings.updateSMSRSignedData(em, Utils.HEX.b2H(data));
        } catch (Exception ex) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed,
                    ex.getLocalizedMessage(), "smsrSignedData")).build();
        }

        try {
            // Reload it.
            settings = BasicSettings.get();
        } catch (Exception ex) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed,
                    ex.getLocalizedMessage())).build();
        }
        return Response.ok(settings).build();
    }

    private static void validateSignedData(byte[] signedData, int certType) throws Exception {
        X509Certificate ciCert, certificate;
        byte[] additionalTLVs;

        byte[] sig = Utils.HEX.h2b(signedData);

        try {
            ciCert = ServerSettings.getCiCertAndAlias().l;
        } catch (Exception ex) {
            throw new Exception("CI " + ex.getLocalizedMessage());
        }

        try {
            certificate = ServerSettings.getServerCert();
        } catch (Exception ex) {
            throw new Exception("Server " + ex.getLocalizedMessage());
        }

        try {
            additionalTLVs = Utils.HEX.h2b(ServerSettings.getAdditionalDiscretionaryDataTlvs());
        } catch (Exception ex) {
            additionalTLVs = null;
        }

        // Make signing data.
        byte[] signingData = ECKeyAgreementEG.makeCertSigningData(certificate, certType, additionalTLVs,
                ECKeyAgreementEG.KEY_AGREEMENT_KEY_TYPE);
        // Verify signature
        Utils.ECC.verifySignature((ECPublicKey) ciCert.getPublicKey(), sig, signingData);

    }
}
