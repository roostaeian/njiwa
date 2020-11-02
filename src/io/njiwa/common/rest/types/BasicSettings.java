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

package io.njiwa.common.rest.types;

import io.njiwa.common.ServerSettings;
import io.njiwa.common.Utils;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import static io.njiwa.common.ECKeyAgreementEG.AUTHORITY_KEY_IDENTIFIER_OID;
import static io.njiwa.common.ECKeyAgreementEG.SUBJECT_KEY_IDENTIFIER_OID;

// @brief server settings
public class BasicSettings {

    public String ciCertificate; // CI certificate, X509 PEM-encoded for inbound, for outbound see ciCertInfo.
    public String crl; // Certificate revocation list. X509 PEM encoded for inbound, for outbound see crlInfo.
    public String oid; // SM-SR/SM-DP OID. In/out.
    public String serverCertificate; // SM-DP/SM-DP Certificate. X509 PEM-encoded for inbound. Must be signed by CI. for outbound, see serverCertInfo;
    public String serverPrivateKey; // ECDSA Private key for the server. Inbound format is hex, for outbound, not set.
    public String smdpSignedData; // Signed SM-DP info for keyagreement (table 77 of SGP 02). Inbound is hex-coded. Outbound will be non-null if set.

    public String smsrSignedData; // Signed SM-SR info for keyagreement (table 39 of SGP 02). Inbound is hex-coded. Outbound will be non-null if set.

    public String additionalDiscretionaryDataTlvs; // Additional TLVs, discretionary data. HEX-coded.
    // Out data:
    CertificateInfo ciCertificateInfo;
    CertificateInfo serverCertificateInfo;
    CRLInfo crlInfo;

    public static class CertificateInfo {
        public BigInteger serialNumber;
        public String subject;
        public String keyIdentifier;
        public String issuer;
        public String authorityKeyIdentifier;
        public String signatureAlgorithm;

        public static CertificateInfo create(X509Certificate certificate) {
            CertificateInfo certificateInfo = new CertificateInfo();

            certificateInfo.serialNumber = certificate.getSerialNumber();
            certificateInfo.subject = certificate.getSubjectX500Principal().getName();
            byte[] subjectIdentifier = certificate.getExtensionValue(SUBJECT_KEY_IDENTIFIER_OID);
            try {
                certificateInfo.keyIdentifier = Utils.formatHexBytes(Utils.HEX.b2H(subjectIdentifier), ':');
            } catch (Exception ex) {}
            byte[] caid = certificate.getExtensionValue(AUTHORITY_KEY_IDENTIFIER_OID);
            try {
                certificateInfo.authorityKeyIdentifier = Utils.formatHexBytes(Utils.HEX.b2H(caid), ':');
            } catch (Exception ex) {}
            certificateInfo.issuer = certificate.getIssuerX500Principal().toString();
            certificateInfo.signatureAlgorithm = certificate.getSigAlgName();

            return certificateInfo;
        }

        public static CertificateInfo create(String certdata)  throws Exception {
            X509Certificate certificate = Utils.certificateFromBytes(Utils.Http.decodeDataUri(certdata));
            return create(certificate);
        }
    }

    public static class CRLInfo {
        public String issuer;
        public Date updatedOn;
        public Date nextUpdateOn;
        public Integer version;
        public Set<BigInteger> revocationList;

        public static CRLInfo create(String crldata) {
            try {
                X509CRL crl = Utils.parseCRL(crldata);
                return create(crl);
            } catch (Exception ex) {
                return null;
            }
        }

        public static CRLInfo create(X509CRL crl) {
            CRLInfo crlInfo = new CRLInfo();
            crlInfo.issuer = crl.getIssuerX500Principal().toString();
            crlInfo.updatedOn = crl.getThisUpdate();
            crlInfo.nextUpdateOn = crl.getNextUpdate();
            crlInfo.version = crl.getVersion();
            crlInfo.revocationList = new HashSet<>();
            for (X509CRLEntry entry: crl.getRevokedCertificates())
                crlInfo.revocationList.add(entry.getSerialNumber());

            return crlInfo;
        }
    }

    /**
     * @brief return the current settings
     * @return
     */
    public static BasicSettings get() {
        BasicSettings settings = new BasicSettings();
        try {
            settings.ciCertificateInfo = CertificateInfo.create(ServerSettings.getCiCertAndAlias().l);
        } catch (Exception ex) {}
        try {
            settings.serverCertificateInfo = CertificateInfo.create(ServerSettings.getServerCert());
        } catch (Exception ex) {}
        try {
            settings.crlInfo = CRLInfo.create(ServerSettings.getCRL());
        } catch (Exception ex) {}
        settings.oid = ServerSettings.getOid();
        try {
            settings.smdpSignedData = Utils.HEX.b2H(ServerSettings.getSMDPSignedData());
        } catch (Exception ex) {}
        try {
            settings.smsrSignedData = Utils.HEX.b2H(ServerSettings.getSMSRSignedData());
        } catch (Exception ex){}
        try {

        } catch (Exception ex) {
            settings.additionalDiscretionaryDataTlvs = Utils.HEX.b2H(ServerSettings.getAdditionalDiscretionaryDataTlvs());
        }
        return settings;
    }
}
