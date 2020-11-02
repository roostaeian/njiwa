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

package io.njiwa.common.ws;

import io.njiwa.common.ECKeyAgreementEG;
import io.njiwa.common.ServerSettings;
import io.njiwa.common.Utils;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * Created by bagyenda on 22/11/2016.
 */
public class InitialiserServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final String PFILE = "njiwa.settings"; // The config file

    private static Properties loadProps() {
        java.util.Properties p = new Properties();
        // ClassLoader loader = Properties.class.getClassLoader();

        try {
            InputStream in =  Thread.currentThread().getContextClassLoader().getResourceAsStream(PFILE);
            p.load(in);
            Utils.lg.info(String.format("%s configs loaded", ServerSettings.Constants.serverName));
            return p;
        } catch (Exception ex) {
            Utils.lg.warning(String.format("Failed to load application properties: %s", ex));
        }
        return null;
    }


    /*
    private void outputKeyCerts() throws  Exception {


        KeyStore ciKeyStore = Utils.loadKeyStore("/tmp/ci.jks", "test1234", false);

        // Get CI Private key and cert
        PrivateKey ciPkey = (PrivateKey) ciKeyStore.getKey("ci", "test1234".toCharArray());
        X509Certificate ciCert = (X509Certificate)ciKeyStore.getCertificate("ci");
        byte[] sig = ECKeyAgreementEG.makeCertSigningData(ciCert,
                2,
                ECKeyAgreementEG.CI_DEFAULT_DISCRETIONARY_DATA,

                (byte)0, ECKeyAgreementEG.DST_VERIFY_KEY_TYPE);


        FileOutputStream f = new FileOutputStream("/tmp/ci.cer");
        Utils.DGI.append(f,0x7f21,sig);
       // f.write(os.toByteArray());
        f.close();

        // Get EUM
        X509Certificate certificate = (X509Certificate) Utils.getKeyStore().getCertificate("eum-ec");
        // Now write to file
        sig = ECKeyAgreementEG.makeCertSigningData(certificate,
                2,
                ECKeyAgreementEG.EUM_DEFAULT_DISCRETIONARY_DATA,
                (byte)0, ECKeyAgreementEG.DST_VERIFY_KEY_TYPE);

        // Write to file
        f = new FileOutputStream("/tmp/eum.cer");
        Utils.DGI.append(f,0x7f21,sig);
        f.close();
    }
*/
    public void init(ServletConfig config) throws ServletException {
        // Get keystore from settings file
        Properties properties = loadProps();

        String keystoreFile = (String)properties.getOrDefault("key-file", "/usr/local/etc/key.store"); // config.getInitParameter("keyfile");
        String keystoreType = (String)properties.get("keystore-type"); // config.getInitParameter("keystoretype");
        String keystorePass = (String)properties.getOrDefault("keyfile-password","testing1234"); // config.getInitParameter("keyfilepassword");
        String privkeyalias = (String)properties.getOrDefault("privatekey-alias", "privatekey-alias"); // config.getInitParameter("privatekeyalias");
        String privkeypasswd = (String)properties.getOrDefault("privatekey-password","testing1234"); // config.getInitParameter("privatekeypassword");
        String jcaProvider = (String)properties.get("jca-provider"); // config.getInitParameter("jcaprovider");
        if (jcaProvider != null)
            ServerSettings.Constants.jcaProvider = jcaProvider;

        String keyfile = keystoreFile == null || keystoreFile.charAt(0) != '/' ? config.getServletContext().getRealPath("/WEB-INF/" + keystoreFile) : keystoreFile;

        Utils.setPrivateKeyAliasAndPassword(privkeyalias, privkeypasswd);

        // Set the trust store and key store
        // XXX for now we just use the same file.
        // http://stackoverflow.com/questions/6340918/trust-store-vs-key-store-creating-with-keytool/6341566#6341566
        System.setProperty("javax.net.ssl.keyStore", keyfile);
        System.setProperty("javax.net.ssl.keyStorePassword", keystorePass);
        System.setProperty("javax.net.ssl.trustStore", keyfile);
        System.setProperty("javax.net.ssl.trustStorePassword", keystorePass);

        try {
            Utils.loadKeyStore(keyfile, keystoreType, keystorePass);
            Utils.lg.info("Initialised keystore and trust store locations");

           // outputKeyCerts();
        } catch (Exception ex) {
            Utils.lg.severe("Failed to initialise key store: " + ex.getMessage());
        }

    }
}
