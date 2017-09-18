package org.fedorahosted.freeotp.keystore;

import android.annotation.TargetApi;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 *   The Android KeyStore is not mockable as it is final, and hence unit testing is difficult.
 *   To accommodate this, a proxy is used here to inject a different keystore for testing.
 */
public class KeyStoreProxy {
    static final String ANDROID_KEYSTORE_TYPE = "AndroidKeyStore";
    static final String DEFAULT_KEYSTORE_TYPE = "JCEKS";

    KeyStore keyStore;
    KeyStore.ProtectionParameter protectionParameter;
    private String defaultKeyStorePath;
    private final char[] defaultKeyStorePassword = new char[]{'f','r','e','e','o','t','p'};

    public KeyStoreProxy(){
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_TYPE);
            protectionParameter = null;
        } catch (KeyStoreException e) {
            initDefaultKeyStore();
        }
    }

    @TargetApi(19)
    private void initDefaultKeyStore() {
        try {
            keyStore = KeyStore.getInstance(DEFAULT_KEYSTORE_TYPE);
            defaultKeyStorePath = new File("fakeKeyStore.jck").getAbsolutePath();
            try (FileInputStream fis = new FileInputStream(defaultKeyStorePath)) {
                keyStore.load(fis, defaultKeyStorePassword);
                protectionParameter = new KeyStore.PasswordProtection(defaultKeyStorePassword);
            }
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     *  Used exclusively as a callback for the SecretStore to keep the JCEKS store up to date
     *  The Android KeyStore is automatically persisted.
     */
    @TargetApi(19)
    void flushToDisk(){
        if (!keyStore.getType().equals(ANDROID_KEYSTORE_TYPE)) {
            try (FileOutputStream fos = new FileOutputStream(defaultKeyStorePath)) {
                keyStore.store(fos, defaultKeyStorePassword);
            } catch (CertificateException | NoSuchAlgorithmException | IOException | KeyStoreException e) {
                e.printStackTrace();
            }
        }
    }
}
