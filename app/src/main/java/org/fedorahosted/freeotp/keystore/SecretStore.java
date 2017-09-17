package org.fedorahosted.freeotp.keystore;


import android.util.Log;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SecretStore {
    public static final String KEYSTORE_TYPE = "AndroidKeyStore";
    private static final String TAG = "SECRET_STORE";
    private KeyStore mKeyStore = null;
    private KeyStore.ProtectionParameter mPassParam;

    /**
     * @param keyStore
     * @throws KeyStoreException
     *
     *  Only used for testing as KeyStore cannot be mocked so we're using a JKS instead.
     *
     */
    @Deprecated
    public SecretStore(KeyStore keyStore) throws KeyStoreException {
        if (mKeyStore != null) {
            throw new InvalidParameterException("KeyStore already defined");
        }

        initialize(keyStore);
    }

    public SecretStore() throws KeyStoreException {
        initialize(KeyStore.getInstance(KEYSTORE_TYPE));
    }

    private void initialize(KeyStore keyStore){
        mKeyStore = keyStore;

        // TODO wire to android protection model!!
        char[] password = new char[]{'F','r','e','e','O','T','P'}; // pass by ref
        mPassParam = new KeyStore.PasswordProtection(password);
    }

    /**
     * @param key HMAC key
     * @param algo HMAC cryptographic hash algorithm
     * @return label for later retrieval from the keystore
     */
    public String addKey(byte[] key, String algo){
        if (null == key){ return null; }

        SecretKey secretKey = new SecretKeySpec(key, "Hmac" + algo);
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);

        String label = UUID.randomUUID().toString();
        try {
            mKeyStore.setEntry(label, secretKeyEntry, mPassParam);
        } catch (KeyStoreException e) {
            Log.e(TAG, e.getLocalizedMessage());
            return null;
        }

        return label;
    }

    /**
     * @param label GUID of secret to use
     * @param data data to HMAC
     * @return HMAC of data
     */
    public byte[] HmacUsingLabel(String label, byte[] data){
        try {
            if (!mKeyStore.containsAlias(label)){
                return null;
            }

            KeyStore.Entry entry = mKeyStore.getEntry(label, mPassParam);
            SecretKey secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
            Mac mac = Mac.getInstance(secretKey.getAlgorithm());
            mac.init(secretKey);
            return mac.doFinal(data);

        } catch (KeyStoreException |
                 InvalidKeyException |
                 NoSuchAlgorithmException |
                 UnrecoverableEntryException e) {
            Log.e(TAG, e.getLocalizedMessage());
        }

        return null;
    }
}
