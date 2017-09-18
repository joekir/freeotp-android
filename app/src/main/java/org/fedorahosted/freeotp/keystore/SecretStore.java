package org.fedorahosted.freeotp.keystore;


import android.annotation.TargetApi;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.fedorahosted.freeotp.keystore.KeyStoreProxy.ANDROID_KEYSTORE_TYPE;
import static org.fedorahosted.freeotp.keystore.KeyStoreProxy.DEFAULT_KEYSTORE_TYPE;

public class SecretStore {
    private static final String TAG = "SECRET_STORE";
    private KeyStore mKeyStore = null;
    private KeyStore.ProtectionParameter mProtParamSet;
    private KeyStore.ProtectionParameter mProtParamGet;
    private KeyStoreProxy mKeyStoreProxy;

    public SecretStore(KeyStoreProxy proxy){
        mKeyStoreProxy = proxy;

        switch (proxy.keyStore.getType()){
            case ANDROID_KEYSTORE_TYPE:
                initAndroidStore(proxy.keyStore);
                break;
            case DEFAULT_KEYSTORE_TYPE:
                initJKECKSStore(proxy.keyStore, proxy.protectionParameter);
                break;
            default:
                throw new RuntimeException(String.format("Unsupported KeyStore Type: %s", proxy.keyStore.getType()));

        }
    }

    @Deprecated
    private void initJKECKSStore(KeyStore keyStore, KeyStore.ProtectionParameter protectionParameter) {
        mKeyStore = keyStore;
        mProtParamSet = mProtParamGet = protectionParameter;
    }

    @TargetApi(23)
    private void initAndroidStore(KeyStore keyStore) {
        mKeyStore = keyStore;

        try {
            mKeyStore.load(null);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            Log.e(TAG, e.getLocalizedMessage());
        }

        mProtParamSet = new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN).build();
        mProtParamGet = null;
    }

    /**
     * @param key  HMAC key
     * @param algo cryptographic hash algorithm to use for the HMAC
     *             valid strings: SHA1, SHA256, SHA512, MD5
     * @return label for later retrieval from the keystore
     */
    public String addKey(byte[] key, String algo) {
        if (null == key) {
            return null;
        }

        SecretKey secretKey = new SecretKeySpec(key, "Hmac" + algo);
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);

        String label = UUID.randomUUID().toString();
        try {
            mKeyStore.setEntry(label, secretKeyEntry, mProtParamSet);
            mKeyStoreProxy.flushToDisk();
        } catch (KeyStoreException e) {
            Log.e(TAG, e.getLocalizedMessage());
            return null;
        }

        return label;
    }


    /**
     * @param label - key label/alias
     * @return
     */
    public boolean removeKey(String label) {
        try {
            if (!mKeyStore.containsAlias(label)) {
                return true;
            }

            mKeyStore.deleteEntry(label);
            mKeyStoreProxy.flushToDisk();
            return true;
        } catch (KeyStoreException e) {
            Log.e(TAG, e.getLocalizedMessage());
        }

        return false;
    }

    /**
     * @param label GUID of secret to use
     * @param data  data to HMAC
     * @return HMAC of data
     */
    public byte[] labelToHmac(String label, byte[] data) {
        try {
            if (!mKeyStore.containsAlias(label)) {
                return null;
            }

            // I don't understand why the protection parameter for Android is null here.
            // It explodes with the Android one passed in for creation and this is how
            // the official Android example works (see HMAC section):
            // https://developer.android.com/reference/android/security/keystore/KeyProtection.html
            KeyStore.Entry entry = mKeyStore.getEntry(label, mProtParamGet);
            SecretKey secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
            Mac mac = Mac.getInstance(secretKey.getAlgorithm());
            mac.init(secretKey);
            return mac.doFinal(data);

        } catch (KeyStoreException | InvalidKeyException |
                NoSuchAlgorithmException | UnrecoverableEntryException e) {

            Log.e(TAG, e.getLocalizedMessage());
        }

        return null;
    }
}
