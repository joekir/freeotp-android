package org.fedorahosted.freeotp.keystore;

import org.junit.Before;
import org.junit.Test;

import java.security.KeyStore;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class SecretStoreTest {
    private SecretStore secretStore;

    @Before
    public void setUp() throws Exception {
        secretStore = new SecretStore(new KeyStoreProxy());
    }

    @Test
    public void addKey_withNoData_returnsNull() throws Exception {
        String label = secretStore.addKey(null, "sha1");
        assertNull(label);
    }

    @Test
    public void addKey_withKeyData_returnsValidUUID() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        String label = secretStore.addKey(key.getEncoded(), "sha1");
        assertNotNull(label);

        // e.g. f0827d4c-308a-4327-8018-b52116710fbe
        assertTrue(label.matches("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"));
    }

    @Test
    public void removeKey_withNonExistantKey_ReturnsTrue() throws Exception {
        assertTrue(secretStore.removeKey("non-existant"));
    }

    @Test
    public void removeKey_withExistingKey_ReturnsTrue() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        String label = secretStore.addKey(key.getEncoded(), "sha1");
        assertNotNull(label);

        // LABEL still exists
        byte[] result = secretStore.labelToHmac(label, new byte[]{0x1});
        assertNotNull(result);

        assertTrue(secretStore.removeKey(label));

        // LABEL no longer exists
        byte[] result2 = secretStore.labelToHmac(label, new byte[]{0x1});
        assertNull(result2);
    }

    @Test
    public void HMACUsingNamedSecret_RoundTrip() throws Exception {
        // Verifying with test data from https://tools.ietf.org/html/rfc2202

        byte[] key = new byte[]{0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb};
        String label = secretStore.addKey(key, "sha1");
        assertNotNull(label);

        String testData = "Hi There";
        byte[] hmac = secretStore.labelToHmac(label, testData.getBytes());
        assertNotNull(hmac);
        byte[] expected = new byte[]{(byte) 0xb6, 0x17, 0x31, (byte) 0x86, 0x55, 0x05, 0x72, 0x64,
                (byte) 0xe2, (byte) 0x8b, (byte) 0xc0, (byte) 0xb6, (byte) 0xfb, 0x37, (byte) 0x8c,
                (byte) 0x8e, (byte) 0xf1, 0x46, (byte) 0xbe, 0x00};

        assertArrayEquals(expected, hmac);
    }
}