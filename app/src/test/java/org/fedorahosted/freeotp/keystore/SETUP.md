### Setting up the test keystore

We're using JKECKS (I have no idea what the initialism expands to!) instead of the AndroidKeyStore for our local testing as they implement the same interface.
JKECKS in favour of JKS as it supports symmetric key storage.

```
# To create using keytool you need to add an inital key then you can delete
$ keytool -genseckey -keystore fakeKeyStore.jck -storetype jceks -storepass freeotp -keyalg AES -keysize 256 -alias jceksaes -keypass password 
$ keytool -list -keystore fakeKeyStore.jck -storetype jceks -storepass freeotp # should show 1 key
$ keytool -delete -keystore fakeKeyStore.jck -storetype jceks -storepass freeotp -alias jceksaes
$ keytool -list -keystore fakeKeyStore.jck -storetype jceks -storepass freeotp # should be clear of keys
```
