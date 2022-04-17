package dev.jskw;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Base64;

/**
 * Sign using via a yubikey's pkcs11 interface without third party libraries.
 */
public class YSign {
    public static final char[] YUBIKEY_DEFAULT_PIN = new char[] {'1', '2', '3', '4', '5', '6'};
    public static final String SHA_256_WITH_ECDSA = "SHA256withECDSA";
    public static final String DIGITAL_SIGNATURE_KEY_ALIAS = "X.509 Certificate for Digital Signature";
    private static final ThreadLocal<AuthProvider> AUTH_PROVIDER = ThreadLocal.withInitial(() -> {
        try {
            return getProvider(getDriver());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    });

    public static void main(String[] toBeSignedAscii) {
        byte[][] argsAsBinaryData = Arrays.stream(toBeSignedAscii)
                .map(arg -> arg.getBytes(StandardCharsets.UTF_8))
                .toArray(byte[][]::new);
        try {
            File toBeSignedFile = null;
            if (toBeSignedAscii.length == 1) {
                toBeSignedFile = new File(toBeSignedAscii[0]);
            }

            String message = null;
            // Run multiple times with java -DNUMBER_OF_SIGNATURES=1000
            // 2:05 to do 1000 signatures or ~125ms per signature
            for (int i = 0; i < Integer.getInteger("NUMBER_OF_SIGNATURES", 1); i++) {
                YSign.AUTH_PROVIDER.get().logout();
                final byte[] signedData;
                if (toBeSignedFile != null && toBeSignedFile.exists()) {
                    message = "toBeSignedFile = " + toBeSignedFile;
                    signedData = signData(toBeSignedFile);
                } else {
                    message = "toBeSignedAscii = " + Arrays.toString(toBeSignedAscii);
                    signedData = signData(argsAsBinaryData);
                }
                System.out.println("signedData = " + Base64.getEncoder().encodeToString(signedData));
            }
            System.out.println(message);
        } catch (Exception exception) {
            throw new RuntimeException(exception);
        } finally {
            try {
                synchronized (AUTH_PROVIDER) {
                    AuthProvider authProvider = YSign.AUTH_PROVIDER.get();
                    if (authProvider != null) {
                        authProvider.logout();
                        System.out.println("authProvider = " + authProvider);
                    }
                }
            } catch (LoginException exception) {
                exception.printStackTrace();
            }
        }
    }

    private static char[] getYubikeyPin() {
        final char[] pin;
        if (System.getenv().containsKey("YUBIKEY_PIN")) {
            pin = System.getenv("YUBIKEY_PIN").toCharArray();
        } else {
            pin = YUBIKEY_DEFAULT_PIN;
        }
        return pin;
    }

    /**
     * Sign some data using a Yubikey.
     *
     * @param tbsData the to be signed data
     * @return signed data
     */
    private static byte[] signData(byte[]... tbsData) throws Exception {
        var contentSigner = getContentSigner();

        // Write to be signed data to signer
        for (byte[] tbsDatum : tbsData) {
            contentSigner.update(tbsDatum);
        }

        // Generate & Return the signature
        return contentSigner.sign();
    }


    /**
     * Sign some data using a Yubikey.
     *
     * @param tbsData the file to be signed
     * @return signed data
     */
    private static byte[] signData(File tbsData) throws Exception {
        var contentSigner = getContentSigner();

        // Write to be signed data to signer
        try (FileInputStream fileInputStream = new FileInputStream(tbsData)) {
            contentSigner.update(fileInputStream.readAllBytes());
        }

        // Generate & Return the signature
        return contentSigner.sign();
    }

    /**
     * Provide a java sha256 signer.
     *
     * @return a java sha256 signer.
     */
    private static Signature getContentSigner() throws Exception {
        // Get an auth provider that is powered by the Yubikey PKCS11 driver
        var authProvider = AUTH_PROVIDER.get();

        // Get a keystore that uses our Yubikey Auth Provider
        var callback = new KeyStore.CallbackHandlerProtection(getPasswordHandler(getYubikeyPin()));
        var keyStoreBuilder = KeyStore.Builder.newInstance("PKCS11", authProvider, callback);
        var keyStore = keyStoreBuilder.getKeyStore();
        keyStore.load(null, null);

        // Get the key handle for our signing key
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(DIGITAL_SIGNATURE_KEY_ALIAS, null);

        // Create a sha256 ECDSA signer
        Signature shaSigner = Signature.getInstance(SHA_256_WITH_ECDSA, authProvider);
        shaSigner.initSign(privateKey);
        return shaSigner;
    }

    /***
     * Get an auth provider that wraps the PKCS11 interface suitable for signatures.
     *
     * @param driver the PKCS11 driver used to communicate with the Yubikey.
     * @return An auth provider that wraps the PKCS11 interface.
     */
    public static AuthProvider getProvider(File driver) throws Exception {
        String config = MessageFormat.format("--name=yubikey\nlibrary = {0}", driver.getAbsolutePath());
        Method providerConfigureMethod = Provider.class.getMethod("configure", String.class);
        Provider provider = Security.getProvider("SunPKCS11");
        return (AuthProvider) providerConfigureMethod.invoke(provider, config);
    }

    /***
     * Find the pkcs11 driver for the yubikey.
     *
     * @return the pkcs11 driver.
     */
    public static File getDriver() throws Exception {
        @SuppressWarnings("SpellCheckingInspection") // don't spellcheck driver filenames
        var paths = new String[] {
                // Linux 32bit
                "/usr/lib/libykcs11.so",
                "/usr/lib/libykcs11.so.1",
                "/usr/lib/i386-linux-gnu/libykcs11.so",
                "/usr/lib/arm-linux-gnueabi/libykcs11.so",
                "/usr/lib/arm-linux-gnueabihf/libykcs11.so",

                // Linux 64bit
                "/usr/lib64/libykcs11.so",
                "/usr/lib64/libykcs11.so.1",
                "/usr/lib/x86_64-linux-gnu/libykcs11.so",
                "/usr/lib/aarch64-linux-gnu/libykcs11.so",
                "/usr/lib/mips64el-linux-gnuabi64/libykcs11.so",
                "/usr/lib/riscv64-linux-gnu/libykcs11.so",

                // Windows 32bit
                System.getenv("ProgramFiles(x86)") + "/Yubico/Yubico PIV Tool/bin/libykcs11.dll",

                // Windows 64bit
                System.getenv("ProgramFiles") + "/Yubico/Yubico PIV Tool/bin/libykcs11.dll",

                // OSX
                "/usr/local/lib/libykcs11.dylib",
        };

        for (String path : paths) {
            File pkcs11Path = new File(path);
            if (pkcs11Path.exists()) {
                return pkcs11Path;
            }
        }

        throw new Exception("PKCS11 driver not found.");
    }

    /**
     * Return a given password for any PasswordCallbacks.
     *
     * @param password the password provided to the PasswordCallbacks
     * @return A callback handler that will respond to Password Callbacks
     *         with the given password.
     */
    public static CallbackHandler getPasswordHandler(char[] password) {
        return (callbacks) -> Arrays.stream(callbacks).forEach(callback -> {
            if (callback instanceof PasswordCallback) {
                ((PasswordCallback) callback).setPassword(password);
            }
        });
    }
}