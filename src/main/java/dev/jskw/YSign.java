package dev.jskw;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Base64;

/**
 * Sign using via a yubikey's pkcs11 interface without third party libraries.
 */
public class YSign {
    private static final String CONFIG_PKCS_11_LIB = "PKCS11_LIB";
    private static final String CONFIG_NUMBER_OF_SIGNATURES = "NUMBER_OF_SIGNATURES";
    private static final String CONFIG_YUBIKEY_PIN = "YUBIKEY_PIN";
    protected static final char[] YUBIKEY_DEFAULT_PIN = new char[] {'1', '2', '3', '4', '5', '6'};
    public static final String SHA_256_WITH_ECDSA = "SHA256withECDSA";
    public static final String DIGITAL_SIGNATURE_KEY_ALIAS = "X.509 Certificate for Digital Signature";
    private static final AuthProvider AUTH_PROVIDER = getProvider();

    @SuppressWarnings("SpellCheckingInspection") // don't spellcheck driver filenames
    private static final String[] DEFAULT_PKCS_11_LIB_PATHS = new String[] {
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

    public static void main(String[] toBeSignedAscii) {
        byte[][] argsAsBinaryData = Arrays.stream(toBeSignedAscii)
                .map(arg -> arg.getBytes(StandardCharsets.UTF_8))
                .toArray(byte[][]::new);
        byte[] signedData = new byte[0];
        File toBeSignedFile;
        try {
            toBeSignedFile = null;
            if (toBeSignedAscii.length == 1) {
                toBeSignedFile = new File(toBeSignedAscii[0]);
            }

            String message = null;
            // Run multiple times with java -DNUMBER_OF_SIGNATURES=1000
            // 2:05 to do 1000 signatures or ~125ms per signature
            for (int i = 0; i < getIntConfigOrDefault(CONFIG_NUMBER_OF_SIGNATURES, 1); i++) {
                AUTH_PROVIDER.logout();
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
                if (AUTH_PROVIDER != null) {
                    System.out.println("authProvider = " + AUTH_PROVIDER);
                    synchronized (AUTH_PROVIDER) {
                        AUTH_PROVIDER.logout();
                    }
                }
            } catch (LoginException exception) {
                exception.printStackTrace();
            }
        }

        final boolean validSignature;
        if (toBeSignedFile != null && toBeSignedFile.exists()) {
            validSignature = verifyData(signedData, toBeSignedFile);
        } else {
            validSignature = verifyData(signedData, argsAsBinaryData);
        }
        System.out.println("validSignature = " + validSignature);
    }

    private static char[] getYubikeyPin() {
        final char[] pin;
        if (System.getenv().containsKey(CONFIG_YUBIKEY_PIN)) {
            pin = System.getenv(CONFIG_YUBIKEY_PIN).toCharArray();
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
        try (FileInputStream fileInputStream = new FileInputStream(tbsData)) {
            return signData(fileInputStream.readAllBytes());
        }
    }

    /***
     * Verify a signature using the public key from the yubikey.
     *
     * @param signature signature bytes
     * @param signedFile file that was signed
     * @return true if signature is valid
     */
    private static boolean verifyData(byte[] signature, File signedFile) {
        try (FileInputStream fileInputStream = new FileInputStream(signedFile)) {
            return verifyData(signature, fileInputStream.readAllBytes());
        } catch (IOException exception) {
            System.err.println("Failed to read file: " + exception.getMessage());
            return false;
        }
    }

    /***
     * Verify a signature using the public key from the yubikey.
     *
     * @param signature signature bytes
     * @param data data that was signed
     * @return true if signature is valid
     */
    private static boolean verifyData(byte[] signature, byte[]... data) {
        try {
            PublicKey publicKey = getKeyStore().getCertificate(DIGITAL_SIGNATURE_KEY_ALIAS).getPublicKey();
            System.out.println("publicKey = " + publicKey);

            // Verification done outside yubikey, do not use AUTH_PROVIDER
            Signature shaVerifier = Signature.getInstance(SHA_256_WITH_ECDSA);
            shaVerifier.initVerify(publicKey);
            for (byte[] datum : data) {
                shaVerifier.update(datum);
            }
            return shaVerifier.verify(signature);
        } catch (KeyStoreException | NoSuchAlgorithmException | InvalidKeyException | SignatureException exception) {
            System.err.println(exception.getMessage());
            return false;
        }
    }

    /**
     * Provide a java sha256 signer.
     *
     * @return a java sha256 signer.
     */
    private static Signature getContentSigner() throws Exception {
        // Get the key handle for our signing key
        PrivateKey privateKey = (PrivateKey) getKeyStore().getKey(DIGITAL_SIGNATURE_KEY_ALIAS, null);

        // Create a sha256 ECDSA signer
        Signature shaSigner = Signature.getInstance(SHA_256_WITH_ECDSA, AUTH_PROVIDER);
        shaSigner.initSign(privateKey);
        return shaSigner;
    }

    /**
     * Get a keystore that uses our Yubikey Auth Provider
     * @return a keystore that uses our Yubikey Auth Provider
     */
    private static KeyStore getKeyStore() throws KeyStoreException {
        var callback = new KeyStore.CallbackHandlerProtection(getPasswordHandler(getYubikeyPin()));
        var keyStoreBuilder = KeyStore.Builder.newInstance("PKCS11", AUTH_PROVIDER, callback);
        var keyStore = keyStoreBuilder.getKeyStore();
        try {
            keyStore.load(null, null);
        } catch (IOException | NoSuchAlgorithmException | CertificateException keyStoreException) {
            throw new KeyStoreException(keyStoreException.getMessage(), keyStoreException);
        }
        return keyStore;
    }

    /***
     * Get an auth provider that wraps the PKCS11 interface suitable for signatures.
     *
     * @return An auth provider that wraps the PKCS11 interface.
     */
    public static AuthProvider getProvider() {
        try {
            File driver = getDriver();
            String config = MessageFormat.format("--name=yubikey\nlibrary = {0}", driver.getAbsolutePath());
            Method providerConfigureMethod = Provider.class.getMethod("configure", String.class);
            Provider provider = Security.getProvider("SunPKCS11");
            return (AuthProvider) providerConfigureMethod.invoke(provider, config);
        } catch (Exception exception) {
            throw new RuntimeException(exception);
        }
    }

    /***
     * Find the pkcs11 driver for the yubikey.
     *
     * @return the pkcs11 driver.
     */
    public static File getDriver() throws Exception {
        var paths = getStringConfigOrDefault(CONFIG_PKCS_11_LIB, "").split(":");

        if (paths.length == 0 || paths[0].equals("")) {
            // Use default paths if no configured paths set
            paths = DEFAULT_PKCS_11_LIB_PATHS;
        }

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
        return callbacks -> Arrays.stream(callbacks).forEach(callback -> {
            if (callback instanceof PasswordCallback passwordCallback) {
                passwordCallback.setPassword(password);
            }
        });
    }

    public static String getStringConfigOrDefault(String key, String defaultValue) {
        if (System.getenv().containsKey(key)) {
            return System.getenv(key);
        } else if (System.getProperties().containsKey(key)) {
            return System.getProperty(key);
        }

        return defaultValue;
    }

    public static int getIntConfigOrDefault(String key, int defaultValue) {
        if (System.getenv().containsKey(key)) {
            return Integer.parseInt(System.getenv(key));
        }

        return Integer.getInteger(key, defaultValue);
    }
}