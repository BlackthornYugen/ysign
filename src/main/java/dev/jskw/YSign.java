package dev.jskw;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.text.MessageFormat;
import java.util.Arrays;

public class YSign {
    public static final char[] YUBIKEY_DEFAULT_PIN = new char[] {'1', '2', '3', '4', '5', '6'};
    public static final String SHA_256_WITH_ECDSA = "SHA256withECDSA";
    public static final String DIGITAL_SIGNATURE_KEY_ALIAS = "X.509 Certificate for Digital Signature";

    public static void main(String[] toBeSignedAscii) {
        byte[][] argsAsBinaryData = Arrays.stream(toBeSignedAscii)
                .map(arg -> arg.getBytes(StandardCharsets.UTF_8))
                .toArray(byte[][]::new);
        try {
            File toBeSignedFile = null;
            if (toBeSignedAscii.length == 1) {
                toBeSignedFile = new File(toBeSignedAscii[0]);
            }

            final byte[] signedData;
            if (toBeSignedFile != null && toBeSignedFile.exists()) {
                System.out.println("toBeSignedFile = " + toBeSignedFile);
                signedData = signData(toBeSignedFile);
            } else {
                System.out.println("toBeSignedAscii = " + Arrays.toString(toBeSignedAscii));
                signedData = signData(argsAsBinaryData);
            }
            System.out.println("signedData = " + Base64.toBase64String(signedData));

        } catch (Exception exception) {
            throw new RuntimeException(exception);
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
        ContentSigner contentSigner = getContentSigner();

        // Write to be signed data to signer
        for (byte[] tbsDatum : tbsData) {
            contentSigner.getOutputStream().write(tbsDatum);
        }

        // Generate & Return the signature
        return contentSigner.getSignature();
    }


    /**
     * Sign some data using a Yubikey.
     *
     * @param tbsData the file to be signed
     * @return signed data
     */
    private static byte[] signData(File tbsData) throws Exception {
        ContentSigner contentSigner = getContentSigner();

        // Write to be signed data to signer
        try (FileInputStream fileInputStream = new FileInputStream(tbsData)) {
            fileInputStream.transferTo(contentSigner.getOutputStream());
        }

        // Generate & Return the signature
        return contentSigner.getSignature();
    }

    /**
     * Provide a bouncy castle content signer.
     *
     * @return a bouncy castle content signer.
     */
    private static ContentSigner getContentSigner() throws Exception {
        // Get an auth provider that is powered by the Yubikey PKCS11 driver
        var provider = getProvider(getDriver());
        provider.login(null, getPasswordHandler(getYubikeyPin()));

        // Get a keystore that uses our Yubikey Auth Provider
        var keyStore = KeyStore.getInstance("PKCS11", provider);
        keyStore.load(null, null);

        // Get the key handle for our signing key
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(DIGITAL_SIGNATURE_KEY_ALIAS, null);

        // Get a bouncy castle content signer that supports PKCS11 keys. Most other
        // signers will fail to sign with just a key handle.
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(SHA_256_WITH_ECDSA);
        contentSignerBuilder.setProvider(provider);
        return contentSignerBuilder.build(privateKey);
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