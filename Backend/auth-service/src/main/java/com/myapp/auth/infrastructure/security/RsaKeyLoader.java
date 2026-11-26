package com.myapp.auth.infrastructure.security;

import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** Loads the RSA signing key pair from PEM files (PKCS#8 private, X.509 public) or generates one for dev. */
public final class RsaKeyLoader {

    private RsaKeyLoader() {
    }

    public static KeyPair load(Resource publicKeyPem, Resource privateKeyPem) {
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(
                    new X509EncodedKeySpec(decodePem(publicKeyPem, "PUBLIC KEY")));
            RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(
                    new PKCS8EncodedKeySpec(decodePem(privateKeyPem, "PRIVATE KEY")));
            return new KeyPair(publicKey, privateKey);
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("Unable to load JWT signing keys", e);
        }
    }

    public static KeyPair generateEphemeral() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(3072);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("RSA unavailable", e);
        }
    }

    private static byte[] decodePem(Resource resource, String type) throws IOException {
        try (InputStream in = resource.getInputStream()) {
            String pem = new String(in.readAllBytes(), StandardCharsets.US_ASCII)
                    .replace("-----BEGIN " + type + "-----", "")
                    .replace("-----END " + type + "-----", "")
                    .replaceAll("\\s", "");
            return Base64.getDecoder().decode(pem);
        }
    }
}
