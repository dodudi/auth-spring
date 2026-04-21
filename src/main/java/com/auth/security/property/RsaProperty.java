package com.auth.security.property;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Getter
@Component
public class RsaProperty {

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public RsaProperty(
            @Value("${auth.rsa.private-key}")
            String privateKeyBase64,

            @Value("${auth.rsa.public-key}")
            String publicKeyBase64
    ) {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            privateKey = (RSAPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyBase64)));
            publicKey = (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyBase64)));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load RSA keys", e);
        }
    }
}
