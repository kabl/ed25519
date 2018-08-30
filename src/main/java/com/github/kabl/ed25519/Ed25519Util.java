package com.github.kabl.ed25519;


import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Ed25519Util {

    public static final EdDSAParameterSpec SPEC = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);

    public static KeyPair generateByPassword(byte[] password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] privateKey = md.digest(password);
            byte[] publicKey = privateToPublicKey(privateKey);
            return new KeyPair(privateKey, publicKey);
        }catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static byte[] privateToPublicKey(byte[] privateKey) {
        return new EdDSAPrivateKeySpec(privateKey, SPEC).getA().toByteArray();
    }
}
