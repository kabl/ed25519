package com.github.kabl.ed25519;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import java.security.MessageDigest;

public class Ed25519 {

    public boolean verify(byte[] publicKey, byte[] signature, byte[] message) {
        EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(publicKey, Ed25519Util.SPEC);
        return verify(new EdDSAPublicKey(pubKey), signature, message);
    }

    public boolean verify(EdDSAPublicKey edDSAPublicKey, byte[] signature, byte[] message) {
        try {
            EdDSAEngine sgr = new EdDSAEngine(MessageDigest.getInstance(edDSAPublicKey.getParams().getHashAlgorithm()));
            sgr.initVerify(edDSAPublicKey);
            sgr.setParameter(EdDSAEngine.ONE_SHOT_MODE);
            sgr.update(message);
            return sgr.verify(signature);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public byte[] sign(byte[] privateKey, byte[] message) {
        EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(privateKey, Ed25519Util.SPEC);
        return sign(new EdDSAPrivateKey(privKey), message);
    }

    public byte[] sign(EdDSAPrivateKey edDSAPrivateKey, byte[] message) {
        try {
            EdDSAEngine sgr = new EdDSAEngine(MessageDigest.getInstance(edDSAPrivateKey.getParams().getHashAlgorithm()));
            sgr.initSign(edDSAPrivateKey);
            sgr.setParameter(EdDSAEngine.ONE_SHOT_MODE);
            sgr.update(message);
            return sgr.sign();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
