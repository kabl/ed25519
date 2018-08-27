package com.github.kabl.ed25519;

import com.github.kabl.ed25519.openssh.SshKeyReader;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.Utils;
import org.junit.Test;

import java.io.File;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import static org.junit.Assert.*;

public class Ed25519Test {

    private static final byte[] PKCS8_PRIV_KEY = Utils.hexToBytes("302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842");
    private static final byte[] X509_PUB_KEY =  Utils.hexToBytes("302a300506032b657003210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1");
    private static final byte[] MESSAGE = "Hello World".getBytes();

    @Test
    public void testSignAndVerify() throws Exception {
        Ed25519 ed25519 = new Ed25519();
        EdDSAPrivateKey privateKey = new EdDSAPrivateKey(new PKCS8EncodedKeySpec(PKCS8_PRIV_KEY));
        EdDSAPublicKey publicKey = new EdDSAPublicKey(new X509EncodedKeySpec(X509_PUB_KEY));

        byte[] signature = ed25519.sign(privateKey, MESSAGE);
        boolean result = ed25519.verify(publicKey, signature, MESSAGE);

        assertTrue(result);
    }

    @Test
    public void testSignAndVerify32ByteKeys() throws Exception {

        byte[] privateKey = Utils.hexToBytes("6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b");
        byte[] publicKey = Utils.hexToBytes("cd03fbddcaaa2703c251656d5ccdd99f5635b1e0653c0636b951a3a3db21dad4");

        Ed25519 ed25519 = new Ed25519();
        byte[] signature = ed25519.sign(privateKey, MESSAGE);
        boolean result = ed25519.verify(publicKey, signature, MESSAGE);

        assertTrue(result);
    }

    @Test
    public void testSignWithOpenSshPrivateKey() throws Exception {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource("id_ed25519").getFile());
        KeyPair keyPair = SshKeyReader.parseOpenSSHFile(file);

        Ed25519 ed25519 = new Ed25519();
        byte[] signature = ed25519.sign(keyPair.getPrivateKey(), MESSAGE);
        boolean result = ed25519.verify(keyPair.getPublicKey(), signature, MESSAGE);

        assertTrue(result);
    }
}