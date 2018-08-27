package com.github.kabl.ed25519;

import net.i2p.crypto.eddsa.Utils;
import org.junit.Test;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;


public class Ed25519UtilTest {

    /**
     * Tools: <br />
     * - http://ed25519.herokuapp.com/ <br />
     * - https://cryptii.com/base64-to-hex <br />
     */
    @Test
    public void generateByPassword() throws Exception {
        KeyPair kp = Ed25519Util.generateByPassword("test".getBytes("UTF-8"));

        assertThat(Utils.bytesToHex(kp.getPrivateKey()), is("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
        assertThat(Utils.bytesToHex(kp.getPublicKey()), is("67d3b5eaf0c0bf6b5a602d359daecc86a7a74053490ec37ae08e71360587c870"));

        Ed25519 ed25519 = new Ed25519();
        byte[] message = "message".getBytes("UTF-8");
        byte[] signature = ed25519.sign(kp.getPrivateKey(), message);
        boolean result = ed25519.verify(kp.getPublicKey(), signature, message);

        assertTrue(result);

        assertThat(Utils.bytesToHex(signature), is("d7ddfdd916da1f93bc69e3db7c0e7fc5d29b716ddc87836163230afbc72e72ba5fd91d30eccb2e66315b9487af95568aecd41af17056f8d9fdc24b16e9a48105"));
    }
}