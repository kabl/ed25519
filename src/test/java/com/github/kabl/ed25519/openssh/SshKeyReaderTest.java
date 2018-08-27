package com.github.kabl.ed25519.openssh;

import net.i2p.crypto.eddsa.Utils;
import org.junit.Test;
import java.io.File;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

public class SshKeyReaderTest {

    /**
     * File was generated with "ssh-keygen -t ed25519".
     */
    @Test
    public void parseOpenSSHFile() throws Exception {

        String expectedPrivateKey = "210192997044836b7e2b8c0dd7bcbc1deb06e097537b7e3f04b81d7b0cc59a84";
        String expectedPublicKey = "bb2f637018d9ed0cf5d2015009480da41f67e4adbbd9be464914325b076dd41f";

        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource("id_ed25519").getFile());
        KeyPair keyPair = SshKeyReader.parseOpenSSHFile(file);

        assertThat(Utils.bytesToHex(keyPair.getPrivateKey()), is(expectedPrivateKey));
        assertThat(Utils.bytesToHex(keyPair.getPublicKey()), is(expectedPublicKey));
    }
}