package com.github.kabl.ed25519.openssh;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.*;

/**
 * Source from: https://gist.github.com/om26er/494b2b34bd605ec081b9d7057cc4aa2f
 */
public class SshKeyReader {

    private static final String SSH_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----";
    private static final String SSH_END = "-----END OPENSSH PRIVATE KEY-----";
    private static final String OPENSSH_KEY_V1 = "openssh-key-v1";

    public static KeyPair parseOpenSSHFile(File file) throws Exception {
        BufferedReader br = new BufferedReader(new FileReader(file));
        String sCurrentLine;
        List<String> lines = new ArrayList<>();
        while ((sCurrentLine = br.readLine()) != null) {
            lines.add(sCurrentLine);
        }
        return parseOpenSSHFile(lines);
    }

    private static KeyPair parseOpenSSHFile(List<String> lines) throws Exception {
        if (!lines.get(0).equals(SSH_BEGIN) || !lines.get(lines.size() - 1).equals(SSH_END)) {
            throw new RuntimeException("Invalid OPENSSH file");
        }
        lines.remove(0);
        lines.remove(lines.size() - 1);
        StringBuilder base64StringBuilder = new StringBuilder();
        for (String line: lines) {
            base64StringBuilder.append(line);
        }
        String base64String = base64StringBuilder.toString();
        byte[] rawKey = Base64.getDecoder().decode(base64String);

        byte[] verify = Arrays.copyOfRange(rawKey, 0, OPENSSH_KEY_V1.length());
        if (!new String(verify).equals(OPENSSH_KEY_V1)) {
            throw new RuntimeException("Invalid OPENSSH file");
        }

        boolean occurred = false;
        int index = 0;
        for (int i = 0; i < rawKey.length; i++) {
            if (rawKey[i] == 's'
                    && rawKey[i + 1] == 's'
                    && rawKey[i + 2] == 'h'
                    && rawKey[i + 3] == '-'
                    && rawKey[i + 4] == 'e'
                    && rawKey[i + 5] == 'd'
                    && rawKey[i + 6] == '2'
                    && rawKey[i + 7] == '5'
                    && rawKey[i + 8] == '5'
                    && rawKey[i + 9] == '1'
                    && rawKey[i + 10] == '9'
                    && rawKey[i + 11] == 0x00
                    && rawKey[i + 12] == 0x00
                    && rawKey[i + 13] == 0x00
                    && rawKey[i + 14] == ' ') {
                index = i + 15;
                if (occurred) {
                    break;
                }
                occurred = true;
            }
        }

        byte[] publicKey = Arrays.copyOfRange(rawKey, index, index + 32);

        index += 32;
        for (int i = index; i < rawKey.length; i++) {
            if (rawKey[i] == 0x00
                    && rawKey[i + 1] == 0x00
                    && rawKey[i + 2] == 0x00
                    && rawKey[i + 3] == '@') {
                index = i + 4;
                break;
            }
        }

        byte[] privateKey = Arrays.copyOfRange(rawKey, index, index + 32);

        return new KeyPair(privateKey, publicKey);
    }

}