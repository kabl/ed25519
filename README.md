# Introduction
Sign and verify library for ED25519 signature algorithm.

# How to use
This library is built for developers which want simply generate signatures and validate signatures.

```java

/**
 * Verifies a signed message.
 *
 * @param publicKey 32 byte array public key.
 * @param signature The signature.
 * @param message The original message which was signed.
 * @return true if the signature matches.
 */
public boolean verify(byte[] publicKey, byte[] signature, byte[] message);

/**
 * Signs data.
 *
 * @param privateKey 32 byte array with the private key. Can be random 32 bytes.
 * @param message Message to sign.
 * @return The signed message.
 */
public byte[] sign(byte[] privateKey, byte[] message);

```

# References
Inspired by:
- https://github.com/str4d/ed25519-java
- https://gist.github.com/om26er/494b2b34bd605ec081b9d7057cc4aa2f

