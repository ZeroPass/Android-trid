/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid.crypto;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;

public class CryptoUtils {
    private static final Logger Journal = Logger.getLogger("io.trid.crypto.utils");

    private static final Random mRng = new SecureRandom();
    public static byte[] getRandomBytes(int len) {
        byte[] rnd = new byte[len];
        mRng.nextBytes(rnd);
        return rnd;
    }

    public static MessageDigest getSha1() {
        try {
            return MessageDigest.getInstance("SHA-1");
        }
        catch (NoSuchAlgorithmException e){return null;}
    }

    public static Mac getMac(final String algo) throws NoSuchAlgorithmException {
        return Mac.getInstance(algo, new org.spongycastle.jce.provider.BouncyCastleProvider());
    }

    public static Cipher getCipher(final String algo) throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance(algo);
    }

    public static byte[] sha1(byte[] data) {
        MessageDigest sha1 = getSha1();
        return sha1.digest(data);
    }

    public static PublicKey getPublicKeyFromBytes(byte[] keyBytes)  {
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(keyBytes);

        String[] algorithms = { "RSA", "EC" };
        for (String algorithm: algorithms) {
            try {
                KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
                PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
                return publicKey;
            } catch (InvalidKeySpecException ikse) {
				/* NOTE: Ignore, try next algorithm. */
            } catch (NoSuchAlgorithmException e) {
                Journal.severe("getPublicKeyFromBytes: No such algorithm exception was thrown e=" + e.getMessage());
                return null;
            }
        }

        return null;
    }
}
