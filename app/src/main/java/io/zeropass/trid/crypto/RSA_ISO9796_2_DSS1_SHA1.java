/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid.crypto;

import android.support.annotation.VisibleForTesting;
import android.util.Pair;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import io.zeropass.trid.Utils;

/**
 * Implementation of ISO/IEC 9796-2 Digital signature scheme 1
 * (Verification only with SHA-1 as message hashing function)
 */
public class RSA_ISO9796_2_DSS1_SHA1 {
    private static Cipher cipher = null;

    public static boolean verifySignature(RSAPublicKey pk, byte[] message, byte[] signature) {
        try {
            if( cipher == null) {
                cipher = Cipher.getInstance("RSA/NONE/NoPadding", new org.spongycastle.jce.provider.BouncyCastleProvider());
            }

            /* Decrypt signature */
            cipher.init(Cipher.DECRYPT_MODE, pk);
            byte[] f = cipher.doFinal(signature);

            return verifyF(f, message);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return false;
    }

    private static boolean verifyF(byte[] f, byte[] message) {
        if(f == null) {
            return false;
        }

        int k = f.length;

        /* Check trailer ends with nibble == 0xC */
        if (((f[k - 1] & 0xF) ^ 0xC) != 0) {
            return false;
        }

        /* Get digest identifier (lat 1 ot 2 bytes */
        int t = f[k - 1] == (byte) 0xBC ? 1 : 2;
        if (t != 1 && f[k - 2] != 0x33) { // Shall be sha 1 see ICAO 9303-11
            return false;
        }

        if(!checkHeader(f)) {
            return false;
        }

        final boolean partialRecovery = getByteBit(f[0], 5) == 1;
        int padBitCount = padBitCount(f);
        if(partialRecovery && padBitCount >= 9) {
            return false;
        }

        /* Sha1 digest size */
        int Lh = CryptoUtils.getSha1().getDigestLength();

        f = removePad(f, padBitCount);
        int m1Len = f.length - (Lh + t);

        /* Extract M1 and message digest */
        byte[] m1 = Utils.copyOut(f, 0, m1Len);
        byte[] d  = Utils.copyOut(f, m1Len, Lh);

        /* Construct message M */
        byte[] m = null;
        if(partialRecovery) {
            m = Utils.join(m1, message);
        }
        else {
            m = m1;
            if(!Utils.memcmp(m, message)) {
                return false;
            }
        }

        /* Calculate sha1 of M and verify that returned digest matches d */
        return Utils.memcmp(d, CryptoUtils.sha1(m));
    }

    private static boolean checkHeader(final byte[] f) {
        return getByteBit(f[0], 7) == 0 && getByteBit(f[0], 6) == 1; // left most tw bits must equal to '01'
    }

    private static int getByteBit(byte b, int num) {
        return b >> num & 1;
    }
    private static int padBitCount(final byte[] f) {
        int c = 0;

        /* If padding is present the right most bit of the left most nibble is 0 */
        if(getByteBit(f[0], 4) == 0) {

            /* Operate on nibbles */
            for (int i = 1; i < f.length * 4; i++) {

                byte b = f[(i * 4) /8];
                byte n = (byte)0;
                if(i % 2 == 0) {
                    n = (byte) ((byte) (b >> 4) & 0x0f); // left nibble
                } else {
                    n = (byte) (b & 0xf); // right nibble
                }

                c++;
                if(n != 0xB) {
                    break;
                }
            }
        }

        return c * 4;
    }

    private static byte [] removePad(byte[] f, int padBitCount) {
        int nr = padBitCount / 4 + 1; // 1 nibble = header;
        int br = nr * 4 /8;
        f = Utils.copyOut(f, br, f.length - br);
        return f;
    }
}
