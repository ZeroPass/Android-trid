/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid;

import android.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;
import java.util.logging.Logger;

import java.security.MessageDigest;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.security.SecureRandom;
import java.util.Random;


public class Utils {

    private static final Logger Journal = Logger.getLogger("io.trid.utils");
    public static void printDebug(final String msg) {
        printDebug("", msg);
    }

    public static void printDebug(final String tag, final String msg) {
        if (BuildConfig.DEBUG) {
            Log.d(tag, msg);
        }
    }

    public static boolean memcmp(byte[] src1, byte[] src2) {
        return memcmp(src1, src2,0);
    }

    public static boolean memcmp(byte[] src1, byte[] src2, int src2BeginOff) {
        if(!checkBounds(src2, src2BeginOff, src1.length)){
            return false;
        }

        for(int i = 0; i < src1.length; i++) {
            if(src1[i] != src2[src2BeginOff + i]) {
                return false;
            }
        }

        return true;
    }

    public static byte[] join(byte[] src1, byte[] src2) {
        byte[] data = new byte[src1.length + src2.length];

        System.arraycopy(src1, 0, data,0, src1.length);
        System.arraycopy(src2, 0, data,src1.length, src2.length);
        return data;
    }

    public static byte[] copyOut(byte[] src, int ofs, int len) {
        if(!checkBounds(src, ofs, ofs + len)) {
            return null;
        }

        byte[] data = new byte[len];
        System.arraycopy(src, ofs, data,0, len);
        return data;
    }

    public static boolean checkBounds(byte[] data, int beingOfs, int endOfs) {
        int dataLen = data.length;
        if(beingOfs >= dataLen || endOfs > dataLen ||
                beingOfs < 0 || endOfs < 0) {
            return false;
        }

        return true;
    }

    public static String hexToStr(byte[] pData) {
        StringBuffer sb = new StringBuffer();
        if (pData == null) {
            sb.append("");
        } else {
            boolean t = false;
            byte[] var5 = pData;
            int var6 = pData.length;

            for (int i = 0; i < var6; i++) {
                byte b = var5[i];
                if (b != 0 || t) {
                    t = true;
                    sb.append(String.format("%02x", new Object[]{Integer.valueOf(b & 255)}));
                }
            }
        }

        return sb.toString().toUpperCase(Locale.getDefault()).trim();
    }

    public static byte[] strToHex(String hexString) {
        if (hexString == null) {
            throw new IllegalArgumentException("Argument can\'t be null");
        } else {
            String text = hexString.replace(" ", "");
            if (text.length() % 2 != 0) {
                throw new IllegalArgumentException("Hex string length has to be even");
            } else {
                byte[] data = new byte[Math.round((float) text.length() / 2.0F)];
                int j = 0;

                for (int i = 0; i < text.length(); i += 2) {
                    Integer val = Integer.valueOf(Integer.parseInt(text.substring(i, i + 2), 16));
                    data[j++] = val.byteValue();
                }

                return data;
            }
        }
    }

    /**
     * Counts the number of set bits in a byte.
     * Needed for adjusting parity bits in adjustParityBits function
     */
    private static byte evenBits(byte b) {
        short count = 0;

        for (short i = 0; i < 8; i++) {
            count += (b >>> i) & 0x1;
        }

        return (byte) (count % 2);
    }

    public static void adjustParityBits(byte[] data) {
        for (short i = 0; i < data.length; i++) {
            if (evenBits(data[i]) == 0)
                data[i] = (byte) (data[i] ^ 1);
        }
    }
}
