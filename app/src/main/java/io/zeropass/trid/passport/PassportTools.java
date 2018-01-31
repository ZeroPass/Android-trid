/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid.passport;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import io.zeropass.trid.Utils;

public class PassportTools {
    private static final Logger Journal = Logger.getLogger("passport");

    /** Mode for KDF. */
    public static final int ENC_MODE = 1, MAC_MODE = 2;
    public static final IvParameterSpec ZERO_IV = new IvParameterSpec(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });

    public static final int KEY_LEN = 16;
    public static final int MAC_LEN = 8;

    public static final int RND_IFD_LEN = 8;
    public static final int RND_IC_LEN = RND_IFD_LEN;

    public static final int KIFD_LEN = KEY_LEN;
    public static final int KIC_LEN = KIFD_LEN;

    public static Mac getMac() {
        try {
            return Utils.getMac("ISO9797ALG3WITHISO7816-4PADDING");
        } catch (NoSuchAlgorithmException e) { return null; }
    }


    public static Mac getMacNoPadding() {
        try {
            return Utils.getMac("ISO9797Alg3Mac");
        } catch (NoSuchAlgorithmException e) { return null; }
    }

    public static Cipher getCipher() {
        try {
            return Utils.getCipher("DESede/CBC/NoPadding");
        }
        catch (NoSuchAlgorithmException e) { return null; }
        catch (NoSuchPaddingException e) { return null; }
    }

    private static SecretKey expandDesKey(SecretKey key) {
        if(key.getEncoded().length != 24) {
            byte[] key1 = key.getEncoded();
            byte[] key2 = new byte[24];

            System.arraycopy(key1, 0, key2, 0, key1.length);
            System.arraycopy(key1, 0, key2, key1.length, key2.length - key1.length);
            key = new SecretKeySpec(key2, "DESede");
        }

        return key;
    }

    /**
     * Plaint text encryption function.
     * ICAO 9303-11 section 4.3.3.1
     * https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
     */
    public static byte[] encrypt(SecretKey key, byte[] data) {
        try {
            Cipher cipher = getCipher();
            key = expandDesKey(key);
            cipher.init(Cipher.ENCRYPT_MODE, key, ZERO_IV);
            return cipher.doFinal(data);
        }
        catch (BadPaddingException e) {return null;}
        catch (InvalidAlgorithmParameterException e) {return null;}
        catch (InvalidKeyException e) {return null;}
        catch (IllegalBlockSizeException e) {return null;}
    }

    public static byte[] decrypt(SecretKey key, byte[] cipherData) {
        try {
            Cipher cipher = getCipher();
            key = expandDesKey(key);
            cipher.init(Cipher.DECRYPT_MODE, key, ZERO_IV);
            return cipher.doFinal(cipherData);
        }
        catch (BadPaddingException e) {return null;}
        catch (InvalidAlgorithmParameterException e) {return null;}
        catch (InvalidKeyException e) {return null;}
        catch (IllegalBlockSizeException e) {return null;}
    }

    public static byte[] decrypt(SecretKey key, byte[] cipherData, int beginOff, int endOff) {
        try {
            Cipher cipher = getCipher();
            cipher.init(Cipher.DECRYPT_MODE, key, ZERO_IV);
            return cipher.doFinal(cipherData, beginOff, endOff);
        }
        catch (BadPaddingException e) {return null;}
        catch (InvalidAlgorithmParameterException e) {return null;}
        catch (InvalidKeyException e) {return null;}
        catch (IllegalBlockSizeException e) {return null;}
    }

    public static byte[] mac(SecretKey macKey, byte[] data) {
        return mac(macKey, data, 0, data.length);
    }

    public static byte[] mac(SecretKey macKey, byte[] data, int endOfs) {
        return mac(macKey, data, 0, endOfs);
    }

    public static byte[] macNoPadding(SecretKey macKey, byte[] data) {
        return macNoPadding(macKey, data, 0, data.length);
    }

    public static byte[] macNoPadding(SecretKey macKey, byte[] data, int endOfs) {
        return macNoPadding(macKey, data, 0, endOfs);
    }

    public static byte[] mac(SecretKey macKey, byte[] data, int beginOfs, int endOfs) {
        return mac(macKey, data, beginOfs, endOfs, true);
    }

    public static byte[] macNoPadding(SecretKey macKey, byte[] data, int beginOfs, int endOfs) {
        return mac(macKey, data, beginOfs, endOfs, false);
    }

    private static byte[] mac(SecretKey macKey, byte[] data, int beginOfs, int endOfs, boolean padding) {
        try {
            if(!Utils.checkBounds(data, beginOfs, endOfs)) {
                return null;
            }

            Mac mac;
            if(padding) {
                mac = getMac();
            }
            else {
                mac = getMacNoPadding();
            }

            mac.init(macKey);
            mac.update(data, beginOfs, endOfs);
            return mac.doFinal();
        }
        catch (InvalidKeyException e) {return null;}
    }


    /**
     * Format document number to 9-character fixed length
     * Missing chars are filled with '<'
     * see: Example 2 of Appendix 3 in ICAO 9303-3
     *      https://www.icao.int/publications/Documents/9303_p3_cons_en.pdf
     * */
    public static String formatDocumentNumber(String docNum) throws InvalidAlgorithmParameterException {
        /* Remove from number '<'. */
        String formatedDocNum = docNum.replace('<', ' ').trim().replace(' ', '<');

        if(formatedDocNum.length() > 9) { // Sanity check
            throw new InvalidAlgorithmParameterException("Invalid document number!");
        }

        /* Fill missing chars with '<' until length 9. */
        while (formatedDocNum.length() < 9) {
            formatedDocNum += "<";
        }

        return formatedDocNum;
    }


    /**
     * Calculate checkdigit as specified ICAO in doc 9303-3 section 4.9
     * https://www.icao.int/publications/Documents/9303_p3_cons_en.pdf
     */
    public static char calculateMrzCheckDigit(String str) {

        try {
            byte[] chars = str == null ? new byte[]{ } : str.getBytes("UTF-8");
            int[] weights = { 7, 3, 1 };
            int result = 0;
            for (int i = 0; i < chars.length; i++) {
                result = (result + weights[i % 3] * decodeMRZDigit(chars[i])) % 10;
            }
            String checkDigitString = Integer.toString(result);
            if (checkDigitString.length() != 1) {  // Sanity check
                throw new IllegalStateException("Failed to compute check digit.");
            }

            char checkDigit = (char)checkDigitString.getBytes("UTF-8")[0];
            return checkDigit;
        }
        catch (NumberFormatException nfe) {
            Journal.severe("Exception: " + nfe.getMessage());
            throw new IllegalStateException("Error in computing check digit.");
        }
        catch (Exception e) {
            Journal.severe("Exception: " + e.getMessage());
            throw new IllegalArgumentException(e.toString());
        }
    }

    /**
     * Decodes char to numeric representation of MRZ character.
     * Needed for calculating MRZ check digit.
     * see: ICAO in doc 9303-3 section 4.9
     */
    private static int decodeMRZDigit(byte ch) throws NumberFormatException {
        switch (ch) {
            case '<':
            case '0': return 0;
            case '1': return 1;
            case '2': return 2;
            case '3': return 3;
            case '4': return 4;
            case '5': return 5;
            case '6': return 6;
            case '7': return 7;
            case '8': return 8;
            case '9': return 9;
            case 'a': case 'A': return 10;
            case 'b': case 'B': return 11;
            case 'c': case 'C': return 12;
            case 'd': case 'D': return 13;
            case 'e': case 'E': return 14;
            case 'f': case 'F': return 15;
            case 'g': case 'G': return 16;
            case 'h': case 'H': return 17;
            case 'i': case 'I': return 18;
            case 'j': case 'J': return 19;
            case 'k': case 'K': return 20;
            case 'l': case 'L': return 21;
            case 'm': case 'M': return 22;
            case 'n': case 'N': return 23;
            case 'o': case 'O': return 24;
            case 'p': case 'P': return 25;
            case 'q': case 'Q': return 26;
            case 'r': case 'R': return 27;
            case 's': case 'S': return 28;
            case 't': case 'T': return 29;
            case 'u': case 'U': return 30;
            case 'v': case 'V': return 31;
            case 'w': case 'W': return 32;
            case 'x': case 'X': return 33;
            case 'y': case 'Y': return 34;
            case 'z': case 'Z': return 35;
            default:
                throw new NumberFormatException("Failed to decode unsupported MRZ character " + ch);
        }
    }

    /*
    *  Calculates Basic Authentication key seed as specified in
    *  appendix D.2 (worked example: basic access control) of document ICAO 9303-11
    *  https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
    * */
    public static byte[] computeKeySeed(String documentNumber, char dnCheckDigit, String dateOfBirth, char dobCheckDigit, String dateOfExpiry, char doeCheckDigit, boolean truncated) {
        try {
            MessageDigest sha1 = Utils.getSha1();
            sha1.update(documentNumber.getBytes("UTF-8"));
            sha1.update(new byte[]{(byte)dnCheckDigit});
            sha1.update(dateOfBirth.getBytes("UTF-8"));
            sha1.update(new byte[]{(byte)dobCheckDigit});
            sha1.update(dateOfExpiry.getBytes("UTF-8"));
            sha1.update(new byte[]{(byte)doeCheckDigit});

            byte[] hash = sha1.digest();
            if (truncated) {
                byte[] keySeed = new byte[KEY_LEN];
                System.arraycopy(hash, 0, keySeed, 0, keySeed.length);
                return keySeed;
            }
            else {
                return hash;
            }
        }
        catch (UnsupportedEncodingException e){ return null;}
    }


    public static byte[] computeKeySeed(String documentNumber, String dateOfBirth, String dateOfExpiry, boolean truncated) {
        return computeKeySeed(documentNumber, calculateMrzCheckDigit(documentNumber),
                dateOfBirth, calculateMrzCheckDigit(dateOfBirth),
                dateOfExpiry, calculateMrzCheckDigit(dateOfExpiry),
                truncated);
    }

    public static byte[] computeBAC_KeySeed(String documentNumber, char dnCheckDigit, String dateOfBirth, char dobCheckDigit, String dateOfExpiry, char doeCheckDigit) {
        return computeKeySeed(documentNumber, dnCheckDigit,
                dateOfBirth, dobCheckDigit,
                dateOfExpiry, doeCheckDigit,
                true);
    }

    public static byte[] computeBAC_KeySeed(String documentNumber, String dateOfBirth, String dateOfExpiry) {
        return computeBAC_KeySeed(documentNumber, calculateMrzCheckDigit(documentNumber),
                dateOfBirth, calculateMrzCheckDigit(dateOfBirth),
                dateOfExpiry, calculateMrzCheckDigit(dateOfExpiry));
    }


    /**
     *  KDF function to derive encryption key or mac key to be used in BAC as specified in
     *  appendix D.1 of document ICAO 9303-11 and ICAO 9303-11 section 9.7.1.1
     *  https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
     */
    public static SecretKey deriveKey(byte[] keySeed, int mode) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.reset();
            sha1.update(keySeed);
            sha1.update(new byte[] { 0x00, 0x00, 0x00, (byte)mode });

            byte[] hashResult = sha1.digest();
            byte[] keyBytes = Utils.copyOut(hashResult,0, KEY_LEN);

            Utils.adjustParityBits(keyBytes);
            return new SecretKeySpec(keyBytes, "DESede");
        }
        catch (NoSuchAlgorithmException e) {return null;}
    }

    /** Computes send sequence counter (SCC)
     * see: ICAO 9303-11 section 9.8.2 */
    public static long calculateSCC(byte[] rndIC, byte[] rndIFD) {
        if (rndIC == null || rndIC.length != RND_IC_LEN
                || rndIFD == null || rndIFD.length != RND_IFD_LEN) {
            throw new InvalidParameterException("RND.IC/RND.IFD null or len 8!");
        }

        long ssc = 0;
        for (int i = 4; i < rndIC.length; i++) {
            ssc <<= 8;
            ssc += (long)(rndIC[i] & 0x000000FF);
        }

        for (int i = 4; i < rndIFD.length; i++) {
            ssc <<= 8;
            ssc += (long)(rndIFD[i] & 0x000000FF);
        }

        return ssc;
    }

    /**
     * Calculate E.IFD and M.IFD needed for BAC
     * specified in document ICAO 9303-11 appendix d.3
     *
     * @returns byte[] E.IFD | M.IFD
     */
    public static ApduEAData generateApduEAData(SecretKey encKey, SecretKey macKey, byte[] rndIC, byte[] rndIFD, byte[] kIFD) {
        if(rndIC.length != RND_IC_LEN && rndIFD.length != RND_IFD_LEN && kIFD.length != KIFD_LEN) {
            return null;
        }

        byte[] s = new byte[ApduEAData.E_LEN];
        System.arraycopy(rndIFD,0, s,0, rndIFD.length);
        System.arraycopy(rndIC,0, s,rndIFD.length, rndIC.length);
        System.arraycopy(kIFD,0, s,rndIFD.length + rndIC.length, kIFD.length);

        /* Encrypt secret */
        byte[] eIFD = encrypt(encKey, s);
        if(eIFD == null || eIFD.length != ApduEAData.E_LEN) {
            return null;
        }

        /* Calculate mac from cipher text */
        byte[] mIFD = mac(macKey, eIFD);
        if(mIFD == null || mIFD.length != MAC_LEN) {
            return null;
        }

        return new ApduEAData(eIFD, mIFD);
    }

    /**
     * Verify External Authenticate command response
     * specified in document ICAO 9303-11 appendix d.3
     */
    public static boolean verifyEAResult(SecretKey macKey, byte[] eaResult) {
        /* Sanity check, see if we have at least 40 bytes (E.IC | M.IC)*/
        if(eaResult.length < 0x28) {
            return false;
        }

        /* Verify mac */
        byte[] mIC = mac(macKey, eaResult, 0, eaResult.length - MAC_LEN);
        return Utils.memcmp(mIC, eaResult, eaResult.length - MAC_LEN);
    }

    /**
     * Decrypt and extract K.IC needed for BAC from E.IC
     * specified in document ICAO 9303-11 appendix d.3
     *
     * @returns byte[] K.IC
     */
    public static byte[] extractKicFromEic(SecretKey decKey, ApduEAData data, byte[] rndIFD) {

        if(rndIFD.length != RND_IFD_LEN) {
            throw new InvalidParameterException("rndIFD len != 8");
        }

        /* Decrypt received data */
        byte[] r = data.decrypt(decKey);
        if(r == null) {
            Journal.warning("extractKicFromEic: failed to decrypt E.IC");
            return null;
        }

        /* Verify received rndIFD */
        if(!Utils.memcmp(rndIFD, r, rndIFD.length)) {
            Journal.warning("extractKicFromEic: decrypted RND.IFD mismatch");
            return null;
        }

        return Utils.copyOut(r, RND_IC_LEN + RND_IFD_LEN, KEY_LEN);
    }

    /** Calculate SessionCipher key
     * specified in document ICAO 9303-11 appendix d.3
     *
     * @return PassportSessionKEy
     */
    public static PassportSessionKey calculateSessionKey(final byte[] rndIC, final byte[] rndIFD, final byte[] kIFD, final byte[] kIC) {

        if(kIFD == null || kIC == null || kIFD.length != kIC.length || kIFD.length != KIFD_LEN) {
            throw new InvalidParameterException("calculateSessionKey K.IFD/K.IC null or len != 16");
        }

        /* Compute key seed from K.IFD & K.IC */
        byte[] keySeed = new byte[16];
        for (int i = 0; i < KIFD_LEN; i++) {
            keySeed[i] = (byte) ((kIC[i] & 0xFF) ^ (kIFD[i] & 0xFF));
        }

        /* Calculate session keys and SSC */
        SecretKey ksEnc = PassportTools.deriveKey(keySeed, ENC_MODE);
        SecretKey ksMac = PassportTools.deriveKey(keySeed, MAC_MODE);
        long ssc = PassportTools.calculateSCC(rndIC, rndIFD);

        return new PassportSessionKey(ksEnc, ksMac, ssc);
    }

    /** Copied from https://github.com/E3V3A/JMRTD/blob/master/jmrtd/src/org/jmrtd/Util.java**/
    public static byte[] pad(/*@ non_null */ byte[] in, int offset, int length, int blockSize) {
        int blockSizeInBytes = blockSize / 8;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(in, offset, length);
        out.write((byte)0x80);

        while (out.size() % blockSizeInBytes != 0) {
            out.write((byte)0x00);
        }

        return out.toByteArray();
    }

    public static byte[] pad(/*@ non_null */ byte[] in) {
        return pad(in, 0, in.length);
    }

    public static byte[] pad(/*@ non_null */ byte[] in, int blockSize) {
        return pad(in, 0, in.length, blockSize);
    }

    public static byte[] pad(/*@ non_null */ byte[] in, int offset, int length) {
        return pad(in, offset, length, 64);
    }

    public static byte[] unpad(byte[] in) throws BadPaddingException {
        int i = in.length - 1;
        while (i >= 0 && in[i] == 0x00) {
            i--;
        }

        if ((in[i] & 0xFF) != 0x80) {
            throw new BadPaddingException("Expected constant 0x80, found 0x" + Integer.toHexString((in[i] & 0x000000FF)) + "\nDEBUG: in = " + Utils.hexToStr(in) + ", index = " + i);
        }

        byte[] out = new byte[i];
        System.arraycopy(in, 0, out, 0, i);
        return out;
    }
}
