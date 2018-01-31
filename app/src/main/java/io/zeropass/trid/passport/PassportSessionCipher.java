/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid.passport;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.logging.Logger;

import io.zeropass.trid.ISO7816;
import io.zeropass.trid.libs.TLVUtil;
import io.zeropass.trid.net.ApduCmd;
import io.zeropass.trid.net.ApduResult;
import io.zeropass.trid.net.SessionCipher;

/**
 * Created by smlu on 29. 01. 2018.
 */

public class PassportSessionCipher extends SessionCipher {

    private static final Logger Journal = Logger.getLogger("passport.session.cipher");
    PassportSessionKey mKS;

    public PassportSessionCipher(PassportSessionKey key) {
        mKS = key;
    }

    /**
     * Encrypts APDU data
     *
     * @returns encrypted APDU bytes
     */
    public ApduCmd encrypt(ApduCmd cmd) {
        try {
            return encryptCommand(cmd);
        } catch (IOException e) {
            Journal.severe("PassportSessionCipher: An IO exception was thrown while encrypting APDU data! e=" + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            Journal.severe("PassportSessionCipher: An exception was thrown while encrypting APDU data! e=" + e.getMessage());
        } catch (InvalidKeyException e) {
            Journal.severe("PassportSessionCipher: An IO exception was thrown while encrypting APDU data! e=" + e.getMessage());
        }

        return null;
    }

    private ApduCmd encryptCommand(ApduCmd cmd) throws IOException, NoSuchAlgorithmException, InvalidKeyException {

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        byte[] maskedHeader = new byte[] { (byte)(cmd.cla() | (byte)0x0C), (byte)cmd.ins(), (byte)cmd.p1(), (byte)cmd.p2() };
        byte[] paddedMaskedHeader = PassportTools.pad(maskedHeader);

        boolean hasDO85 = ((byte)cmd.ins() == ISO7816.INS_READ_BINARY2);

        byte[] do8587 = new byte[0];
        byte[] do97 = new byte[0];

        /* Encode Le field */
        int le = cmd.ne();
        if (le > 0) {
            bOut.reset();
            bOut.write((byte)0x97);
            bOut.write((byte)0x01);
            bOut.write((byte)le);
            do97 = bOut.toByteArray();
        }

        /* Encrypt command data */
        if (cmd.data() != null && cmd.data().length > 0) {
            byte[] data = PassportTools.pad(cmd.data());
            byte[] ciphertext = PassportTools.encrypt(mKS.getKSenc(), data);

            bOut.reset();
            bOut.write(hasDO85 ? (byte)0x85 : (byte)0x87);
            bOut.write(TLVUtil.getLengthAsBytes(ciphertext.length + (hasDO85 ? 0 : 1)));

            if(!hasDO85) {
                bOut.write(0x01);
            }

            bOut.write(ciphertext, 0, ciphertext.length);
            do8587 = bOut.toByteArray();
        }

        /* Construct data M */
        bOut.reset();
        bOut.write(paddedMaskedHeader, 0, paddedMaskedHeader.length);
        bOut.write(do8587, 0, do8587.length);
        bOut.write(do97, 0, do97.length);
        byte[] m = bOut.toByteArray();

        /* Construct data N to be used in mac operation (pad(SSC | M)) */
        bOut.reset();
        DataOutputStream dataOut = new DataOutputStream(bOut);

        mKS.incrementSSC();
        dataOut.writeLong(mKS.getSSC());
        dataOut.write(m, 0, m.length);
        dataOut.flush();
        byte[] n = PassportTools.pad(bOut.toByteArray());

		/* Compute mac checksum */
        byte[] cc = PassportTools.macNoPadding(mKS.getKSmac(), n);
        int ccLength = cc.length;
        if (ccLength != 8) {
            Journal.warning("Found mac length of " + ccLength + ", only using first 8 bytes");
            ccLength = 8;
        }

        /* Construct DO.8E*/
        bOut.reset();
        bOut.write((byte) 0x8E);
        bOut.write(ccLength);
        bOut.write(cc, 0, ccLength);
        byte[] do8E = bOut.toByteArray();

		/* Construct protected apdu */
        bOut.reset();
        bOut.write(do8587);
        bOut.write(do97);
        bOut.write(do8E);
        byte[] protectedData = bOut.toByteArray();

        return new ApduCmd(maskedHeader[0], maskedHeader[1], maskedHeader[2], maskedHeader[3], protectedData, 256);
    }

    /**
     * Decrypt APDU result data
     *
     * @returns encrypted APDU bytes
     */
    public ApduResult decrypt(ApduResult result) {

        try {
            return decryptCommand(result);
        }
        catch (GeneralSecurityException e) {
            Journal.severe("PassportSessionCipher: An exception was thrown while decrypting APDU data: " + e.getMessage());
        }
        catch (IOException e) {
            Journal.severe("PassportSessionCipher: An exception was thrown while decrypting APDU data: " + e.getMessage());
        }

        return null;
    }


    private ApduResult decryptCommand(ApduResult result) throws GeneralSecurityException, IOException {
        long oldssc = mKS.getSSC();
        byte[] rapdu = result.raw();
        try {
            if (result == null || rapdu.length < 2) {
                throw new IllegalArgumentException("Invalid response APDU");
            }

            DataInputStream inputStream = new DataInputStream(new ByteArrayInputStream(rapdu));
            byte[] data = new byte[0];
            short sw = 0;
            boolean finished = false;
            byte[] cc = null;

            while (!finished) {
                int tag = inputStream.readByte();
                switch (tag) {
                    case (byte) 0x87:
                        data = readDO87(inputStream, false);
                        break;
                    case (byte) 0x85:
                        data = readDO87(inputStream, true);
                        break;
                    case (byte) 0x99:
                        sw = readDO99(inputStream);
                        break;
                    case (byte) 0x8E:
                        cc = readDO8E(inputStream);
                        finished = true;
                        break;
                }
            }

            if (!checkMac(rapdu, cc)) {
                throw new IllegalStateException("Invalid MAC");
            }

            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            bOut.write(data, 0, data.length);
            bOut.write((sw & 0xFF00) >> 8);
            bOut.write(sw & 0x00FF);

            return new ApduResult(bOut.toByteArray());
        }
        finally {
			/*
			 * If we fail to unwrap, at least make sure we have the same counter
			 * as the ICC, so that we can continue to communicate using secure
			 * messaging...
			 */
            if (mKS.getSSC() == oldssc) {
                mKS.incrementSSC();
            }
        }
    }

    /**
     * The <code>0x87</code> tag has already been read.
     *
     * @param inputStream inputstream to read from
     */
    private byte[] readDO87(DataInputStream inputStream, boolean do85) throws IOException, GeneralSecurityException {
		/* Read length... */
        int length = 0;

        int buf = inputStream.readUnsignedByte();
        if ((buf & 0x00000080) != 0x00000080) {
			/* Short form */
            length = buf;

            if(!do85) {
                buf = inputStream.readUnsignedByte(); /* should be 0x01... */
                if (buf != 0x01) {
                    throw new IllegalStateException("DO'87 expected 0x01 marker, found " + Integer.toHexString(buf & 0xFF));
                }
            }
        }
        else {
			/* Long form */
            int lengthBytesCount = buf & 0x0000007F;
            for (int i = 0; i < lengthBytesCount; i++) {
                length = (length << 8) | inputStream.readUnsignedByte();
            }

            if(!do85) {
                buf = inputStream.readUnsignedByte(); /* should be 0x01... */
                if (buf != 0x01) {
                    throw new IllegalStateException("DO'87 expected 0x01 marker");
                }
            }
        }

        if(!do85) {
            length--; /* takes care of the extra 0x01 marker... */
        }

		/* Read data */
        byte[] ciphertext = new byte[length];
        inputStream.readFully(ciphertext);

        /* Decrypt and unpad data */
        byte[] paddedData = PassportTools.decrypt(mKS.getKSenc(), ciphertext);
        byte[] data = PassportTools.unpad(paddedData);
        return data;
    }

    private short readDO99(DataInputStream inputStream) throws IOException {
        int length = inputStream.readUnsignedByte();
        if (length != 2) {
            throw new IllegalStateException("DO'99 wrong length");
        }

        byte sw1 = inputStream.readByte();
        byte sw2 = inputStream.readByte();
        return (short) (((sw1 & 0x000000FF) << 8) | (sw2 & 0x000000FF));
    }

    private byte[] readDO8E(DataInputStream inputStream) throws IOException, GeneralSecurityException {
        int length = inputStream.readUnsignedByte();
        if (length != 8) {
            throw new IllegalStateException("DO'8E wrong length");
        }

        byte[] cc1 = new byte[8];
        inputStream.readFully(cc1);
        return cc1;
    }

    private boolean checkMac(byte[] rapdu, byte[] cc1) throws GeneralSecurityException {
        try {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            DataOutputStream dataOut = new DataOutputStream(bOut);

            /* Increment and add ssc */
            mKS.incrementSSC();
            dataOut.writeLong(mKS.getSSC());

            byte[] paddedData = PassportTools.pad(rapdu, 0, rapdu.length - 2 - 8 - 2);
            dataOut.write(paddedData, 0, paddedData.length);
            dataOut.flush();
            dataOut.close();

            byte[] cc2 = PassportTools.macNoPadding(mKS.getKSmac(), bOut.toByteArray());
            if (cc2.length > 8 && cc1.length == 8) {
                byte[] newCC2 = new byte[8];
                System.arraycopy(cc2, 0, newCC2, 0, newCC2.length);
                cc2 = newCC2;
            }

            return Arrays.equals(cc1, cc2);
        } catch (IOException ioe) {
            return false;
        }
    }
}
