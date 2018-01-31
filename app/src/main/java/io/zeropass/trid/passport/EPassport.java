/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid.passport;

import android.nfc.tech.IsoDep;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.text.SimpleDateFormat;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import java.util.logging.Logger;

import io.zeropass.trid.ISO7816;
import io.zeropass.trid.Utils;
import io.zeropass.trid.net.ApduCmd;
import io.zeropass.trid.net.ApduResult;
import io.zeropass.trid.net.NfcTransmitterError;
import io.zeropass.trid.smartcard.SmartCardError;


/*/
* Interface for reading files from ePassport and using BAC and AA protocols.
*
* Refs:
* https://www.icao.int/publications/pages/publication.aspx?docnum=9303
* https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
* http://wireilla.com/papers/ijbb/V2N1/2112ijbb02.pdf
* https://www.icao.int/Security/mrtd/Pages/default.aspx
* http://wiki.yobi.be/wiki/EPassport
* https://www.commoncriteriaportal.org/files/ppfiles/c0247_epp.pdf
* http://www.sarm.am/docs/ISO_IEC_9796-2_2002(E)-Character_PDF_document.pdf
* https://books.google.si/books?id=cNanimitjLwC&pg=PA39&lpg=PA39&dq=%22LDS+Data+Group+15%22&source=bl&ots=OqmNEQd0HS&sig=kIjGal3K2BrixOXKY_9lt1WIi-4&hl=sl&sa=X&ved=0ahUKEwjbnLavyevYAhWmOsAKHfvODfAQ6AEIKjAB#v=onepage&q=Active%20Auth&f=false
*/
public class EPassport extends PassportApdu {

    /** The data group presence list. */
    public static final short EF_COM = 0x011E;

    /** The security document. */
    public static final short EF_SOD = 0x011D;

    /** Data group 15 contains the public key used for Active Authentication. */
    public static final short EF_DG15 = 0x010F;



    private PublicKey mPublicKey; // ePassport's public key


    private static final SimpleDateFormat mSdf = new SimpleDateFormat("yyMMdd");

    private static final Logger Journal = Logger.getLogger("passport");



    public EPassport(IsoDep isoDep) throws NfcTransmitterError, PassportError {
        super(isoDep);
    }

    public void selectApplet() throws NfcTransmitterError {
        final byte[] appletId = { (byte) 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };
        selectApplet(appletId);
    }

    /*Returns ICC's public key */
    public byte[] readPublicKey() throws NfcTransmitterError {
        Journal.info("Reading IC Public Key from IC" );

        byte[] publicKey = null;
        try {
            selectFile(EF_COM);
            selectFile(EF_SOD);
            selectFile(EF_DG15);

            byte[] first8Bytes = readBinary(0, 8);

            // TODO: +2 is wrong should be + 3! why: TLV= Tag + Length + Value.
            //   Tag= 1 byte, Length= 1-3 byte depends on length. and since the size of public key is greater then 128bytes, the size of TL is 3bytes, which has to be counted
            int length = readLength(Utils.copyOut(first8Bytes, 1, 7)) + 3;

            byte[] data = readBinary(8, length - 8);

            publicKey = Utils.join(first8Bytes, data);

        } catch (SmartCardError e) {
            Journal.severe("readPublicKey: And exception was thrown e=" + e.getMessage());
        }

        return publicKey;
    }

    int readLength(byte[] data ) {
        int length = 0;
        try {
            ByteArrayInputStream bis =  new ByteArrayInputStream(data);
            DataInputStream inputStream = new DataInputStream(bis);
            int bytesRead = 0;

            int b = inputStream.readUnsignedByte();
            bytesRead++;
            if ((b & 0x80) == 0x00) {
            /* short form */
                length = b;
            } else {
            /* long form */
                int count = b & 0x7F;
                length = 0;
                for (int i = 0; i < count; i++) {
                    b = inputStream.readUnsignedByte();
                    bytesRead++;
                    length <<= 8;
                    length |= b;
                }
            }


        } catch (IOException e) {
            e.printStackTrace();
        }

        return length;
    }
    /*
    *  Function generate answer to getChallange response and
    *  calculates session key from response.
    *  specified in document ICAO 9303-11 appendix d.3
    *
    *  @returns kIC
    */
    private PassportSessionKey generateSessionKey(SecretKey encKey, SecretKey macKey, byte[] rndIC, byte[] rndIFD, byte[] kIFD) throws NfcTransmitterError {
        Utils.printDebug(Journal.getName(), String.format("generateSessionKey: generating E.IFD and M.IFD from:\nRND.IC=%s\nRND.IFD=%s\nK.IFD=%s\nK.ENC=%s\nK.MAC=%s",
                Utils.hexToStr(rndIC), Utils.hexToStr(rndIFD), Utils.hexToStr(kIFD), Utils.hexToStr(encKey.getEncoded()), Utils.hexToStr(macKey.getEncoded())));

        ApduEAData eaData = PassportTools.generateApduEAData(encKey, macKey, rndIC, rndIFD, kIFD);
        if(eaData == null) {
            Journal.warning("generateSessionKey: failed to generate EA data");
            return null;
        }

        /* Authenticate data and retrieve K.IC */
        ApduEAData result = externalAuthenticate(eaData);
        if(result == null) {
            return  null;
        }

        /* Verify result */
        if(!result.verify(macKey)) {
            Journal.warning("generateSessionKey: received EA data mac mismatch!");
            return null;
        }

        /* Extract K.IC from E.IC */
        byte[] kIC = PassportTools.extractKicFromEic(encKey, result, rndIFD);
        return PassportTools.calculateSessionKey(rndIC, rndIFD, kIFD, kIC);
    }

    /*
    *  Function does Basic Access Control (BAC) as specified in document ICAO 9303-11
    */
    public  boolean doBAC(String documentNumber, String dateOfBirth, String dateOfExpiry) throws InvalidAlgorithmParameterException, NfcTransmitterError {
        documentNumber = PassportTools.formatDocumentNumber(documentNumber);
        //TODO verify dates
//        dateOfBirth = mSdf.format(dateOfBirth);
//        dateOfExpiry = mSdf.format(dateOfExpiry);
        Utils.printDebug(Journal.getName(), "Executing BAC with: passportNumber:" + documentNumber +
                " dateOfBirth:" + dateOfBirth + " dateOfExpiry:" + dateOfExpiry);

        byte[] keySeed = PassportTools.computeBAC_KeySeed(documentNumber, dateOfBirth, dateOfExpiry);
        SecretKey encKey = PassportTools.deriveKey(keySeed, PassportTools.ENC_MODE);
        SecretKey macKey = PassportTools.deriveKey(keySeed, PassportTools.MAC_MODE);

        Utils.printDebug(Journal.getName(), "Calculated BA key: "+ Utils.hexToStr(encKey.getEncoded()));
        Utils.printDebug(Journal.getName(), "Calculated BA mac key: "+ Utils.hexToStr(macKey.getEncoded()));

        return doBAC(encKey, macKey);
    }

   /*
   *  See appendix D.3 of ICAO 9303-11
   */
    private boolean doBAC(SecretKey encKey, SecretKey macKey) throws NfcTransmitterError {
        byte[] rndIC = getChallenge();
        if(rndIC == null) {
            Journal.warning("BAC error: failed to get challenge from IC!");
            return false;
        }

        /* Generate random num and key */
        byte[] rndIFD = Utils.getRandomBytes(PassportTools.RND_IFD_LEN);
        byte[] kIFD   = Utils.getRandomBytes(PassportTools.KIFD_LEN);

        /* Generate session key with IC */
        PassportSessionKey ks = generateSessionKey(encKey, macKey, rndIC, rndIFD, kIFD);
        if(ks == null) {
            Journal.warning("BAC failed.");
            return false;
        }

        Journal.info("BAC succeeded. Setting new session.");
        Utils.printDebug(Journal.getName(), "SessionCipher key: "+ Utils.hexToStr(ks.getKSenc().getEncoded()));
        Utils.printDebug(Journal.getName(), "SessionCipher mac key: "+ Utils.hexToStr(ks.getKSmac().getEncoded()));
        Utils.printDebug(Journal.getName(), "SSC: " + ks.getSSC());

        setSessionKey(ks);
        return true;
    }
}
