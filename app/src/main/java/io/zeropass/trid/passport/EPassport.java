/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid.passport;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.InvalidParameterException;
import java.text.SimpleDateFormat;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import java.util.logging.Logger;

import io.zeropass.trid.Utils;
import io.zeropass.trid.com.ComProvider;
import io.zeropass.trid.crypto.CryptoUtils;
import io.zeropass.trid.crypto.PassportSessionKey;
import io.zeropass.trid.passport.lds.LDSFile;
import io.zeropass.trid.smartcard.SmartCardError;
import io.zeropass.trid.tlv.TLVUtils;


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



    private PublicKey mPublicKey; // ePassport's public key


    private static final SimpleDateFormat mSdf = new SimpleDateFormat("yyMMdd");

    private static final Logger Journal = Logger.getLogger("io.trid.passport");



    public EPassport(ComProvider provider) throws IOException, PassportError {
        super(provider);

        if(!isConnected()) {
            connect();
        }
    }

    /*Returns ICC's public key */
    public PublicKey readPublicKey() throws IOException {
        Journal.info("Reading IC Public Key from IC" );

        PublicKey pk = null;
        try {
            selectFile(LDSFile.EF_COM_FID);
            selectFile(LDSFile.EF_SOD_FID);

            // TODO: try reading by SFI
            byte[] dg15File = readFile(LDSFile.EF_DG15_FID);
            if(dg15File == null) {
                return null;
            }

            int tag = TLVUtils.getTag(dg15File, 0);
            if(tag != LDSFile.EF_DG15_TAG) {
                Journal.severe("readPublicKey: Received invalid EF with TAG=" + tag );
                return null;
            }

            /* Extract ASN.1 DER encoded public key */
            pk = CryptoUtils.getPublicKeyFromBytes(TLVUtils.getValue(dg15File));

        } catch (SmartCardError | IOException e) {
            Journal.severe("readPublicKey: An exception was thrown e=" + e.getMessage());
        }

        return pk;
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
    private PassportSessionKey generateSessionKey(SecretKey encKey, SecretKey macKey, byte[] rndIC, byte[] rndIFD, byte[] kIFD) throws IOException {
        Utils.printDebug(Journal.getName(), String.format("generateSessionKey: generating E.IFD and M.IFD from:\nRND.IC=%s\nRND.IFD=%s\nK.IFD=%s\nK.ENC=%s\nK.MAC=%s",
                Utils.hexToStr(rndIC), Utils.hexToStr(rndIFD), Utils.hexToStr(kIFD), Utils.hexToStr(encKey.getEncoded()), Utils.hexToStr(macKey.getEncoded())));

        ApduEAData eaData = PassportTools.generateApduEAData(encKey, macKey, rndIC, rndIFD, kIFD);
        if(eaData == null) {
            Journal.warning("generateSessionKey: Failed to generate EA data");
            return null;
        }

        /* Authenticate data and retrieve K.IC */
        ApduEAData result = externalAuthenticate(eaData);
        if(result == null) {
            return  null;
        }

        /* Verify result */
        if(!result.verify(macKey)) {
            Journal.warning("generateSessionKey: Received EA data checksum mismatch!");
            return null;
        }

        /* Extract K.IC from E.IC */
        byte[] kIC = PassportTools.extractKicFromEic(encKey, result, rndIFD);
        return PassportTools.calculateSessionKey(rndIC, rndIFD, kIFD, kIC);
    }

    /*
    *  Function does Basic Access Control (BAC) as specified in document ICAO 9303-11
    *  Note: BAC might become deprecated in the future. Instead PACE should be used
    *        to establish session. see: section 4.1 ++https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
    */
    public  boolean doBAC(String documentNumber, String dateOfBirth, String dateOfExpiry) throws IOException, InvalidParameterException {
        documentNumber = PassportTools.formatDocumentNumber(documentNumber);
        //TODO verifySignature dates
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
    private boolean doBAC(SecretKey encKey, SecretKey macKey) throws IOException {
        Utils.printDebug(Journal.getName(), "Requesting challenge from IC");
        byte[] rndIC = getChallenge();
        if(rndIC == null) {
            Journal.warning("BAC error: failed to get challenge from IC!");
            return false;
        }

        Utils.printDebug(Journal.getName(), "Received challenge from IC: RND.IC=" + Utils.hexToStr(rndIC));

        /* Generate random num and key */
        byte[] rndIFD = CryptoUtils.getRandomBytes(PassportTools.RND_IFD_LEN);
        byte[] kIFD   = CryptoUtils.getRandomBytes(PassportTools.KIFD_LEN);

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
