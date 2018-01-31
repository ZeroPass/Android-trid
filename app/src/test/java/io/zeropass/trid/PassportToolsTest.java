/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid;

import org.hamcrest.core.IsEqual;
import org.junit.Test;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import io.zeropass.trid.net.ApduCmd;
import io.zeropass.trid.net.ApduResult;
import io.zeropass.trid.passport.ApduEAData;
import io.zeropass.trid.passport.PassportSessionCipher;
import io.zeropass.trid.passport.PassportSessionKey;
import io.zeropass.trid.passport.PassportTools;

import static org.junit.Assert.*;
import static org.junit.Assert.assertNotNull;


public class PassportToolsTest {

    private static void testMRZCheckDigit(String s, char digit) {
        assertEquals(PassportTools.calculateMrzCheckDigit(s), digit);
    }

    @Test
    public static void mrzCheckDigit() {

        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Utils.strToHex("30819F300D06092A864886F70D010101050003818D0030818902818100A13F98038CC80DE9BE94A917B5CFCE74CC4BB1337222E82D83C3FC2CBF5E81F80CBC4475CE2FCB08DBB2CEDAB4B3264DC12961B8166B32D238E5A52B02A271F46165B5EF03AC24C76B85D4B4E5A872925D692E8159B1B2BCFB5D6A2E086A88A78853363BC2A52E9725C668416243C45E921DED173FF970B4D0C5F277D034CCFD0203010000"));

        String[] algorithms = { "RSA", "EC" };

        PublicKey publicKey = null;
        for (String algorithm: algorithms) {
            try {
                KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
                publicKey = keyFactory.generatePublic(pubKeySpec);
                int i = 0;

                if(publicKey != null) {
                    break;
                }
               // return publicKey;
            } catch (InvalidKeySpecException e) {
				/* NOTE: Ignore, try next algorithm. */
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }



        /* Test vectors from ICAO 9303-11 appendix D.2 */

        testMRZCheckDigit("D23145890734", '9');
        testMRZCheckDigit("340712", '7');
        testMRZCheckDigit("950712", '2');

        testMRZCheckDigit("L898902C<", '3');
        testMRZCheckDigit("690806", '1');
        testMRZCheckDigit("940623", '6');

        testMRZCheckDigit("D23145890734", '9');
        testMRZCheckDigit("340712", '7');
        testMRZCheckDigit("950712", '2');
    }

    private static byte[] calculateAndVerify_BAKeySeed(String pn, String dob, String doe, String checkSeed) {
        byte[] keySeed = PassportTools.computeBAC_KeySeed(pn, dob, doe);
        assertThat(keySeed, IsEqual.equalTo(Utils.strToHex(checkSeed)));

        return keySeed;
    }

    @Test
    public static void BACkey() {
        /* Test vectors from ICAO 9303-11 appendix D.1 && D.2 */

        byte[] keySeed = calculateAndVerify_BAKeySeed("L898902C<", "690806", "940623", "239AB9CB282DAF66231DC5A4DF6BFBAE");

        SecretKey encKey = PassportTools.deriveKey(keySeed, PassportTools.ENC_MODE);
        SecretKey macKey = PassportTools.deriveKey(keySeed, PassportTools.MAC_MODE);

        assertThat(encKey.getEncoded(), IsEqual.equalTo(Utils.strToHex("AB94FDECF2674FDFB9B391F85D7F76F2")));
        assertThat(macKey.getEncoded(), IsEqual.equalTo(Utils.strToHex("7962D9ECE03D1ACD4C76089DCE131543")));
    }

    @Test
    public static void BAC() {
        /* Test vectors from ICAO 9303-11 appendix D.1 && D.2 */

        byte[] keySeed = calculateAndVerify_BAKeySeed("L898902C<", "690806", "940623", "239AB9CB282DAF66231DC5A4DF6BFBAE");

        SecretKey encKey = PassportTools.deriveKey(keySeed, PassportTools.ENC_MODE);
        SecretKey macKey = PassportTools.deriveKey(keySeed, PassportTools.MAC_MODE);

        assertThat(encKey.getEncoded(), IsEqual.equalTo(Utils.strToHex("AB94FDECF2674FDFB9B391F85D7F76F2")));
        assertThat(macKey.getEncoded(), IsEqual.equalTo(Utils.strToHex("7962D9ECE03D1ACD4C76089DCE131543")));

        /* Generating EA data */
        byte[] rndIC  = Utils.strToHex("4608F91988702212");
        byte[] rndIFD = Utils.strToHex("781723860C06C226");
        byte[] kIFD   = Utils.strToHex("0B795240CB7049B01C19B33E32804F0B");

        ApduEAData eaData = PassportTools.generateApduEAData(encKey, macKey, rndIC, rndIFD, kIFD);
        assertThat(eaData.E, IsEqual.equalTo(Utils.strToHex("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2")));
        assertThat(eaData.M, IsEqual.equalTo(Utils.strToHex("5F1448EEA8AD90A7")));
        assertThat(eaData.toBytes(), IsEqual.equalTo(Utils.strToHex("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A7")));

        /* Decrypt received EA Data */
        ApduEAData respEaData = new ApduEAData(Utils.strToHex("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449"));
        assert(respEaData.verify(macKey));

        byte[] kIC = PassportTools.extractKicFromEic(encKey, respEaData, rndIFD);
        assertNotNull(kIC);

        PassportSessionKey ks = PassportTools.calculateSessionKey(rndIC, rndIFD, kIFD, kIC);
        assertNotNull(ks);

        assertThat(ks.getKSenc().getEncoded(), IsEqual.equalTo(Utils.strToHex("979EC13B1CBFE9DCD01AB0FED307EAE5")));
        assertThat(ks.getKSmac().getEncoded(), IsEqual.equalTo(Utils.strToHex("F1CB1F1FB5ADF208806B89DC579DC1F8")));
        assertEquals(ks.getSSC(), 0x887022120C06C226L);
    }

    @Test
    public static void secureMessaging() {
        /* Test vectors taken from BAC() function */
        byte[] rndIC  = Utils.strToHex("4608F91988702212");
        byte[] rndIFD = Utils.strToHex("781723860C06C226");
        byte[] kIFD   = Utils.strToHex("0B795240CB7049B01C19B33E32804F0B");
        byte[] kIC    = Utils.strToHex("0B4F80323EB3191CB04970CB4052790B");

        PassportSessionKey ks = PassportTools.calculateSessionKey(rndIC, rndIFD, kIFD, kIC);

        /* Verify key data */
        assertNotNull(ks);
        assertThat(ks.getKSenc().getEncoded(), IsEqual.equalTo(Utils.strToHex("979EC13B1CBFE9DCD01AB0FED307EAE5")));
        assertThat(ks.getKSmac().getEncoded(), IsEqual.equalTo(Utils.strToHex("F1CB1F1FB5ADF208806B89DC579DC1F8")));
        assertEquals(ks.getSSC(), 0x887022120C06C226L);

        PassportSessionCipher sc = new PassportSessionCipher(ks);
        assertNotNull(sc);

        // Test vectord taken from ICAO 9303-11 D.4
        try {
            // 1. Select EF.COM
            /* Encrypt APDU cmd*/
            byte[] cmdData = new byte[2];
            cmdData[0] = 0x01;
            cmdData[1] = 0x1E;
            ApduCmd cmd = new ApduCmd(0x00, 0xA4, 0x02, 0x0C, cmdData);

            ApduCmd encCmd = sc.encrypt(cmd);
            assertNotNull(encCmd);
            assertArrayEquals(Utils.strToHex("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800"), encCmd.toBytes());


            /* Decrypt APDU result */
            ApduResult rapdu = new ApduResult(Utils.strToHex("990290008E08FA855A5D4C50A8ED9000"));
            rapdu = sc.decrypt(rapdu);
            assertNotNull(rapdu);
            assert(rapdu.statusCode() == ISO7816.SW_NO_ERROR);

            // 2. Read binary (4 four bytes)
            /* Encrypt APDU cmd */
            cmd = new ApduCmd(0x00, 0xB0, 0x00, 0x00, 4);
            encCmd = sc.encrypt(cmd);
            assertNotNull(encCmd);
            assertArrayEquals(Utils.strToHex("0CB000000D9701048E08ED6705417E96BA5500"), encCmd.toBytes());

            /* Dectypt APDU result */
            rapdu = new ApduResult(Utils.strToHex("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000"));
            rapdu = sc.decrypt(rapdu);
            assertNotNull(rapdu);
            assert(rapdu.statusCode() == ISO7816.SW_NO_ERROR);

            byte[] read4Bytes = rapdu.data();
            assertArrayEquals(Utils.strToHex("60145F01"), read4Bytes);

            // 3. Read binary (remaining 18 bytes from offset 4) {
            /* Encrypt APDU cmd */
            cmd = new ApduCmd(0x00, 0xB0, 0x00, 0x04, 0x12);
            encCmd = sc.encrypt(cmd);
            assertNotNull(encCmd);
            assertArrayEquals(Utils.strToHex("0CB000040D9701128E082EA28A70F3C7B53500"), encCmd.toBytes());

            /* Dectypt APDU result */
            rapdu = new ApduResult(Utils.strToHex("871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D749000"));
            rapdu = sc.decrypt(rapdu);
            assertNotNull(rapdu);
            assert(rapdu.statusCode() == ISO7816.SW_NO_ERROR);
            assertArrayEquals(Utils.strToHex("04303130365F36063034303030305C026175"), rapdu.data());

            // Final check
            assertArrayEquals(Utils.strToHex("60145F0104303130365F36063034303030305C026175"), Utils.join(read4Bytes, rapdu.data()));
        }
        catch (Exception e) {
            Logger.getGlobal().severe("And exception was thrown: " + e.getMessage());
            assert(false);
        }
    }

    @Test
    public static void runAll() {
        mrzCheckDigit();
        BACkey();
        BAC();
        secureMessaging();
    }
}
