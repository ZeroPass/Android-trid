/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid;

import org.junit.Test;

import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import io.zeropass.trid.crypto.CryptoUtils;
import io.zeropass.trid.crypto.RSA_ISO9796_2_DSS1_SHA1;
import io.zeropass.trid.tlv.TLVUtils;

import static junit.framework.Assert.assertEquals;


public class CryptoUtilsTest {

    @Test
    public static void RSA_ISO9796_DSS1_SHA1_SignatureTest() {
        PublicKey pubKey = CryptoUtils.getPublicKeyFromBytes(TLVUtils.getValue(Utils.strToHex("6F81A230819F300D06092A864886F70D010101050003818D0030818902818100A13F98038CC80DE9BE94A917B5CFCE74CC4BB1337222E82D83C3FC2CBF5E81F80CBC4475CE2FCB08DBB2CEDAB4B3264DC12961B8166B32D238E5A52B02A271F46165B5EF03AC24C76B85D4B4E5A872925D692E8159B1B2BCFB5D6A2E086A88A78853363BC2A52E9725C668416243C45E921DED173FF970B4D0C5F277D034CCFD0203010001")));
        byte[] message = Utils.copyOut(CryptoUtils.sha1(Utils.strToHex("AABBCCAABBCC")), 0, 8);
        byte[] signature = Utils.strToHex("22BF2420BE8A18114CA8E3D3AADC44EC0BEC50E42C640882DBFEED068F0AAB75BE69B65130B037F1EBC75EE1448FA3B60B1E70DD9C821D58BDE234B45BDC3F848FF8DD6BB4BB6854E13A940EA038F1FDE7B67C72360AAFB9FED3A4D991973AC9440DB1D7DD6A86B72554A703B47FDDDAA495F514E80549D667E4595DB11801E6");

        boolean isSigValid = RSA_ISO9796_2_DSS1_SHA1.verifySignature((RSAPublicKey) pubKey, message, signature);
        assertEquals(isSigValid, true);
    }

    private static boolean testISO9796Recovery(byte[] f, byte[] message) {
        try {
            Method m = RSA_ISO9796_2_DSS1_SHA1.class.getDeclaredMethod("verifyF", byte[].class, byte[].class);
            m.setAccessible(true);
            Object r = m.invoke(null, f, message);
            return (Boolean)r;
        } catch (IllegalAccessException e) {
            e.printStackTrace();
            return false;
        } catch (InvocationTargetException e) {
            e.printStackTrace();
            return false;
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
            return false;
        }
    }

    @Test
    public static void RSA_ISO9796_DSS1_SHA1_MessageRecoveryTest() {
        /*Test vectors are from ISO9796-2: http://www.sarm.am/docs/ISO_IEC_9796-2_2002(E)-Character_PDF_document.pdf */
        byte[] f1 = Utils.strToHex("4BBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB BBBBBAFE DCBA9876 543210FE DCBA9876 543210FE DCBA9876 543210FE DCBA9876 543210FE DCBA9876 543210FE DCBA9876 54321085 DCC7FC51 3716375A 059D0254 39FCD925 C828ACBC");
        byte[] m1 = Utils.strToHex("FEDCBA98 76543210 FEDCBA98 76543210 FEDCBA98 76543210 FEDCBA98 76543210 FEDCBA98 76543210 FEDCBA98 76543210");
        assert (testISO9796Recovery(f1, m1));
        assertEquals(testISO9796Recovery(f1, m1), true);

        byte[] f2 = Utils.strToHex("6A616263 64626364 65636465 66646566 67656667 68666768 69676869 6A68696A 6B696A6B 6C6A6B6C 6D6B6C6D 6E6C6D6E 6F6D6E6F 706E6F70 716F7071 72707172 73717273 74727374 75737475 76747576 77757677 78767778 79777879 7A78797A 61797A61 627A6162 63611CF7 A9974518 E555C180 2CB810A2 3C274FCF AA7333CC");
        byte[] m2 = Utils.strToHex("626364 62636465");
        assertEquals(testISO9796Recovery(f2, m2), true);
    }

    @Test
    public static void runAll() {
        RSA_ISO9796_DSS1_SHA1_MessageRecoveryTest();
        RSA_ISO9796_DSS1_SHA1_SignatureTest();
    }
}
