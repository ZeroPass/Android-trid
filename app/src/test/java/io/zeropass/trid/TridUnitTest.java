package io.zeropass.trid;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class TridUnitTest {
    @Test
    public void Utils() throws Exception {
        UtilsTest.adjustParityBits();
    }

    @Test
    public void PassportTools() {
        PassportToolsTest.runAll();
    }

    @Test
    public void CryptoUtils() {
        CryptoUtilsTest.runAll();
    }
}