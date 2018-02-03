/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid;

import org.hamcrest.core.IsEqual;
import org.junit.Test;
import static org.junit.Assert.*;
import android.support.v4.util.Pair;
import io.zeropass.trid.Utils;
import io.zeropass.trid.passport.PassportTools;


public class UtilsTest {

    private static void testAPB(byte[] input, byte[] output) {
        Utils.adjustParityBits(input);
        assertThat(input, IsEqual.equalTo(output));
    }

    @Test
    public static void adjustParityBits() {
        Pair<byte[], byte[]> tv1 = new Pair<>(Utils.strToHex("AB94FCEDF2664EDF"), Utils.strToHex("AB94FDECF2674FDF"));
        Pair<byte[], byte[]> tv2 = new Pair<>(Utils.strToHex("B9B291F85D7F77F2"), Utils.strToHex("B9B391F85D7F76F2"));
        Pair<byte[], byte[]> tv3 = new Pair<>(Utils.strToHex("7862D9ECE03C1BCD"), Utils.strToHex("7962D9ECE03D1ACD"));
        Pair<byte[], byte[]> tv4 = new Pair<>(Utils.strToHex("4D77089DCF131442"), Utils.strToHex("4C76089DCE131543"));

        testAPB(tv1.first, tv1.second);
        testAPB(tv2.first, tv2.second);
        testAPB(tv3.first, tv3.second);
        testAPB(tv4.first, tv4.second);
    }

    public static void runAll() {
        adjustParityBits();
    }
}
