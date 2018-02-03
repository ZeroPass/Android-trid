/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid.crypto;

import java.security.InvalidParameterException;
import javax.crypto.SecretKey;
import io.zeropass.trid.passport.PassportTools;

public class PassportSessionKey {
    private SecretKey mKSenc;
    private SecretKey mKSmac;
    private long mSSC;

    public PassportSessionKey(SecretKey ksEnc, SecretKey ksMac, long ssc) {
        if(ksEnc.getEncoded().length != PassportTools.KEY_LEN) {
            throw  new InvalidParameterException("ksEnc len != 16");
        }

        if(ksMac.getEncoded().length != PassportTools.KEY_LEN) {
            throw  new InvalidParameterException("ksMac len != 16");
        }

        mKSenc = ksEnc;
        mKSmac = ksMac;
        mSSC = ssc;
    }

    public SecretKey getKSenc() {
        return mKSenc;
    }

    public SecretKey getKSmac() {
        return mKSmac;
    }

    public long getSSC() {
        return mSSC;
    }

    public void incrementSSC() {
        mSSC++;
    }
}
