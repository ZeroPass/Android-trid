/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid.net;

import java.security.InvalidParameterException;

import io.zeropass.trid.Utils;

public class ApduResult {
    private byte[] mData;
    private short  mStatusCode;
    public ApduResult(byte[] rawResponse) throws InvalidParameterException {
        final int len = rawResponse.length;
        if(rawResponse == null || len < 2) {
            throw new InvalidParameterException("Invalid raw response!");
        }

        if(len > 2) {
            mData = new byte[len - 2];
            System.arraycopy(rawResponse, 0, mData, 0, len - 2);
        }

        byte sw1 = rawResponse[len-2];
        byte sw2 = rawResponse[len-1];
        mStatusCode = (short) ((sw1 << 8 ) | sw2);
    }

    public byte[] data() {
        return mData;
    }

    public short statusCode() {
        return mStatusCode;
    }

    public byte[] raw() {
        byte[] sw = new byte[2];
        sw[0] = (byte)( mStatusCode & 0x00FF);
        sw[1] = (byte)( mStatusCode & 0xFF00);
        return Utils.join(mData, sw);
    }
}
