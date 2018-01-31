package io.zeropass.trid.smartcard;

/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

public class SmartCardError extends Exception {
    private short mSW = 0;
    public SmartCardError(String message, short sw) {
        super(message);
        mSW = sw;
    }

    public short getSW() {
        return mSW;
    }
}