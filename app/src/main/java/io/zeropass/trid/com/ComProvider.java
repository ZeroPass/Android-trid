/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid.com;

import android.util.Log;
import java.io.IOException;
import java.security.InvalidParameterException;
import io.zeropass.trid.Utils;
import io.zeropass.trid.crypto.SessionCipher;

/** Abstract class to provide communication between IFD and IC */
public abstract class ComProvider {

    private SessionCipher mSession = null;

    protected abstract String getLoggerName();

    public abstract boolean isConnected();
    public abstract void connect() throws IOException;
    public abstract void disconnect();

    public abstract byte[] getATR();

    protected abstract byte[] transceive(final byte[] data) throws IOException;

    public void setSession(SessionCipher s) {
        mSession = s;
    }

    public ApduResult transceive(ApduCmd cmd) throws IOException {

        byte[] cmdBytes = null;
        if(mSession != null) {
            cmdBytes = mSession.encrypt(cmd).toBytes();
        }
        else {
            cmdBytes = cmd.toBytes();
        }

            /* Send raw apdu bytes */
        Utils.printDebug(getLoggerName(), String.format("sending bytes to ICC: len=%d data=%s", cmdBytes.length, Utils.hexToStr(cmdBytes)));
        byte[] response = transceive(cmdBytes);

        try {
            Utils.printDebug(getLoggerName(), String.format("received bytes from ICC: len=%d data=%s", response.length, Utils.hexToStr(response)));
            ApduResult res = new ApduResult(response);

                /* Decrypt apdu result */
            if(mSession != null) {
                res = mSession.decrypt(res);
            }

            return res;
        }
        catch (InvalidParameterException e) {
            Log.e(getLoggerName(),"Apdu result error: " + e.getLocalizedMessage());
            return null;
        }
    }
}
