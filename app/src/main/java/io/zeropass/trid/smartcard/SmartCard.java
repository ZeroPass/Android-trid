/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid.smartcard;

import java.io.IOException;

import io.zeropass.trid.com.ApduCmd;
import io.zeropass.trid.com.ApduResult;
import io.zeropass.trid.com.ComProvider;
import io.zeropass.trid.crypto.SessionCipher;

/**
 * Created by smlu on 1. 02. 2018.
 */

public class SmartCard {
    private ComProvider provider;
    public SmartCard(ComProvider provider) {
        this.provider = provider;
    }

    public void connect() throws IOException {
        provider.connect();
    }

    public boolean isConnected() {
        return provider.isConnected();
    }

    public void disconnect() {
        provider.disconnect();
    }

    protected ApduResult select(int p1, int p2, byte[] data) throws IOException {
        return transceive(new ApduCmd(ISO7816.CLA_NO_SM, ISO7816.INS_SELECT_FILE, p1, p2, data));
    }

    protected ApduResult getChallenge(int le) throws IOException {
        return transceive(new ApduCmd(ISO7816.CLA_NO_SM, ISO7816.INS_GET_CHALLENGE, 0x00, 0x00, le));
    }

    protected ApduResult readBinary(int p1, int p2, int le) throws IOException {
        return transceive(new ApduCmd(ISO7816.CLA_NO_SM, ISO7816.INS_READ_BINARY, p1, p2, le));
    }

    protected ApduResult readBinary(int offset, int len) throws IOException {
        byte offsetHi = (byte) ((offset & 0xFF00) >> 8);
        byte offsetLo = (byte) (offset & 0xFF);

        return readBinary(offsetHi, offsetLo, len);
    }


    protected ApduResult internalAuthenticate(byte[] data, int le) throws IOException {
        return transceive(new ApduCmd(ISO7816.CLA_NO_SM, ISO7816.INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, data, le));
    }

    protected ApduResult externalAuthenticate(byte[] data, int le) throws IOException {

        ApduCmd apdu = new ApduCmd(ISO7816.CLA_NO_SM, ISO7816.INS_EXTERNAL_AUTHENTICATE, 0x00, 0x00, data, le);
        return transceive(apdu);
    }

    protected void setSession(SessionCipher cipher) {
        provider.setSession(cipher);
    }

    protected ApduResult transceive(ApduCmd cmd) throws IOException {
        return provider.transceive(cmd);
    }
}
