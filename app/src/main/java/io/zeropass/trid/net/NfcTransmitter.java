/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/
/**
 * Created by smlu on 23. 01. 2018.
 */

package io.zeropass.trid.net;

import java.io.IOException;
import android.nfc.tech.NfcA;
import android.nfc.tech.NfcB;
import android.nfc.tech.IsoDep;
import android.nfc.Tag;
import android.support.annotation.Nullable;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.util.logging.Logger;
import java.util.logging.Level;

import io.zeropass.trid.Utils;


/**
 * Nfc transmitter for sending APDUs to terminal
 */

public final class NfcTransmitter {
    final private IsoDep mIsoDep;
    private SessionCipher mSession = null;

    private static final int mDefaultTimeout = 5000;
    private static final Logger Journal = Logger.getLogger("net.nfc_transmitter");


    public NfcTransmitter(IsoDep isoDep) throws NfcTransmitterError {
        if(isoDep == null) {
            throw new NfcTransmitterError("IsoDep == null");
        }

        this.mIsoDep = isoDep;
    }

    public boolean isConnected()
    {
        return mIsoDep.isConnected();
    }

    public void connect(int timeout) throws NfcTransmitterError
    {
        try {
            if(!this.isConnected()) {
                mIsoDep.connect();
                mIsoDep.setTimeout(timeout);
            }
        }
        catch(IOException e) {
            Journal.log(Level.WARNING, "Could not connect to terminal", e);
            throw new NfcTransmitterError(e.getMessage());
        }
    }

    public  void connect() throws NfcTransmitterError
    {
        this.connect(mDefaultTimeout);
    }

    public void disconnect() {
        try{
            mIsoDep.close();
        } catch (IOException e) {;}
    }

    @Nullable
    public byte[] getATR() {
        Tag tag = mIsoDep.getTag();
        if (tag == null) {
            return null;
        }

        NfcA nfcA = NfcA.get(tag);
        if (nfcA != null) {
            return mIsoDep.getHistoricalBytes();
        }

        NfcB nfcB = NfcB.get(tag);
        if (nfcB != null) {
            return mIsoDep.getHiLayerResponse();
        }

        return mIsoDep.getHistoricalBytes();
    }

    public void setSession(SessionCipher s) {
        mSession = s;
    }

    public ApduResult transceive(ApduCmd cmd) throws NfcTransmitterError {
        try {
            if(mIsoDep == null) {
                Journal.log(Level.SEVERE, "Cannot transceive apdu command IsoDep is null!");
                return null;
            }

            byte[] cmdBytes = null;
            if(mSession != null) {
                cmdBytes = mSession.encrypt(cmd).toBytes();
            }
            else {
                cmdBytes = cmd.toBytes();
            }

            /* Send raw apdu bytes */
            Utils.printDebug(Journal.getName(), String.format("sending bytes to ICC: len=%d data=%s", cmdBytes.length, Utils.hexToStr(cmdBytes)));
            byte[] response = mIsoDep.transceive(cmdBytes);

            try {
                Utils.printDebug(Journal.getName(), String.format("received bytes from ICC: len=%d data=%s", response.length, Utils.hexToStr(response)));
                ApduResult res = new ApduResult(response);

                /* Decrypt apdu result */
                if(mSession != null) {
                    res = mSession.decrypt(res);
                }

                return res;
            }
            catch (InvalidParameterException e) {
                Journal.log(Level.SEVERE, "Apdu result error: " + e.getLocalizedMessage());
                return null;
            }
        }
        catch (IOException e) {
            throw new NfcTransmitterError(e.getMessage());
        }
    }
}
