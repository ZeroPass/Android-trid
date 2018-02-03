/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/
/**
 * Created by smlu on 23. 01. 2018.
 */

package io.zeropass.trid.com;

import java.io.IOException;
import android.nfc.tech.NfcA;
import android.nfc.tech.NfcB;
import android.nfc.tech.IsoDep;
import android.nfc.Tag;
import android.support.annotation.Nullable;

import java.security.InvalidParameterException;
import java.util.logging.Logger;
import java.util.logging.Level;

import io.zeropass.trid.Utils;


/**
 * Nfc transmitter for sending APDUs to terminal
 */

public final class NfcProvider extends ComProvider{
    final private IsoDep mIsoDep;

    private static final int mDefaultTimeout = 5000;
    private static final Logger Journal = Logger.getLogger("io.trid.com.nfc.provider");


    public NfcProvider(IsoDep isoDep) throws InvalidParameterException {
        if(isoDep == null) {
            throw new InvalidParameterException("IsoDep == null");
        }

        this.mIsoDep = isoDep;
    }

    @Override
    public boolean isConnected()
    {
        return mIsoDep.isConnected();
    }

    public void connect(int timeout) throws IOException
    {
        try {
            if(!this.isConnected()) {
                mIsoDep.connect();
                mIsoDep.setTimeout(timeout);
            }
        }
        catch(IOException e) {
            Journal.warning("Could not connect to terminal!");
            throw new IOException(e.getMessage());
        }
    }

    @Override
    public  void connect() throws IOException
    {
        this.connect(mDefaultTimeout);
    }

    @Override
    public void disconnect() {
        try{
            mIsoDep.close();
        } catch (IOException e) {;}
    }

    @Override
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

    protected String getLoggerName() {
        return Journal.getName();
    }

    @Override
    protected byte[] transceive(final byte[] data) throws IOException {
        return mIsoDep.transceive(data);
    }
}
