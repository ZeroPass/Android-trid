/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid.net;


/*
*  ApduCmd is application protocol data unit (APDU) structure.
*  https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
*  http://cardwerk.com/iso-7816-4-annex-a-smart-card-standard/
*/
public class ApduCmd {

    private int mCla = 0x00;
    private int mIns = 0x00;
    private int mP1 = 0x00;
    private int mP2 = 0x00;
    private byte[] mData = null;
    private int mNe = 0x00;

    public ApduCmd(int cla, int ins, int p1, int p2) {
        this(cla, ins, p1, p2, null, 0);
    }

    public ApduCmd(int cla, int ins, int p1, int p2, byte[] data) {
        this(cla, ins, p1, p2, data, 0);
    }

    public ApduCmd(int cla, int ins, int p1, int p2, int le) {
        this(cla, ins, p1, p2, null, le);
    }

    public ApduCmd(int cla, int ins, int p1, int p2, byte[] data, int ne) {
        mCla = cla;
        mIns = ins;
        mP1 = p1;
        mP2 = p2;
        mData = data;
        mNe = ne;

        if(mData != null && mData.length > 65535) {
            throw new IllegalArgumentException("Data len too big");
        }

        if (mNe < 0) {
            throw new IllegalArgumentException("Le < 0");
        }
        else if (mNe > 65536) {
            throw new IllegalArgumentException("Le > 65536");
        }
    }

    public int cla() {
        return mCla;
    }

    public int ins() {
        return mIns;
    }

    public int p1() {
        return mP1;
    }

    public int p2() {
        return mP2;
    }

    public byte[] data() {
        return mData;
    }

    public int ne() {
        return mNe;
    }


    private byte[] serializeDataAndLe(byte[] data, int ne) {
        if (data == null) {
            if (ne > 0) {
                if (ne <= 256) {
                    // 256 is encoded as 0x00
                    byte len = (ne != 256) ? (byte)ne : 0;
                    byte[] ser = new byte[1];
                    ser[0] = len;
                    return ser;
                }
                else { // ne > 256
                    byte l1, l2;

                    if (ne == 65536) { // 65536 is encoded as 0x0000
                        l1 = 0;
                        l2 = 0;
                    } else {
                        l1 = (byte)(ne >> 8);
                        l2 = (byte)ne;
                    }

                    byte[] ser = new byte[3];
                    ser[0] = 0; // first byte must be 0
                    ser[1] = l1;
                    ser[2] = l2;
                    return ser;
                }
            }
        }
        else { // data != null
            if (ne < 1) {
                if (data.length <= 255) {
                    byte[] ser = new byte[1 + data.length];
                    ser[0] = (byte)data.length;

                    System.arraycopy(data, 0, ser, 1, data.length);
                    return ser;
                }
                else {
                    byte[] ser = new byte[3 + data.length];
                    ser[0] = 0;
                    ser[1] = (byte)(data.length >> 8);
                    ser[2] = (byte) data.length;

                    System.arraycopy(data, 0, ser, 3, data.length);
                    return ser;
                }
            }
            else { // ne >= 1
                if ((data.length <= 255) && (ne <= 256)) {
                    byte[] ser = new byte[2 + data.length];
                    ser[0] = (byte)data.length;

                    System.arraycopy(data, 0, ser, 1, data.length);
                    ser[ser.length - 1] = (ne != 256) ? (byte)ne : 0;
                    return ser;
                }
                else {
                    byte[] ser = new byte[5 + data.length];
                    ser[0] = 0;
                    ser[1] = (byte)(data.length >> 8);
                    ser[2] = (byte) data.length;

                    System.arraycopy(data, 0, ser, 3, data.length);
                    if (ne != 65536) {
                        int lePos = ser.length - 2;
                        ser[lePos]     = (byte)(ne >> 8);
                        ser[lePos + 1] = (byte)ne;
                    }

                    return ser;
                }
            }
        }

        return null;
    }

    /* Serialize APDU to bytes */
    public byte[] toBytes() {
        if(this == null) {
            return null;
        }

        byte[] apduBytes = new byte[4]; // header
        apduBytes[0] = (byte) mCla;
        apduBytes[1] = (byte) mIns;
        apduBytes[2] = (byte) mP1;
        apduBytes[3] = (byte) mP2;

        byte[] dataAndLeBytes = serializeDataAndLe(mData, mNe);
        if(dataAndLeBytes != null) {
            byte[] newApduBytes = new byte[apduBytes.length + dataAndLeBytes.length];
            System.arraycopy(apduBytes, 0, newApduBytes, 0, apduBytes.length);
            System.arraycopy(dataAndLeBytes, 0, newApduBytes, apduBytes.length, dataAndLeBytes.length);

            apduBytes = newApduBytes;
        }

        return apduBytes;
    }
}


