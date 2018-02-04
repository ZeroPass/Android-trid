/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid.tlv;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import io.zeropass.trid.Utils;

public class TLVUtils implements ASN1Constants {

    /**
     * Deserialize Tag
     *
     * @param data
     * @return tag
     */
    public static int getTag(byte[] data) throws IOException {
        return getTag(data, 0);
    }

    /**
     * Deserialize Tag
     *
     * @param data
     * @param offs offset in data
     * @return tag
     */
    public static int getTag(byte[] data, int offs) throws IOException {
        DataInputStream  inputStream = new DataInputStream(new ByteArrayInputStream(data, offs, data.length - offs));
        int tag = -1;
        int b = inputStream.readUnsignedByte();
        switch (b & 0x1F) {
            case 0x1F:
                tag = b; /* We store the first byte including LHS nibble */
                b = inputStream.readUnsignedByte();

                while ((b & 0x80) == 0x80) {
                    tag <<= 8;
                    tag |= (b & 0x7F);
                    b = inputStream.readUnsignedByte();
                }

                tag <<= 8;
                tag |= (b & 0x7F);
                /*
                * Byte with MSB set is last byte of
           * tag...
           */
                break;
            default:
                tag = b;
                break;
        }

        return tag;
    }

    /**
     * Deserialize data length
     *
     * @param data
     * @param offs offset in data
     * @return data length
     */
    public static int getDataLength(byte[] data, int offs) {
        if(data == null || data.length <= offs) {
            return 0;
        }

        int length = data[offs] & 0xff;
        if((length & 0x80) == 0x80) { // long form
            int numberOfBytes = length & 0x7f;
            if(numberOfBytes > 3) {
                throw new IllegalStateException(String.format("At position %d the len is more then 3 [%d]", offs, numberOfBytes));
            }

            length = 0;
            offs++;
            int endOffs = offs + numberOfBytes;
            if(data.length < endOffs) {
                throw new IllegalStateException(String.format("At position %d the end offset of data to read [%d] is greater then data len=%d", offs, endOffs, data.length));
            }

            for(int i= offs; i < endOffs; i++) {
                length = length * 0x100 + (data[i] & 0xff);
            }
        }

        return length;
    }

    /**
     * Get serialized Tag byte count
     *
     * @param tag
     * @return number of bytes of serialized tag
     */
    public static int getTagBytesCount(int tag) {
        return getTagAsBytes(tag).length;
    }

    /**
     * Get serialized Tag byte count
     *
     * @param data
     * @param offs offset in data
     * @return number of bytes of serialized tag
     */
    public static int getTagBytesCount(byte[] data, int offs) {
        if(data == null || data.length <= offs) {
            return 0;
        }

        if ((data[offs] & 0x1F) == 0x1F) { // see subsequent bytes
            int len = 2;
            int endOffs = offs + 10;
            offs++;

            if(data.length < endOffs) {
                throw new IllegalStateException(String.format("At position %d the end offset of data to read [%d] is greater then data len=%d", offs, endOffs, data.length));
            }

            for (int i = offs + 1; i < offs + 10; i++) {
                if ((data[i] & 0x80) != 0x80) {
                    break;
                }
                len++;
            }
            return len;
        } else {
            return 1;
        }
    }

    /**
     * Get serialized length byte count
     *
     * @param length
     * @return number of bytes of serialized length
     */
    public static int getLengthBytesCount(int length) {
        return getLengthAsBytes(length).length;
    }

    /**
     * Get serialized length byte count
     *
     * @param data
     * @param offs offset in data
     * @return number of bytes of serialized length
     */
    public static int getLengthBytesCount(byte data[], int offs) {
        if(data == null || data.length <= offs) {
            return 0;
        }

        int len = data[offs] & 0xff;
        if( (len & 0x80) == 0x80) { // long form
            return 1 + (len & 0x7f);
        } else { // short form
            return 1;
        }
    }

    public static boolean isPrimitive(int tag) {
        int i = 4;
        while( i --> 0) {
            int mask = (0xFF << (8 * i));
            if ((tag & mask) != 0x00) {
                break;
            }
        }

        int msByte = (((tag & (0xFF << (8 * i))) >> (8 * i)) & 0xFF);
        return ((msByte & 0x20) == 0x00);
    }

    /**
     * Serialize Tag to bytes
     *
     * @param tag
     * @return serialized tag.
     */
    public static byte[] getTagAsBytes(int tag) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        int byteCount = (int)(Math.log(tag) / Math.log(256)) + 1;
        for (int i = 0; i < byteCount; i++) {
            int pos = 8 * (byteCount - i - 1);
            out.write((tag & (0xFF << pos)) >> pos);
        }

        byte[] tagBytes = out.toByteArray();
        switch (getTagClass(tag)) {
            case APPLICATION_CLASS:
                tagBytes[0] |= 0x40;
                break;
            case CONTEXT_SPECIFIC_CLASS:
                tagBytes[0] |= 0x80;
                break;
            case PRIVATE_CLASS:
                tagBytes[0] |= 0xC0;
                break;
            default:
                /* NOTE: Unsupported tag class. Now what? */
                break;
        }

        if (!isPrimitive(tag)) {
            tagBytes[0] |= 0x20;
        }

        return tagBytes;
    }

    /**
     * Serialize length to bytes
     *
     * @param length
     * @return serialized length
     */
    public static byte[] getLengthAsBytes(int length) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (length < 0x80) {
      /* short form */
            out.write(length);
        } else {
            int byteCount = log(length, 256);
            out.write(0x80 | byteCount);
            for (int i = 0; i < byteCount; i++) {
                int pos = 8 * (byteCount - i - 1);
                out.write((length & (0xFF << pos)) >> pos);
            }
        }

        return out.toByteArray();
    }

    static int getTagClass(int tag) {
        int i = 0;
        while(i --> 0) {
            int mask = (0xFF << (8 * i));
            if ((tag & mask) != 0x00) {
                break;
            }
        }

        int msByte = (((tag & (0xFF << (8 * i))) >> (8 * i)) & 0xFF);
        switch (msByte & 0xC0) {
            case 0x00:
                return UNIVERSAL_CLASS;
            case 0x40:
                return APPLICATION_CLASS;
            case 0x80:
                return CONTEXT_SPECIFIC_CLASS;
            case 0xC0:
            default:
                return PRIVATE_CLASS;
        }
    }

    private static int log(int n, int base) {
        int result = 0;
        while (n > 0) {
            n = n / base;
            result ++;
        }
        return result;
    }

    /**
     * Get serialized TLV length from TLV fragment
     *
     * @param data - raw tlv fragment
     * @return serialized length
     */
    public static int getRawDataLengthFromFragment(byte[] data) {
        int tagLen  = TLVUtils.getTagBytesCount(data, 0);
        int dataLen = TLVUtils.getDataLength(data, tagLen);

        return dataLen + tagLen + TLVUtils.getLengthBytesCount(dataLen);
    }


    /**
     * Get value from serialized TLV
     *
     * @param data
     * @param offset in data to the beginning of TLV bytes
     * @return TLV value
     */
    public static byte[] getValue(byte[] data, int offset) {
        int tagLen  = TLVUtils.getTagBytesCount(data, offset);
        int dataLen = TLVUtils.getDataLength(data, offset + tagLen);
        return Utils.copyOut(data, tagLen + offset + TLVUtils.getLengthBytesCount(dataLen), dataLen);
    }

    /**
     * Get value from serialized TLV
     *
     * @param tlvData
     * @return TLV value
     */
    public static byte[] getValue(byte[] tlvData) {
        return TLVUtils.getValue(tlvData, 0);
    }
}
