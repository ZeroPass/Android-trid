/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid.tlv;

public interface ASN1Constants {
    /** Universal tag class. */
    public static final int UNIVERSAL_CLASS = 0;
    public static final int APPLICATION_CLASS = 1;
    public static final int CONTEXT_SPECIFIC_CLASS = 2;
    public static final int PRIVATE_CLASS = 3;

    /* Primitive tags X.690 */
    public static final int BOOLEAN_TYPE_TAG           = 0x01;
    public static final int INTEGER_TYPE_TAG           = 0x02;
    public static final int BIT_STRING_TYPE_TAG        = 0x03;
    public static final int OCTET_STRING_TYPE_TAG      = 0x04;
    public static final int NULL_TYPE_TAG              = 0x05;
    public static final int OBJECT_IDENTIFIER_TYPE_TAG = 0x06;
    public static final int OBJECT_DESCRIPTOR_TYPE_TAG = 0x07;
    public static final int EXTERNAL_TYPE_TAG          = 0x08;
    public static final int REAL_TYPE_TAG              = 0x09;
    public static final int ENUMERATED_TYPE_TAG        = 0x0A;
    public static final int EMBEDDED_PDV_TYPE_TAG      = 0x0B;
    public static final int UTF8_STRING_TYPE_TAG       = 0x0C;
    public static final int SEQUENCE_TYPE_TAG          = 0x10;
    public static final int SET_TYPE_TAG               = 0x11;
    public static final int NUMERIC_STRING_TYPE_TAG    = 0x12;
    public static final int PRINTABLE_STRING_TYPE_TAG  = 0x13;
    public static final int T61_STRING_TYPE_TAG        = 0x14;
    public static final int IA5_STRING_TYPE_TAG        = 0x16;
    public static final int UTC_TIME_TYPE_TAG          = 0x17;
    public static final int GENERALIZED_TIME_TYPE_TAG  = 0x18;
    public static final int GRAPHIC_STRING_TYPE_TAG    = 0x19;
    public static final int VISIBLE_STRING_TYPE_TAG    = 0x1A;
    public static final int GENERAL_STRING_TYPE_TAG    = 0x1B;
    public static final int UNIVERSAL_STRING_TYPE_TAG  = 0x1C;
    public static final int BMP_STRING_TYPE_TAG        = 0x1E;
}
