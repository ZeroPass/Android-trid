/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid.passport.lds;

/** Passport storage structure
 * see ICAO 9303-10 */
public interface LDSFile {

    public static final byte[] EMRTD_AID = { (byte) 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };

    /** The data group presence list. */
    public static final short EF_COM_FID  = 0x011E;
    public static final byte  EF_COM_SFI  = 0x1E;
    public static final int   EF_COM_TAG  = 0x60;

    /** Data group 1 */
    public static final short EF_DG1_FID  = 0x0101;
    public static final byte  EF_DG1_SFI  = 0x01;
    public static final int   EF_DG1_TAG  = 0x61;

    /** Data group 2 */
    public static final short EF_DG2_FID  = 0x0102;
    public static final byte  EF_DG2_SFI  = 0x02;
    public static final int   EF_DG2_TAG  = 0x75;

    /** Data group 3 */
    public static final short EF_DG3_FID  = 0x0103;
    public static final byte  EF_DG3_SFI  = 0x03;
    public static final int   EF_DG3_TAG  = 0x63;

    /** Data group 4 */
    public static final short EF_DG4_FID  = 0x0104;
    public static final byte  EF_DG4_SFI  = 0x04;
    public static final int   EF_DG4_TAG  = 0x76;

    /** Data group 5 */
    public static final short EF_DG5_FID  = 0x0105;
    public static final byte  EF_DG5_SFI  = 0x05;
    public static final int   EF_DG5_TAG  = 0x65;

    /** Data group 5 */
    public static final short EF_DG6_FID  = 0x0106;
    public static final byte  EF_DG6_SFI  = 0x06;
    public static final int   EF_DG6_TAG  = 0x66;

    /** Data group 7 */
    public static final short EF_DG7_FID  = 0x0107;
    public static final byte  EF_DG7_SFI  = 0x07;
    public static final int   EF_DG7_TAG  = 0x67;

    /** Data group 8 */
    public static final short EF_DG8_FID  = 0x0108;
    public static final byte  EF_DG8_SFI  = 0x08;
    public static final int   EF_DG8_TAG  = 0x68;

    /** Data group 9 */
    public static final short EF_DG9_FID  = 0x0109;
    public static final byte  EF_DG9_SFI  = 0x09;
    public static final int   EF_DG9_TAG  = 0x69;

    /** Data group 10 */
    public static final short EF_DG10_FID  = 0x010A;
    public static final byte  EF_DG10_SFI  = 0x0A;
    public static final int   EF_DG10_TAG  = 0x6A;

    /** Data group 11 */
    public static final short EF_DG11_FID  = 0x010B;
    public static final byte  EF_DG11_SFI  = 0x0B;
    public static final int   EF_DG11_TAG  = 0x6B;

    /** Data group 12 */
    public static final short EF_DG12_FID  = 0x010C;
    public static final byte  EF_DG12_SFI  = 0x0C;
    public static final int   EF_DG12_TAG  = 0x6C;

    /** Data group 13 */
    public static final short EF_DG13_FID  = 0x010D;
    public static final byte  EF_DG13_SFI  = 0x0D;
    public static final int   EF_DG13_TAG  = 0x6D;

    /** Data group 14 */
    public static final short EF_DG14_FID  = 0x010E;
    public static final byte  EF_DG14_SFI  = 0x0E;
    public static final int   EF_DG14_TAG  = 0x6E;

    /** Data group 15 contains the public key used for Active Authentication. */
    public static final short EF_DG15_FID  = 0x010F;
    public static final byte  EF_DG15_SFI  = 0x0F;
    public static final int   EF_DG15_TAG  = 0x6F;

    /** Data group 16 */
    public static final short EF_DG16_FID  = 0x0110;
    public static final byte  EF_DG16_SFI  = 0x10;
    public static final int   EF_DG16_TAG  = 0x70;

    /** The document security object. */
    public static final short EF_SOD_FID  = 0x011D;
    public static final byte  EF_SOD_SFI  = 0x1D;
    public static final int   EF_SOD_TAG  = 0x77;

    /** The document security object. */
    public static final short EF_CARD_ACCESS_FID = 0x011C;
    public static final byte  EF_CARD_ACCESS_SFI = 0x1C;

    /** The document security object. */
    public static final short EF_CARD_SECURITY_FID = 0x011D;
    public static final byte  EF_CARD_SECURITY_SFI = 0x1D;
}