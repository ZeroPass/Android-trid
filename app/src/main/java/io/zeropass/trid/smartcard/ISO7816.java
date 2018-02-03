/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid.smartcard;

/**
 * Created by smlu on 23. 01. 2018.
 */

/**
 * ISO 7816-4  Interindustry Commands
 * http://cardwerk.com/smart-card-standard-iso7816-4-section-5-basic-organizations/
 * http://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands
 */
public interface ISO7816 {
    static final byte CLA_NO_SM                         = (byte)0x00;
    static final byte INS_GET_CHALLENGE                 = (byte)0x84;
    static final byte INS_EXTERNAL_AUTHENTICATE         = (byte)0x82;
    static final byte INS_INTERNAL_AUTHENTICATE         = (byte)0x88;
    static final byte INS_READ_BINARY                   = (byte)0xB0;
    static final byte INS_READ_BINARY2                  = (byte)0xB1;
    static final byte INS_SELECT                        = (byte)0xA4;
    static final byte INS_SELECT_FILE                   = (byte)0xA4;
    static final short SW_COMMAND_NOT_ALLOWED           = (short)0x6986;
    static final short SW_CONDITIONS_NOT_SATISFIED      = (short)0x6985;
    static final short SW_FILE_NOT_FOUND                = (short)0x6A82;
    static final short SW_NO_ERROR                      = (short)0x9000;
    static final short SW_SECURITY_STATUS_NOT_SATISFIED = (short)0x6982;
    static final short SW_UNKNOWN                       = (short)0x6F00;

}
