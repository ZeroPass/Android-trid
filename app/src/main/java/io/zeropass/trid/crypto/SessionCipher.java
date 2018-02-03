/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid.crypto;

import java.io.IOException;

import io.zeropass.trid.com.ApduCmd;
import io.zeropass.trid.com.ApduResult;

/**
 * Created by smlu on 29. 01. 2018.
 */

public abstract class SessionCipher {

    /**
    * Encrypts APDU data
    *
    * @returns encrypted APDU bytes
    */
    public abstract ApduCmd encrypt(ApduCmd cmd) throws IOException;

    /**
     * Decrypt APDU result data
     *
     * @returns encrypted APDU bytes
     */
    public abstract ApduResult decrypt(ApduResult result);

}
