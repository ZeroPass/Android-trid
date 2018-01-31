/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid.passport;

public class PassportError extends Exception {
    public PassportError(String message) {
        super(message);
    }
}
