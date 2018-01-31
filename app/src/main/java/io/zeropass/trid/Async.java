/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid;

import android.os.AsyncTask;
import android.os.AsyncTask;

import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class Async extends AsyncTask<Void, Void, Object> {
    private static final Logger Journal = Logger.getLogger("async");

    @Override
    protected Object doInBackground(final Void... params) {

        Object result = null;

        try {
            doInBackground();
        } catch (Exception e) {
            result = e;
            Journal.log(Level.SEVERE, e.getMessage(), e);
        }

        return result;
    }

    protected abstract void doInBackground();
}