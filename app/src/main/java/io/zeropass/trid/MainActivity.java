/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid;

import io.zeropass.trid.net.NfcTransmitterError;
import java.security.InvalidAlgorithmParameterException;
import java.util.logging.Logger;

import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.provider.Settings;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.EditText;
import android.widget.Button;
import android.widget.TextView;
import android.widget.ScrollView;
import android.widget.Toast;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.app.ProgressDialog;
import java.util.Arrays;

public class MainActivity extends AppCompatActivity {

    private static final Logger Journal = Logger.getLogger("main");
    private Button mBtnCopyToClipboard;
    private TextView mTvOutput;
    private ScrollView mSvOutput;
    private EditText mEditTextDataToSign;
    private EditText mEditTextPassNum;
    private EditText mEditTextDob;
    private EditText mEditTextDoe;

    private byte[] mDataToSign;
    private String mPassportNumber;
    private String mDateOfBirth;
    private String mDateOfExpiry;

    private ProgressBar mProgressBar;
    private LinearLayout mMainLayout;
    private LinearLayout mProgressBarLayout;
    private TextView mProgressBarText;

    ProgressDialog mProgressDialog;


    // Nfc
    private NfcAdapter mNfcAdapter = null;
    private PendingIntent mPendingIntent;
    private static final IntentFilter[] mIntentFilters = new IntentFilter[]{new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED)};
    private static final String[][] mTechLists = new String[][]{{IsoDep.class.getName()}};

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mBtnCopyToClipboard = (Button)findViewById(R.id.btnCopy);
        mSvOutput = (ScrollView) findViewById(R.id.scrollViewOutput);
        mTvOutput = (TextView)findViewById(R.id.textViewOutput);
        setOutputVisible(false);

        mEditTextDataToSign = (EditText)findViewById(R.id.editTextDataToSign);
        mEditTextPassNum    = (EditText)findViewById(R.id.editTextPassportNumber);
        mEditTextDob = (EditText)findViewById(R.id.editTextDateOfBirth);
        mEditTextDoe = (EditText)findViewById(R.id.editTextDateOfExpiry);

        mProgressDialog = new ProgressDialog(this);

        // Nfc Adapter init
        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
        mPendingIntent = PendingIntent.getActivity(this, 0, new Intent(this, this.getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);

        // Read card on launch
        if (getIntent().getAction() == NfcAdapter.ACTION_TECH_DISCOVERED) {
            onNewIntent(getIntent());
        }
    }

    void setOutputVisible(boolean visible) {
        if(visible) {
            mBtnCopyToClipboard.setVisibility(Button.VISIBLE);
            mSvOutput.setVisibility(ScrollView.VISIBLE);
            mTvOutput.setVisibility(TextView.VISIBLE);
        }
        else {
            mBtnCopyToClipboard.setVisibility(Button.GONE);
            mSvOutput.setVisibility(ScrollView.GONE);
            mTvOutput.setVisibility(TextView.GONE);
        }
    }

    boolean updateData() {
        mDataToSign = mEditTextDataToSign.getText().toString().getBytes();
        mPassportNumber = mEditTextPassNum.getText().toString();
        mDateOfBirth  = mEditTextDob.getText().toString();
        mDateOfExpiry = mEditTextDoe.getText().toString();

        return true;
    }

    void setOutput(byte[] iccPublicKey, byte[] iccSignature) {
        /* Format: DataToSign, Sha1(DataToSign), iccPublicKey, iccSignature, iccPubKeyExp */
        String output = Utils.hexToStr(mDataToSign) + "," +
                Utils.hexToStr(Utils.sha1(mDataToSign)) + "," +
                Utils.hexToStr(iccPublicKey) + "," +
                Utils.hexToStr(iccSignature)
                 + ""/* missing exponent */ ;

        mTvOutput.setText(output);
        setOutputVisible(!output.isEmpty());
    }

    @Override
    protected void onPause() {
        disableNfc();
        super.onPause();
    }

    @Override
    protected void onResume() {
        if(!enableNfc()){
            finish();
        }

        super.onResume();
    }

    boolean enableNfc() {
        if (mNfcAdapter == null) {
            Journal.warning("No Nfc hardware found!");
            // TODO: report to the calling activity
        }
        else if (!mNfcAdapter.isEnabled()) {
            Journal.warning("Nfc is not enabled");

            AlertDialog.Builder alert = new AlertDialog.Builder(this);
            alert.setTitle("Info");
            alert.setMessage("Nfc is not enabled you will be moved to setting app.");
            alert.setPositiveButton("OK", new DialogInterface.OnClickListener() {
                @Override
                public void onClick(final DialogInterface dialog, final int which) {
                    Intent intent = null;
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
                        intent = new Intent(Settings.ACTION_NFC_SETTINGS);
                    } else {
                        intent = new Intent(Settings.ACTION_WIRELESS_SETTINGS);
                    }
                    dialog.dismiss();
                    startActivity(intent);
                }
            });

            alert.setCancelable(false);
            alert.show();
        } else {
            mNfcAdapter.enableForegroundDispatch(this, mPendingIntent, mIntentFilters, mTechLists);
            return true;
        }

        return false;
    }

    void disableNfc() {
        if (mNfcAdapter != null) {
            mNfcAdapter.enableForegroundDispatch(this, mPendingIntent, mIntentFilters, mTechLists);
        }
    }

    void showToast(final String text) {
        try {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    Toast.makeText(getApplicationContext(), text, Toast.LENGTH_LONG).show();
                }
            });
            Thread.sleep(300);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    void showProgressBar(String text) {
        mProgressDialog.setTitle(text);
        mProgressDialog.show();
    }

    void showProgressBar() {
        showProgressBar("Processing...");
    }

    void hideProgressBar() {
        mProgressDialog.hide();
    }

    @Override
    protected void onNewIntent(final Intent intent) {
        Utils.printDebug(Journal.getName(), "onNewIntent");
        super.onNewIntent(intent);

        if(!updateData()) {
            return;
        }

        showProgressBar("Signing data...");
        final Tag nfcTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        if (nfcTag != null) {
            new Async() {
                private boolean mException;
                private boolean mFinish = false;
                byte[] iccPubKey = null;
                byte[] iccSignature = null;

                @Override
                protected void onPreExecute() {
                    super.onPreExecute();
                }

                @Override
                protected void doInBackground() {

                    IsoDep isoDep = IsoDep.get(nfcTag);
                    if (isoDep == null) {
                        Journal.warning("ePassport was removed from terminal!");
                        return;
                    }

                    try {
                        mException = false;
                        EPassport passport = new EPassport(isoDep);
                        passport.selectApplet();
//                        passport.externalAuthenticate(Utils.deriveKey(Utils.strToHex("239AB9CB282DAF66231DC5A4DF6BFBAE"), Utils.ENC_MODE),
//                                Utils.deriveKey(Utils.strToHex("239AB9CB282DAF66231DC5A4DF6BFBAE"), Utils.MAC_MODE),
//                                Utils.strToHex("4608F91988702212"),
//                                Utils.strToHex("781723860C06C226"),
//                                Utils.strToHex("0B795240CB7049B01C19B33E32804F0B"));

                        if(passport.doBAC(mPassportNumber, mDateOfBirth, mDateOfExpiry)) {
                           iccPubKey = passport.readPublicKey();
                           iccSignature =  passport.signData(Arrays.copyOfRange(Utils.sha1(mDataToSign), 0, 8));

                           if(iccPubKey != null && iccSignature != null) {
                               showToast("Signing data succeed!");
                           }
                           else {
                               showToast("An error occurred while trying to sign data!");
                           }
                        } else {
                            showToast("Auth failed. Check input data!");
                        }
                    }
                    catch (NfcTransmitterError e) {
                        showToast("Reading ePassport via NFC failed!");
                    }
                    catch (EPassportError e) {
                        Journal.severe("An Exception was thrown while trying to read ePassport: " + e.getMessage());
                        mException = true;
                    }
                    catch (InvalidAlgorithmParameterException e) {
                        e.printStackTrace();
                    } finally {
                    }
                }

                @Override
                protected void onPostExecute(final Object result) {
                    if(iccPubKey != null && iccSignature != null) {
                        setOutput(iccPubKey, iccSignature);
                    } else {
                        setOutputVisible(false);
                    }
                    hideProgressBar();
                }

            }.execute();
        }
    }
}