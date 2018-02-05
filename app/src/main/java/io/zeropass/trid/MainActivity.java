/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/

package io.zeropass.trid;

import io.zeropass.trid.com.NfcProvider;
import io.zeropass.trid.crypto.CryptoUtils;
import io.zeropass.trid.crypto.RSA_ISO9796_2_DSS1_SHA1;
import io.zeropass.trid.passport.EPassport;
import io.zeropass.trid.passport.PassportError;
import io.zeropass.trid.tlv.TLVUtils;

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.logging.Logger;

import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
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
import android.view.View;
import android.widget.EditText;
import android.widget.Button;
import android.widget.TextView;
import android.widget.ScrollView;
import android.widget.Toast;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.app.ProgressDialog;

public class MainActivity extends AppCompatActivity {

    private static final Logger Journal = Logger.getLogger("main");
    private Button mBtnCopyToClipboard;
    private TextView mTvOutput;
    private TextView mLabelNfcStatus;
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
        mLabelNfcStatus = (TextView) findViewById(R.id.labelNfcStatus);

        mProgressDialog = new ProgressDialog(this);

        // Nfc Adapter init
        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
        mPendingIntent = PendingIntent.getActivity(this, 0, new Intent(this, this.getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);

        // Read card on launch
        if (getIntent().getAction() == NfcAdapter.ACTION_TECH_DISCOVERED) {
            onNewIntent(getIntent());
        }

        // Clipboard button click event
        mBtnCopyToClipboard.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View view) {
                ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                ClipData clip = ClipData.newPlainText("trdi_output", mTvOutput.getText());
                clipboard.setPrimaryClip(clip);
                showToast("Copied to clipboard");
            }
        });

//
//        PublicKey pubKey = CryptoUtils.getPublicKeyFromBytes(TLVUtils.getValue(Utils.strToHex("6F81A230819F300D06092A864886F70D010101050003818D0030818902818100A13F98038CC80DE9BE94A917B5CFCE74CC4BB1337222E82D83C3FC2CBF5E81F80CBC4475CE2FCB08DBB2CEDAB4B3264DC12961B8166B32D238E5A52B02A271F46165B5EF03AC24C76B85D4B4E5A872925D692E8159B1B2BCFB5D6A2E086A88A78853363BC2A52E9725C668416243C45E921DED173FF970B4D0C5F277D034CCFD0203010001")));
//        byte[] message = Utils.strToHex("AABBCCAABBCC");
//        byte[] signature = Utils.strToHex("22BF2420BE8A18114CA8E3D3AADC44EC0BEC50E42C640882DBFEED068F0AAB75BE69B65130B037F1EBC75EE1448FA3B60B1E70DD9C821D58BDE234B45BDC3F848FF8DD6BB4BB6854E13A940EA038F1FDE7B67C72360AAFB9FED3A4D991973AC9440DB1D7DD6A86B72554A703B47FDDDAA495F514E80549D667E4595DB11801E6");
//
//        mDataToSign = message;
//        setOutput(pubKey, signature);
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

    void setOutput(PublicKey iccPublicKey, byte[] iccSignature) {
        String output = "";
        if(verifySignature(iccPublicKey, iccSignature)) {
            /* Format: DataToSign, Sha1(DataToSign), iccPublicKey, iccSignature, iccPubKeyExp */
            output = String.format("Signed data: %s\n\nData SHA-1: %s\n\nePassport public key:\n    modulo=%s\n    e=%s\n\nSignature: %s",
                    Utils.hexToStr(mDataToSign),
                    Utils.hexToStr(getHashOfDataToSign()),
                    Utils.hexToStr(((RSAPublicKey)iccPublicKey).getModulus().toByteArray()),
                    Utils.hexToStr(((RSAPublicKey)iccPublicKey).getPublicExponent().toByteArray()),
                    Utils.hexToStr(iccSignature));
        }
        else { // Signature verification failed
            AlertDialog.Builder alert = new AlertDialog.Builder(this);
            alert.setTitle("Error");
            alert.setMessage("Failed to verify signature.");
            alert.setPositiveButton("Dismiss", new DialogInterface.OnClickListener() {
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

            alert.show();
        }

        mTvOutput.setText(output);
        setOutputVisible(!output.isEmpty());
    }

    private byte[] getHashOfDataToSign() {
        return CryptoUtils.sha1(mDataToSign);
    }

    private byte[] getHashChunkOfDataToSign() {
        return Utils.copyOut(getHashOfDataToSign(), 0, 8);
    }

    private boolean verifySignature(PublicKey iccPublicKey, byte[] iccSignature) {
        String pubKeyAlgorithm = iccPublicKey.getAlgorithm();
        boolean isValid = false;
        if("EC".equals(pubKeyAlgorithm) || "ECDSA".equals(pubKeyAlgorithm)) {
            // TODO: verify ECDSA signature
            Journal.warning("Cannot verify ECDSA signature!");
        }
        else if("RSA".equals(pubKeyAlgorithm)) {
            byte[] dataToSign = getHashOfDataToSign();
            isValid = RSA_ISO9796_2_DSS1_SHA1.verifySignature((RSAPublicKey) iccPublicKey, getHashChunkOfDataToSign(), iccSignature);
            if(!isValid) {
                Journal.warning("RSA signature verification failed!");
            }
        }
        else {
            Journal.warning("Could not verify signature, unknown PKI algorithm!");
        }

        return isValid;
    }

    @Override
    protected void onPause() {
        disableNfc();
        super.onPause();
    }

    @Override
    protected void onResume() {
        if(!enableNfc()){
            //finish();
            AlertDialog.Builder alert = new AlertDialog.Builder(this);
            if(mNfcAdapter == null) {
                mLabelNfcStatus.setText(R.string.nfc_not_found);

                alert.setTitle("Error");
                alert.setMessage("No NFC adapter found. The app will now exit!");
                alert.setPositiveButton("Exit", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(final DialogInterface dialog, final int which) {
                        MainActivity.this.finish();
                    }
                });
            } else if(!mNfcAdapter.isEnabled()) {
                mLabelNfcStatus.setText(R.string.nfc_disabled);

                alert.setTitle("Info");
                alert.setMessage("NFC Adapter is not enabled you will be moved to settings app.");
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
            }
            else {
                mLabelNfcStatus.setText(R.string.nfc_enabled);
            }

            alert.setCancelable(false);
            alert.show();
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
                PublicKey iccPubKey = null;
                byte[] iccSignature = null;

                @Override
                protected void onPreExecute() {
                    super.onPreExecute();
                }

                @Override
                protected void doInBackground() {

                    IsoDep isoDep = IsoDep.get(nfcTag);
                    if (isoDep == null) {
                        Journal.warning("ICC was removed from terminal!");
                        showToast("ePassport was removed !");
                        return;
                    }

                    try {
                        mException = false;
                        EPassport passport = new EPassport(new NfcProvider(isoDep));
                        passport.selectEMRTD();

                        if(passport.doBAC(mPassportNumber, mDateOfBirth, mDateOfExpiry)) {
                           iccPubKey = passport.readPublicKey();
                           iccSignature =  passport.internalAuthenticate(getHashChunkOfDataToSign());

                           Journal.info("ICC Public key: " + Utils.hexToStr(iccPubKey.getEncoded()));
                           Journal.info("ICC Signature: " + Utils.hexToStr(iccSignature));
                           if(iccPubKey != null && iccSignature != null) {
                               showToast("Signing data succeed!");
                           }
                           else {
                               showToast("An error occurred while trying to sign data!");
                           }
                        } else {
                            showToast("ePassport auth failed. Check input data!");
                        }
                    }
                    catch (PassportError | IOException e) {
                        showToast("Signing data via ePassport failed!");
                        Journal.severe("An Exception was thrown while trying to read ePassport: " + e.getMessage());
                        mException = true;
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