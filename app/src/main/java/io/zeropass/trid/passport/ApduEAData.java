package io.zeropass.trid.passport;

import java.security.InvalidParameterException;

import javax.crypto.SecretKey;

import io.zeropass.trid.Utils;

/* Data for apdu command External authenticate */
public class ApduEAData {
    public static final int E_LEN = 32;

    public final byte[] E; // E.IFD or E.IC
    public final byte[] M; // M.IFD or M.IC

    public ApduEAData(byte[] E, byte[] M) {
        if(E.length != E_LEN || M.length != PassportTools.MAC_LEN) {
            throw new InvalidParameterException("Invalid E or M len");
        }

        this.E = E;
        this.M = M;
    }

    public ApduEAData(SecretKey mKey, byte[] E) {
        if(E.length != E_LEN) {
            throw new InvalidParameterException("Invalid E len");
        }

        this.E = E;
        this.M = PassportTools.mac(mKey, E);
    }

    public ApduEAData(byte[] rawData) {
        if(rawData.length < (E_LEN + PassportTools.MAC_LEN)) {
            throw new InvalidParameterException("EAData rawData len < 40");
        }

        this.E = Utils.copyOut(rawData, 0, E_LEN);
        this.M = Utils.copyOut(rawData, E_LEN, PassportTools.MAC_LEN);
    }

    public boolean verify(SecretKey mKey) {
        return Utils.memcmp(PassportTools.mac(mKey, E), M);
    }

    public byte[] decrypt(SecretKey decKey) {
        return PassportTools.decrypt(decKey, E);
    }

    /* Serialize as E | M */
    public byte[] toBytes() {
        return Utils.join(E, M);
    }
}
