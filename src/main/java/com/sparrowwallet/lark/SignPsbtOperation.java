package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.psbt.PSBT;

public class SignPsbtOperation extends AbstractClientOperation {
    private final PSBT psbt;
    private PSBT signedPsbt;

    public SignPsbtOperation(String deviceType, PSBT psbt) {
        super(deviceType);
        this.psbt = psbt;
    }

    public SignPsbtOperation(String deviceType, String devicePath, PSBT psbt) {
        super(deviceType, devicePath);
        this.psbt = psbt;
    }

    public SignPsbtOperation(byte[] fingerprint, PSBT psbt) {
        super(fingerprint);
        this.psbt = psbt;
    }

    @Override
    public void apply(HardwareClient hardwareClient) throws DeviceException {
        // Anti-exfil hook (Option 1 - launch flag). When -Dsparrow.antiexfil=true
        // is set and the device is a Jade, route signing through the two-round
        // sign-to-contract exchange with host-side verification instead of the
        // normal single-shot sign. Any other device, or flag unset, is unchanged.
        boolean antiExfil = Boolean.getBoolean("sparrow.antiexfil");
        if(antiExfil && hardwareClient instanceof JadeClient jadeClient) {
            signedPsbt = jadeClient.signTransactionAntiExfil(psbt);
        } else {
            signedPsbt = hardwareClient.signTransaction(psbt);
        }
    }

    public PSBT getPsbt() {
        return signedPsbt;
    }

    @Override
    public boolean success() {
        return signedPsbt != null;
    }
}
