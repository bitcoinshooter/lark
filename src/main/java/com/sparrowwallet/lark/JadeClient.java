package com.sparrowwallet.lark;

import com.fazecast.jSerialComm.SerialPort;
import com.sparrowwallet.drongo.*;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTParseException;
import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.lark.jade.JadeDevice;
import com.sparrowwallet.lark.jade.JadeVersion;
import com.sparrowwallet.tern.http.client.HttpClientService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class JadeClient extends HardwareClient {
    private static final Logger log = LoggerFactory.getLogger(JadeClient.class);

    public static final List<DeviceId> JADE_DEVICE_IDS = List.of(new DeviceId(0x10c4, 0xea60),
            new DeviceId(0x1a86, 0x55d4), new DeviceId(0x0403, 0x6001), new DeviceId(0x1a86, 0x7523),
            new DeviceId(0x303a, 0x4001), new DeviceId(0x303a, 0x1001));
    private static final Version MIN_SUPPORTED_VERSION = new Version("0.1.47");
    private static final int MAX_WALLET_NAME_LENGTH = 15;
    private static final int MAX_AUTH_ATTEMPTS = 3;

    private final SerialPort serialPort;
    private final HttpClientService httpClientService;
    private String masterFingerprint;

    public JadeClient(SerialPort serialPort, HttpClientService httpClientService) throws DeviceException {
        if(JADE_DEVICE_IDS.stream().anyMatch(deviceId -> deviceId.matches(serialPort))) {
            this.serialPort = serialPort;
            this.httpClientService = httpClientService;
        } else {
            throw new DeviceException("Not a Jade");
        }
    }

    @Override
    void initializeMasterFingerprint() throws DeviceException {
        try(JadeDevice jadeDevice = new JadeDevice(serialPort, httpClientService)) {
            initialize(jadeDevice);
            this.masterFingerprint = Utils.bytesToHex(jadeDevice.getXpub(Network.getCanonical(), "m/0h").getParentFingerprint());
        }
    }

    @Override
    ExtendedKey getPubKeyAtPath(String path) throws DeviceException {
        try(JadeDevice jadeDevice = new JadeDevice(serialPort, httpClientService)) {
            initialize(jadeDevice);
            return jadeDevice.getXpub(Network.getCanonical(), path);
        }
    }

    @Override
    PSBT signTransaction(PSBT psbt) throws DeviceException {
        try(JadeDevice jadeDevice = new JadeDevice(serialPort, httpClientService)) {
            initialize(jadeDevice);

            try {
                OutputDescriptor outputDescriptor = getOutputDescriptor(psbt);
                if(outputDescriptor != null && outputDescriptor.isMultisig()) {
                    String name = getWalletNameOrDefault(outputDescriptor);
                    jadeDevice.registerMultisig(Network.getCanonical(), name, outputDescriptor);
                }
            } catch(DeviceException e) {
                log.warn("Could not register wallet: " + e.getMessage());
            } catch(RuntimeException e) {
                log.error("Error registering wallet", e);
            }

            byte[] psbtBytes = psbt.getForExport().serialize();
            byte[] signedPsbtBytes = jadeDevice.signTransaction(Network.getCanonical(), psbtBytes);
            return new PSBT(signedPsbtBytes);
        } catch(PSBTParseException e) {
            throw new DeviceException("Invalid signed PSBT", e);
        }
    }

    /**
     * Anti-exfil signing over USB. Drives the two-round sign-to-contract
     * exchange with the Jade via AntiExfilSession, calling the existing
     * signTransaction transport once per round, and verifies every signature
     * incorporates our host entropy before returning.
     *
     * Throws DeviceException (wrapping SecurityException) if verification
     * fails on any input - the caller MUST NOT broadcast in that case.
     */
    PSBT signTransactionAntiExfil(PSBT psbt) throws DeviceException {
        try(JadeDevice jadeDevice = new JadeDevice(serialPort, httpClientService)) {
            initialize(jadeDevice);

            try {
                OutputDescriptor outputDescriptor = getOutputDescriptor(psbt);
                if(outputDescriptor != null && outputDescriptor.isMultisig()) {
                    String name = getWalletNameOrDefault(outputDescriptor);
                    jadeDevice.registerMultisig(Network.getCanonical(), name, outputDescriptor);
                }
            } catch(DeviceException e) {
                log.warn("Could not register wallet: " + e.getMessage());
            } catch(RuntimeException e) {
                log.error("Error registering wallet", e);
            }

            // Build the per-input map of THIS device's signing pubkeys, keyed by
            // input index, from the PSBT's bip32 derivations filtered to our
            // master fingerprint.
            Map<Integer, List<byte[]>> signersByInput = new LinkedHashMap<>();
            List<PSBTInput> inputs = psbt.getPsbtInputs();
            for(int i = 0; i < inputs.size(); i++) {
                PSBTInput input = inputs.get(i);
                List<byte[]> signers = new ArrayList<>();
                for(Map.Entry<ECKey, KeyDerivation> e : input.getDerivedPublicKeys().entrySet()) {
                    String fp = e.getValue() == null ? null : e.getValue().getMasterFingerprint();
                    if(fp != null && fp.equalsIgnoreCase(masterFingerprint)) {
                        signers.add(e.getKey().getPubKey());
                    }
                }
                if(!signers.isEmpty()) {
                    signersByInput.put(i, signers);
                }
            }

            if(signersByInput.isEmpty()) {
                throw new DeviceException("No inputs for this device to anti-exfil sign");
            }

            byte[] psbtBytes = psbt.getForExport().serialize();
            AntiExfilSession session = new AntiExfilSession(psbtBytes, signersByInput);

            // Round 1: host commitments -> Jade returns signer commitments
            byte[] round1 = session.buildRound1();
            byte[] reply1 = jadeDevice.signTransaction(Network.getCanonical(), round1);
            session.acceptRound1Reply(reply1);

            // Round 2: reveal entropy -> Jade signs
            byte[] round2 = session.buildRound2();
            byte[] reply2 = jadeDevice.signTransaction(Network.getCanonical(), round2);

            // Verify every signature incorporated our entropy - throws on failure
            PSBT verified = session.verifyAndExtract(reply2);
            return verified;
        } catch(PSBTParseException e) {
            throw new DeviceException("Invalid signed PSBT", e);
        } catch(SecurityException e) {
            throw new DeviceException("Anti-exfil verification FAILED: " + e.getMessage(), e);
        } catch(Exception e) {
            throw new DeviceException("Anti-exfil signing error: " + e.getMessage(), e);
        }
    }

    @Override
    String signMessage(String message, String path) throws DeviceException {
        try(JadeDevice jadeDevice = new JadeDevice(serialPort, httpClientService)) {
            initialize(jadeDevice);
            return jadeDevice.signMessage(message, path);
        }
    }

    @Override
    String displaySinglesigAddress(String path, ScriptType scriptType) throws DeviceException {
        try(JadeDevice jadeDevice = new JadeDevice(serialPort, httpClientService)) {
            initialize(jadeDevice);
            return jadeDevice.displaySinglesigAddress(Network.getCanonical(), path, scriptType);
        }
    }

    @Override
    String displayMultisigAddress(OutputDescriptor outputDescriptor) throws DeviceException {
        try(JadeDevice jadeDevice = new JadeDevice(serialPort, httpClientService)) {
            initialize(jadeDevice);
            String name = getWalletNameOrDefault(outputDescriptor);
            jadeDevice.registerMultisig(Network.getCanonical(), name, outputDescriptor);
            return jadeDevice.displayMultisigAddress(Network.getCanonical(), name, outputDescriptor);
        }
    }

    @Override
    protected String getWalletNameOrDefault(OutputDescriptor outputDescriptor) {
        String name = super.getWalletNameOrDefault(outputDescriptor).trim().replaceAll("[^\\x21-\\x7E]", "_");
        if(name.isEmpty()) {
            name = "Wallet";
        } else if(name.length() > MAX_WALLET_NAME_LENGTH) {
            name = name.substring(0, MAX_WALLET_NAME_LENGTH);
        }

        return name;
    }

    private void initialize(JadeDevice jadeDevice) throws DeviceException {
        JadeVersion jadeVersion = jadeDevice.getVersionInfo();
        if(jadeVersion == null || jadeVersion.JADE_VERSION() == null) {
            throw new DeviceException("Not a Jade: no version info returned");
        }
        // JADE_VERSION arrives as a raw string. Release firmware reports semver
        // (e.g. "1.0.34"); self-built/debug firmware may report a git hash like
        // "b54ca0be-dirty" which is not a parseable Version. Tolerate the latter:
        // treat an unparseable version as a dev build and skip the min-version
        // check rather than failing to connect.
        try {
            Version fwVersion = new Version(jadeVersion.JADE_VERSION());
            if(fwVersion.compareTo(MIN_SUPPORTED_VERSION) < 0) {
                throw new DeviceException("Jade fw version: " + jadeVersion.JADE_VERSION() + " < minimum required version: " + MIN_SUPPORTED_VERSION);
            }
        } catch(IllegalArgumentException e) {
            log.warn("Jade reported non-semver version '" + jadeVersion.JADE_VERSION() + "' - treating as dev build, skipping min-version check");
        }

        jadeDevice.addEntropy();

        boolean authenticated = false;
        for(int i = 0; i < MAX_AUTH_ATTEMPTS && !authenticated; i++) {
            authenticated = jadeDevice.authUser(Network.getCanonical());
        }

        if(!authenticated) {
            throw new DeviceException("Could not authenticate Jade device");
        }
    }

    @Override
    public String getPath() {
        return serialPort.getSystemPortPath();
    }

    @Override
    public HardwareType getHardwareType() {
        return HardwareType.JADE;
    }

    @Override
    public WalletModel getModel() {
        return WalletModel.JADE;
    }

    @Override
    public Boolean needsPinSent() {
        return null;
    }

    @Override
    public Boolean needsPassphraseSent() {
        return null;
    }

    @Override
    public String fingerprint() {
        return masterFingerprint;
    }

    @Override
    public boolean card() {
        return false;
    }

    @Override
    public String[][] warnings() {
        return new String[0][];
    }

    @Override
    public final boolean equals(Object o) {
        if(this == o) {
            return true;
        }
        if(!(o instanceof JadeClient that)) {
            return false;
        }

        return getModel().equals(that.getModel());
    }

    @Override
    public int hashCode() {
        return getModel().hashCode();
    }
}
