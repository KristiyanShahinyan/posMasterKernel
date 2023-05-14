package digital.paynetics.phos.kernel.mastercard.misc;

@SuppressWarnings("FieldCanBeLocal")
public class MastercardKernelConfiguration {
    private final MastercardAdditionalTerminalCapabilities mastercardAdditionalTerminalCapabilities =
            new MastercardAdditionalTerminalCapabilities(true);

    private final boolean idsSupported = false;
    private final boolean emvModeNotSupported;
    private final boolean magstripeModeNotSupported;
    private final boolean balanceReadingSupported = false;
    private final boolean tornTransactionRecoverySupported = false;
    private final boolean deviceCvmSupported;
    private final boolean relayResistanceSupported;
    //    private final byte[] terminalActionCodeDefault = {(byte) 0x84, 0x00, 0x00, 0x00, 0x0c};
    private final byte[] terminalActionCodeDefault;
    private final byte[] terminalActionCodeDenial;
    private final byte[] terminalActionCodeOnline;


    public MastercardKernelConfiguration(boolean emvModeNotSupported, boolean magstripeModeNotSupported, boolean deviceCvmSupported,
                                         boolean relayResistanceSupported, byte[] terminalActionCodeDefault,
                                         byte[] terminalActionCodeDenial, byte[] terminalActionCodeOnline) {

        this.emvModeNotSupported = emvModeNotSupported;
        this.magstripeModeNotSupported = magstripeModeNotSupported;
        this.deviceCvmSupported = deviceCvmSupported;
        this.relayResistanceSupported = relayResistanceSupported;
        this.terminalActionCodeDefault = terminalActionCodeDefault;
        this.terminalActionCodeDenial = terminalActionCodeDenial;
        this.terminalActionCodeOnline = terminalActionCodeOnline;
    }


    public MastercardAdditionalTerminalCapabilities getMastercardAdditionalTerminalCapabilities() {
        return mastercardAdditionalTerminalCapabilities;
    }


    public boolean isIdsSupported() {
        return idsSupported;
    }


    public boolean isEmvModeNotSupported() {
        return emvModeNotSupported;
    }


    public boolean isMagstripeModeNotSupported() {
        return magstripeModeNotSupported;
    }


    public boolean isBalanceReadingSupported() {
        return balanceReadingSupported;
    }


    public boolean isTornTransactionRecoverySupported() {
        return tornTransactionRecoverySupported;
    }


    public boolean isDeviceCvmSupported() {
        return deviceCvmSupported;
    }


    public boolean isRelayResistanceSupported() {
        return relayResistanceSupported;
    }


    public byte[] getTerminalActionCodeDenial() {
        return terminalActionCodeDenial;
    }


    public byte[] getTerminalActionCodeDefault() {
        return terminalActionCodeDefault;
    }


    public byte[] getTerminalActionCodeOnline() {
        return terminalActionCodeOnline;
    }
}
