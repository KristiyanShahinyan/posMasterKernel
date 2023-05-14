package digital.paynetics.phos.kernel.mastercard.misc;

public final class MastercardAdditionalTerminalCapabilities {
    private final boolean cash;


    public MastercardAdditionalTerminalCapabilities(boolean cash) {
        this.cash = cash;
    }


    public boolean isCash() {
        return cash;
    }
}
