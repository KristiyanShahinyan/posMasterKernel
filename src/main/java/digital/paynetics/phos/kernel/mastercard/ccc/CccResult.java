package digital.paynetics.phos.kernel.mastercard.ccc;

import digital.paynetics.phos.kernel.common.emv.Outcome;


public class CccResult {
    private final boolean isOk;
    private final Outcome outcome;


    private CccResult(boolean isOk, Outcome outcome) {

        this.isOk = isOk;
        this.outcome = outcome;
    }


    public static CccResult createOkResult(Outcome outcome) {

        return new CccResult(true, outcome);
    }


    public static CccResult createFailResult(Outcome outcome) {
        return new CccResult(false, outcome);
    }


    public boolean isOk() {
        return isOk;
    }


    public Outcome getOutcome() {
        return outcome;
    }

}
