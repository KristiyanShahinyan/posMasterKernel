package digital.paynetics.phos.kernel.mastercard.misc;

import java.math.BigInteger;


public class DsOdsInfoForReader {
    private final boolean isUsableForTc;
    private final boolean isUsableForArqc;
    private final boolean isUsableForAac;
    private final boolean isStopIfNoOdsTerm;
    private final boolean isStopIfWriteFailed;


    public DsOdsInfoForReader(boolean isUsableForTc, boolean isUsableForArqc, boolean isUsableForAac, boolean isStopIfNoOdsTerm, boolean isStopIfWriteFailed) {
        this.isUsableForTc = isUsableForTc;
        this.isUsableForArqc = isUsableForArqc;
        this.isUsableForAac = isUsableForAac;
        this.isStopIfNoOdsTerm = isStopIfNoOdsTerm;
        this.isStopIfWriteFailed = isStopIfWriteFailed;
    }


    public static DsOdsInfoForReader fromByte(byte b) {
        BigInteger bi = BigInteger.valueOf(b);

        boolean isUsableForTc = bi.testBit(8 - 1);
        boolean isUsableForArqc = bi.testBit(7 - 1);
        boolean isUsableForAac = bi.testBit(6 - 1);
        boolean isStopIfNoOdsTerm = bi.testBit(3 - 1);
        boolean isStopIfWriteFailed = bi.testBit(2 - 1);

        return new DsOdsInfoForReader(isUsableForTc, isUsableForArqc, isUsableForAac, isStopIfNoOdsTerm, isStopIfWriteFailed);
    }


    public boolean isUsableForTc() {
        return isUsableForTc;
    }


    public boolean isUsableForArqc() {
        return isUsableForArqc;
    }


    public boolean isUsableForAac() {
        return isUsableForAac;
    }


    public boolean isStopIfNoOdsTerm() {
        return isStopIfNoOdsTerm;
    }


    public boolean isStopIfWriteFailed() {
        return isStopIfWriteFailed;
    }

}
