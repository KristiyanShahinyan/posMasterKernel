package digital.paynetics.phos.kernel.mastercard.misc;

import digital.paynetics.phos.kernel.common.emv.Outcome;


public enum MagstripeCvmCapability {
    NO_CVM((byte) 0),
    OBTAIN_SIGNATURE((byte) 1),
    ONLINE_PIN((byte) 2),
    NOT_APPLICABLE((byte) 0xf0);


    private final byte code;


    MagstripeCvmCapability(byte code) {
        this.code = code;
    }


    public static MagstripeCvmCapability fromByte(byte b) {
        b &= 0b11110000;
        switch (b) {
            case 0:
                return NO_CVM;
            case 0b00010000:
                return OBTAIN_SIGNATURE;
            case 0b00100000:
                return ONLINE_PIN;
            case (byte) 0b11110000:
                return NOT_APPLICABLE;
            default:
                throw new IllegalArgumentException("Invalid value for CVM capability: " + b);
        }
    }


    public static Outcome.Cvm toOutcomeCvm(MagstripeCvmCapability c) {
        switch (c) {
            case NO_CVM:
                return Outcome.Cvm.NO_CVM;
            case OBTAIN_SIGNATURE:
                return Outcome.Cvm.OBTAIN_SIGNATURE;
            case ONLINE_PIN:
                return Outcome.Cvm.ONLINE_PIN;
            case NOT_APPLICABLE:
                return Outcome.Cvm.NOT_APPLICABLE;
            default:
                throw new AssertionError("Cannot happen");
        }
    }


    public byte getCode() {
        return code;
    }
}
