package digital.paynetics.phos.kernel.mastercard.misc;

import java.math.BigInteger;


public class DsSlotManagementControl {
    private final boolean isPermanentSlotType;
    private final boolean isVolatileSlotType;
    private final boolean isLowVolatility;
    private final boolean isLockedSlot;
    private final boolean isDeactivatedSlot;


    public DsSlotManagementControl(boolean isPermanentSlotType,
                                   boolean isVolatileSlotType,
                                   boolean isLowVolatility,
                                   boolean isLockedSlot,
                                   boolean isDeactivatedSlot) {

        this.isPermanentSlotType = isPermanentSlotType;
        this.isVolatileSlotType = isVolatileSlotType;
        this.isLowVolatility = isLowVolatility;
        this.isLockedSlot = isLockedSlot;
        this.isDeactivatedSlot = isDeactivatedSlot;
    }


    public static DsSlotManagementControl fromByte(byte b) {
        BigInteger bi = BigInteger.valueOf(b);

        boolean isPermanentSlotType = bi.testBit(8 - 1);
        boolean isVolatileSlotType = bi.testBit(7 - 1);
        boolean isLowVolatility = bi.testBit(6 - 1);
        boolean isLockedSlot = bi.testBit(5 - 1);
        boolean isDeactivatedSlot = bi.testBit(1 - 1);

        return new DsSlotManagementControl(isPermanentSlotType, isVolatileSlotType, isLowVolatility, isLockedSlot, isDeactivatedSlot);
    }


    public boolean isPermanentSlotType() {
        return isPermanentSlotType;
    }


    public boolean isVolatileSlotType() {
        return isVolatileSlotType;
    }


    public boolean isLowVolatility() {
        return isLowVolatility;
    }


    public boolean isLockedSlot() {
        return isLockedSlot;
    }


    public boolean isDeactivatedSlot() {
        return isDeactivatedSlot;
    }
}
