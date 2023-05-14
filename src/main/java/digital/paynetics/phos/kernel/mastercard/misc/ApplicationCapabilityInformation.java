package digital.paynetics.phos.kernel.mastercard.misc;

import java.math.BigInteger;


public class ApplicationCapabilityInformation {
    private final boolean supportForFieldOffDetection;
    private final boolean supportBalanceReading;
    private final CdaIndicator cdaIndicator;
    private final boolean dataStorageVersion1;
    private final boolean dataStorageVersion2;


    public ApplicationCapabilityInformation(boolean supportForFieldOffDetection,
                                            boolean supportBalanceReading,
                                            CdaIndicator cdaIndicator,
                                            boolean dataStorageVersion1,
                                            boolean dataStorageVersion2) {

        this.supportForFieldOffDetection = supportForFieldOffDetection;
        this.supportBalanceReading = supportBalanceReading;
        this.cdaIndicator = cdaIndicator;
        this.dataStorageVersion1 = dataStorageVersion1;
        this.dataStorageVersion2 = dataStorageVersion2;
    }


    public static ApplicationCapabilityInformation fromBytes(byte[] data) {
        if (data.length != 3) {
            throw new IllegalArgumentException("Invalid data length");
        }

        BigInteger bi2 = BigInteger.valueOf(data[1]);

        @SuppressWarnings("PointlessArithmeticExpression")
        CdaIndicator cdaIndicator = bi2.testBit(1 - 1) ? CdaIndicator.CDA_OVER_TC_ARQC_AAC : CdaIndicator.CDA_AS_IN_EMV;
        boolean supportForFieldOffDetection = bi2.testBit(3 - 1);
        boolean supportBalanceReading = bi2.testBit(2 - 1);

        boolean dataStorageVersion1 = false;
        boolean dataStorageVersion2 = false;
        byte tmp = (byte) (data[0] & 0b00000011);
        if (tmp == 0b00000010) {
            dataStorageVersion2 = true;
        } else if (tmp == 0b00000001) {
            dataStorageVersion1 = true;
        }


        return new ApplicationCapabilityInformation(supportForFieldOffDetection,
                supportBalanceReading,
                cdaIndicator,
                dataStorageVersion1,
                dataStorageVersion2);
    }


    public CdaIndicator getCdaIndicator() {
        return cdaIndicator;
    }


    public enum CdaIndicator {
        CDA_AS_IN_EMV,
        CDA_OVER_TC_ARQC_AAC
    }


    public boolean isSupportForFieldOffDetection() {
        return supportForFieldOffDetection;
    }


    public boolean isSupportBalanceReading() {
        return supportBalanceReading;
    }


    public boolean isDataStorageVersion1() {
        return dataStorageVersion1;
    }


    public boolean isDataStorageVersion2() {
        return dataStorageVersion2;
    }
}
