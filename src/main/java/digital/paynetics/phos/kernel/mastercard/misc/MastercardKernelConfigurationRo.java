package digital.paynetics.phos.kernel.mastercard.misc;

public interface MastercardKernelConfigurationRo {
    int getReaderContactlessFloorLimit();

    int getReaderContactlessTransactionLimitNoOnDeviceCvm();

    int getReaderContactlessTransactionLimitOnDeviceCvm();

    int getReaderCvmRequiredLimit();

    int getReaderContactlessTransactionLimit();
}
