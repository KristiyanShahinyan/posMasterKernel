package digital.paynetics.phos.kernel.mastercard.rrp;

import java.io.IOException;

import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;
import digital.paynetics.phos.kernel.mastercard.misc.TlvDb;


public interface Rrp {
    static RrpResult createOkResult(boolean relayResistanceTimeLimitsExceeded,
                                    boolean relayResistanceThresholdExceeded,
                                    int measuredProcessingTime,
                                    int rrpCounter
    ) {

        return new RrpResult(true, null,
                relayResistanceTimeLimitsExceeded, relayResistanceThresholdExceeded, measuredProcessingTime, rrpCounter, null);
    }

    static RrpResult createFailResult(RrpResult.ErrorType error, byte[] sw) {
        return new RrpResult(false, error, false, false, 0, 0, sw);
    }

    RrpResult process(Transceiver transceiver, TlvDb tlvDb) throws IOException;


    class RrpResult {
        private final boolean isOk;
        private final ErrorType errorType;
        private final boolean relayResistanceTimeLimitsExceeded;
        private final boolean relayResistanceThresholdExceeded;
        private final int measuredProcessingTime;
        private final int rrpCounter;
        private final byte[] sw;


        protected RrpResult(boolean isOk,
                            ErrorType error,
                            boolean relayResistanceTimeLimitsExceeded,
                            boolean relayResistanceThresholdExceeded,
                            int measuredProcessingTime,
                            int rrpCounter,
                            byte[] sw) {

            this.relayResistanceTimeLimitsExceeded = relayResistanceTimeLimitsExceeded;
            this.relayResistanceThresholdExceeded = relayResistanceThresholdExceeded;
            this.measuredProcessingTime = measuredProcessingTime;
            this.rrpCounter = rrpCounter;
            this.sw = sw;
            if (isOk && error != null) {
                throw new IllegalArgumentException("when isOk == true, error must be null");
            }
            this.isOk = isOk;
            this.errorType = error;
        }


        public boolean isOk() {
            return isOk;
        }


        public ErrorType getErrorType() {
            return errorType;
        }


        public boolean isRelayResistanceTimeLimitsExceeded() {
            return relayResistanceTimeLimitsExceeded;
        }


        public boolean isRelayResistanceThresholdExceeded() {
            return relayResistanceThresholdExceeded;
        }


        public int getMeasuredProcessingTime() {
            return measuredProcessingTime;
        }


        public int getRrpCounter() {
            return rrpCounter;
        }


        public byte[] getSw() {
            return sw;
        }


        public enum ErrorType {
            PARSE_ERROR,
            TRY_ANOTHER_CARD_ERROR
        }
    }
}
