package digital.paynetics.phos.kernel.mastercard.misc;

import java.math.BigInteger;

import digital.paynetics.phos.kernel.common.emv.TerminalVerificationResults;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;


public final class TvrUtil {
    private TvrUtil() {
        throw new AssertionError("Non-instantiable utility class");
    }


    public static TerminalVerificationResults fromBytes(byte[] bytes) {
        TerminalVerificationResults ret = new TerminalVerificationResults();

        BigInteger bi0 = BigInteger.valueOf(bytes[0]);
        if (bi0.testBit(8 - 1)) {
            ret.setOfflineDataAuthenticationNotPerformed(true);
        }

        if (bi0.testBit(7 - 1)) {
            ret.setSdaFailed(true);
        }

        if (bi0.testBit(6 - 1)) {
            ret.setIccDataMissing(true);
        }

        if (bi0.testBit(5 - 1)) {
            ret.setCardOnTerminalExceptionFile(true);
        }

        if (bi0.testBit(4 - 1)) {
            ret.setDdaFailed(true);
        }

        if (bi0.testBit(3 - 1)) {
            ret.setCdaFailed(true);
        }


        BigInteger bi1 = BigInteger.valueOf(bytes[1]);
        if (bi1.testBit(8 - 1)) {
            ret.setIccAndTerminalAppDifferentVersions(true);
        }

        if (bi1.testBit(7 - 1)) {
            ret.setExpiredApplication(true);
        }

        if (bi1.testBit(6 - 1)) {
            ret.setApplicationNotYetEffective(true);
        }

        if (bi1.testBit(5 - 1)) {
            ret.setRequestedServiceNotAllowed(true);
        }

        if (bi1.testBit(4 - 1)) {
            ret.setNewCard(true);
        }


        BigInteger bi2 = BigInteger.valueOf(bytes[2]);
        if (bi2.testBit(8 - 1)) {
            ret.setCvmNotSuccessful(true);
        }

        if (bi2.testBit(7 - 1)) {
            ret.setUnrecognizedCvm(true);
        }

        if (bi2.testBit(6 - 1)) {
            ret.setPinTryLimitExceeded(true);
        }

        if (bi2.testBit(5 - 1)) {
            ret.setPinPadNotPresentOrWorking(true);
        }

        if (bi2.testBit(4 - 1)) {
            ret.setPinNotEntered(true);
        }

        if (bi2.testBit(3 - 1)) {
            ret.setOnlinePinEntered(true);
        }


        BigInteger bi3 = BigInteger.valueOf(bytes[3]);
        if (bi3.testBit(8 - 1)) {
            ret.setTransactionExceedsFloorLimit(true);
        }

        if (bi3.testBit(7 - 1)) {
            ret.setLowerConsecutiveOfflineLimitExceeded(true);
        }

        if (bi3.testBit(6 - 1)) {
            ret.setUpperConsecutiveOfflineLimitExceeded(true);
        }

        if (bi3.testBit(5 - 1)) {
            ret.setTransactionSelectedRandomlyForOnlineProcessing(true);
        }

        if (bi3.testBit(4 - 1)) {
            ret.setMerchantForcedTransactionOnline(true);
        }


        BigInteger bi4 = BigInteger.valueOf(bytes[4]);
        if (bi4.testBit(8 - 1)) {
            ret.setDefaultTdolUsed(true);
        }

        if (bi4.testBit(7 - 1)) {
            ret.setIssuerAuthenticationFailed(true);
        }

        if (bi4.testBit(6 - 1)) {
            ret.setScriptProcessingFailedBeforeFinalGenerateAc(true);
        }

        if (bi4.testBit(5 - 1)) {
            ret.setScriptProcessingFailedAfterFinalGenerateAc(true);
        }

        if (bi4.testBit(4 - 1)) {
            ret.setRelayResistanceThresholdExceeded(true);
        }

        if (bi3.testBit(3 - 1)) {
            ret.setRelayResistanceTimeLimitsExceeded(true);
        }

        if (bi3.testBit(2 - 1)) {
            ret.setRelayResistancePerformed(TerminalVerificationResults.RelayResistancePerformed.PERFORMED);
        }

        if (bi3.testBit(1 - 1)) {
            ret.setRelayResistancePerformed(TerminalVerificationResults.RelayResistancePerformed.NOT_PERFORMED);
        }


        return ret;
    }


    public static Tlv asTlv(TerminalVerificationResults t) {
        byte[] data = t.toBytes();
        return new Tlv(EmvTag.TERMINAL_VERIFICATION_RESULTS, data.length, data);
    }

}
