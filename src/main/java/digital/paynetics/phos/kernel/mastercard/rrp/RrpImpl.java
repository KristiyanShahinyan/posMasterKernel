package digital.paynetics.phos.kernel.mastercard.rrp;

import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;

import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;
import digital.paynetics.phos.kernel.common.emv.tag.TlvUtils;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import digital.paynetics.phos.kernel.common.misc.RandomGenerator;
import digital.paynetics.phos.kernel.common.misc.TimeProvider;
import digital.paynetics.phos.kernel.common.nfc.ApduCommand;
import digital.paynetics.phos.kernel.common.nfc.ApduCommandPackage;
import digital.paynetics.phos.kernel.common.nfc.ApduResponsePackage;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;
import digital.paynetics.phos.kernel.mastercard.misc.TlvDb;


public class RrpImpl implements Rrp {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());

    private final RandomGenerator randomGenerator;
    private final TimeProvider timeProvider;


    @Inject
    public RrpImpl(@Named("RandomGenerator for RRP") RandomGenerator randomGenerator,
                   TimeProvider timeProvider) {

        this.randomGenerator = randomGenerator;
        this.timeProvider = timeProvider;
    }


    @Override
    public RrpResult process(Transceiver transceiver, TlvDb tlvDb) throws IOException {
        int rrpCounter = -1; // we use do-while so we need to offset it with 1 to -1

        double measuredRelayResistanceProcessingTime;
        int minTimeForProcessingRelayResistanceApdu;
        int maxTimeForProcessingRelayResistanceApdu;
        int deviceEstimatedTransmissionTimeForRelayResistanceRadpu;
        int terminalExpectedTransmissionTimeForRelayResistanceRapdu;

        int maximumRelayResistanceGracePeriod = ByteUtils.byteArrayToInt(
                tlvDb.get(EmvTag.MAXIMUM_RELAY_RESISTANCE_GRACE_PERIOD).getValueBytes());

        int relayResistanceTransmissionTimeMismatchThreshold = ByteUtils.byteArrayToInt(
                tlvDb.get(EmvTag.RELAY_RESISTANCE_TRANSMISSION_TIME_MISMATCH_THRESHOLD).getValueBytes());

        int relayResistanceAccuracyThreshold = ByteUtils.byteArrayToInt(
                tlvDb.get(EmvTag.RELAY_RESISTANCE_ACCURACY_THRESHOLD).getValueBytes());

        do {
            // S3.61, SR1.23
            byte[] random = new byte[4];
            randomGenerator.nextBytes(random);
            tlvDb.updateOrAddKernel(new Tlv(EmvTag.UNPREDICTABLE_NUMBER, 4, random));
            tlvDb.updateOrAddKernel(new Tlv(EmvTag.TERMINAL_RELAY_RESISTANCE_ENTROPY, 4, random));

            rrpCounter++; //SR1.24
            logger.debug("rrpCounter: {}", rrpCounter);
            tlvDb.updateOrAddKernel(new Tlv(EmvTag.RRP_COUNTER, 1, new byte[]{(byte) rrpCounter}));

            long rrpStart = timeProvider.getVmTime();

            // S3.63
            ApduCommandPackage cmd = new ApduCommandPackage(ApduCommand.EXCHANGE_RELAY_RESISTANCE_DATA, random);
            logger.debug("EXCHANGE_RELAY_RESISTANCE_DATA");
            // S3.64
            ApduResponsePackage resp = transceiver.transceive(cmd);

            // SR1.4
            long rrpEnd = timeProvider.getVmTime();
            // SR1.10
            long timeTakenMillis = rrpEnd - rrpStart; // in milliseconds
            logger.debug("timeTakenMillis: {}", timeTakenMillis);
            double timeTakenMicros = timeTakenMillis * 1000d;

            //SR1.11
            if (!resp.isSuccess()) {
                resp.purgeData();
                // SR1.12, SR1.13
                resp.purgeData();
                return Rrp.createFailResult(RrpResult.ErrorType.TRY_ANOTHER_CARD_ERROR, resp.getStatusWord().statusWord);
            }

            // SR1.14
            try {
                List<Tlv> rrpTlvs = TlvUtils.getTlvs(Arrays.copyOfRange(resp.getData(), 0, resp.getData().length - 2));
                resp.purgeData();
                if (rrpTlvs.size() != 1) {
                    return Rrp.createFailResult(RrpResult.ErrorType.PARSE_ERROR, null);
                }
                Tlv rrpTlv = rrpTlvs.get(0);
                if (rrpTlv.getTag() != EmvTag.RESPONSE_MESSAGE_TEMPLATE_1) {
                    return Rrp.createFailResult(RrpResult.ErrorType.PARSE_ERROR, null);
                }

                byte[] rrpData = rrpTlv.getValueBytes();
                if (rrpData.length != 10) {
                    return Rrp.createFailResult(RrpResult.ErrorType.PARSE_ERROR, null);
                }


                byte[] deviceRelayResistanceEntropy = Arrays.copyOfRange(rrpData, 0, 4);

                minTimeForProcessingRelayResistanceApdu = ByteUtils.byteArrayToInt(Arrays.copyOfRange(rrpData, 4, 6));
                maxTimeForProcessingRelayResistanceApdu = ByteUtils.byteArrayToInt(Arrays.copyOfRange(rrpData, 6, 8));
                deviceEstimatedTransmissionTimeForRelayResistanceRadpu = ByteUtils.byteArrayToInt(Arrays.copyOfRange(rrpData, 8, 10));

                tlvDb.updateOrAddKernel(new Tlv(EmvTag.DEVICE_RELAY_RESISTANCE_ENTROPY, 4, deviceRelayResistanceEntropy));
                tlvDb.updateOrAddKernel(new Tlv(EmvTag.MIN_TIME_FOR_PROCESSING_RELAY_RESISTANCE_APDU, 2,
                        Arrays.copyOfRange(rrpData, 4, 6)));
                tlvDb.updateOrAddKernel(new Tlv(EmvTag.MAX_TIME_FOR_PROCESSING_RELAY_RESISTANCE_APDU, 2,
                        Arrays.copyOfRange(rrpData, 6, 8)));
                tlvDb.updateOrAddKernel(new Tlv(EmvTag.DEVICE_ESTIMATED_TRANSMISSION_TIME_FOR_RELAY_RESISTANCE_RAPDU, 2,
                        Arrays.copyOfRange(rrpData, 8, 10)));


                int terminalExpectedTransmissionTimeForRelayResistanceCadpu = ByteUtils.byteArrayToInt(
                        tlvDb.get(EmvTag.TERMINAL_EXPECTED_TRANSMISSION_TIME_C_APDU).getValueBytes());

                terminalExpectedTransmissionTimeForRelayResistanceRapdu = ByteUtils.byteArrayToInt(
                        tlvDb.get(EmvTag.TERMINAL_EXPECTED_TRANSMISSION_TIME_R_APDU).getValueBytes());

                int minimumRelayResistanceGracePeriod = ByteUtils.byteArrayToInt(
                        tlvDb.get(EmvTag.MINIMUM_RELAY_RESISTANCE_GRACE_PERIOD).getValueBytes());

                // SR1.18
                measuredRelayResistanceProcessingTime = Math.max(0d, (timeTakenMicros / 100d) -
                        terminalExpectedTransmissionTimeForRelayResistanceCadpu -
                        Math.min(deviceEstimatedTransmissionTimeForRelayResistanceRadpu,
                                terminalExpectedTransmissionTimeForRelayResistanceRapdu)
                );

                byte[] tmpM = ByteBuffer.allocate(4).putInt((int) measuredRelayResistanceProcessingTime).array();

                tlvDb.updateOrAddKernel(new Tlv(EmvTag.MEASURED_RELAY_RESISTANCE_PROCESSING_TIME, 2, new byte[]{tmpM[2], tmpM[3]}));

                logger.debug("measuredRelayResistanceProcessingTime: {}", measuredRelayResistanceProcessingTime);

                // SR1.19
                if (measuredRelayResistanceProcessingTime < Math.max(0, minTimeForProcessingRelayResistanceApdu -
                        minimumRelayResistanceGracePeriod)) {

                    logger.warn("measuredRelayResistanceProcessingTime too low");
                    return Rrp.createFailResult(RrpResult.ErrorType.TRY_ANOTHER_CARD_ERROR, null);
                }
            } catch (TlvException e) {
                return Rrp.createFailResult(RrpResult.ErrorType.PARSE_ERROR, null);
            }

            boolean tookTooLong = measuredRelayResistanceProcessingTime >
                    (maxTimeForProcessingRelayResistanceApdu + maximumRelayResistanceGracePeriod);
            if (tookTooLong) {
                logger.debug("RRP took too long. measuredRelayResistanceProcessingTime: {}, " +
                                "maxTimeForProcessingRelayResistanceApdu: {}, maximumRelayResistanceGracePeriod: {}",
                        measuredRelayResistanceProcessingTime,
                        maxTimeForProcessingRelayResistanceApdu,
                        maximumRelayResistanceGracePeriod
                );
            }
        } while (rrpCounter < 2 && (measuredRelayResistanceProcessingTime >
                (maxTimeForProcessingRelayResistanceApdu + maximumRelayResistanceGracePeriod)));

        boolean relayResistanceTimeLimitsExceeded = false;
        boolean relayResistanceThresholdExceeded = false;

        // SR1.28
        if ((measuredRelayResistanceProcessingTime >
                (maxTimeForProcessingRelayResistanceApdu + maximumRelayResistanceGracePeriod))) {
            // SR1.29
            relayResistanceTimeLimitsExceeded = true;
            logger.debug("relayResistanceTimeLimitsExceeded := true");
        }

        // SR1.30
        if (deviceEstimatedTransmissionTimeForRelayResistanceRadpu > 0 && terminalExpectedTransmissionTimeForRelayResistanceRapdu > 0) {
            if ((((deviceEstimatedTransmissionTimeForRelayResistanceRadpu * 100f) /
                    terminalExpectedTransmissionTimeForRelayResistanceRapdu) < relayResistanceTransmissionTimeMismatchThreshold)
                    ||
                    (((terminalExpectedTransmissionTimeForRelayResistanceRapdu * 100f) /
                            deviceEstimatedTransmissionTimeForRelayResistanceRadpu) < relayResistanceTransmissionTimeMismatchThreshold)
                    ||
                    (Math.max(0, (measuredRelayResistanceProcessingTime - minTimeForProcessingRelayResistanceApdu)) >
                            relayResistanceAccuracyThreshold)
                    ) {

                logger.debug("relayResistanceThresholdExceeded := true");
                relayResistanceThresholdExceeded = true;
            }
        } else {
            relayResistanceThresholdExceeded = true;
        }

        return Rrp.createOkResult(relayResistanceTimeLimitsExceeded, relayResistanceThresholdExceeded,
                (int) measuredRelayResistanceProcessingTime, rrpCounter);
    }
}
