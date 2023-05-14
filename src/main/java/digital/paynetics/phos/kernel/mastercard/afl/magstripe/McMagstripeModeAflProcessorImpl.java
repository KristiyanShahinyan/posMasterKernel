package digital.paynetics.phos.kernel.mastercard.afl.magstripe;

import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.kernel.common.Afl;
import digital.paynetics.phos.kernel.common.emv.kernel.common.AflsExtractor;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMap;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapImpl;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapReadOnly;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;
import digital.paynetics.phos.kernel.common.emv.tag.TlvUtils;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import digital.paynetics.phos.kernel.common.misc.Track1Data;
import digital.paynetics.phos.kernel.common.misc.Track2Data;
import digital.paynetics.phos.kernel.common.nfc.ApduCommand;
import digital.paynetics.phos.kernel.common.nfc.ApduCommandPackage;
import digital.paynetics.phos.kernel.common.nfc.ApduResponsePackage;
import digital.paynetics.phos.kernel.common.nfc.ApduResponseStatusWord;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;
import digital.paynetics.phos.kernel.mastercard.MastercardKernel;
import digital.paynetics.phos.kernel.mastercard.MastercardTags;
import digital.paynetics.phos.kernel.mastercard.afl.McAflProcessorResult;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardErrorIndication;

import static digital.paynetics.phos.kernel.mastercard.misc.MastercardMessageIdentifier.ERROR_OTHER_CARD;


public class McMagstripeModeAflProcessorImpl implements McMagstripeModeAflProcessor {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());

    private final AflsExtractor aflsExtractor;

    private volatile boolean isStopSignalReceived = false;


    @Inject
    public McMagstripeModeAflProcessorImpl(AflsExtractor aflsExtractor) {
        this.aflsExtractor = aflsExtractor;
    }


    @Override
    public McAflProcessorResult process(Transceiver transceiver,
                                        byte[] applicationFileLocator,
                                        TlvMapReadOnly tlvDb) throws IOException {

        List<Tlv> forTlvDb = new ArrayList<>();
        List<Tlv> forTlvDbKernel = new ArrayList<>();

        List<Afl> afls;
        try {
            afls = aflsExtractor.extractAfls(applicationFileLocator);
            logger.debug("Extracted AFLs: {}", afls.size());
            if (afls.size() == 0) {
                return cardDataError(tlvDb);
            }

            for (Afl afl : afls) {
                McAflProcessorResult rez = processSingleAfl(transceiver, afl, tlvDb);
                if (rez.isOk()) {
                    forTlvDb.addAll(rez.getForTlvDb());
                } else {
                    return rez;
                }

                if (isStopSignalReceived) {
                    return McAflProcessorResult.createFailResult(MastercardKernel.createStopOutcome(), false);
                }
            }

            TlvMap tmp = new TlvMapImpl();
            for (Tlv tlv : forTlvDb) {
                if (!tmp.isTagPresentAndNonEmpty(tlv.getTag())) {
                    tmp.add(tlv);
                }
            }

            // S7.20
            if (!tmp.isTagPresentAndNonEmpty(EmvTag.TRACK2_DATA) ||
                    !tmp.isTagPresentAndNonEmpty(EmvTag.TERMINAL_TRANSACTION_QUALIFIERS__PUNATC_TRACK2) ||
                    !tmp.isTagPresentAndNonEmpty(EmvTag.PCVC3_TRACK2) ||
                    !tmp.isTagPresentAndNonEmpty(EmvTag.NATC_TRACK2)
                    ) {

                // S7.21.1, S7.21.2
                return cardDataMissing(tlvDb);
            } else {
                // S7.23
                try {
                    Track2Data t2d = new Track2Data(tmp.get(EmvTag.TRACK2_DATA).getValueBytes());
                    byte[] dd = ByteUtils.char2byteArr(t2d.getDiscretionaryDataPadded());
                    forTlvDbKernel.add(new Tlv(EmvTag.DD_CARD_TRACK2, dd.length, dd));
                    t2d.purge();
                } catch (EmvException e) {
                    logger.warn(e.getMessage());
                    return cardDataError(tlvDb);
                }
            }

            // S7.22


            int punAtc2nz = Integer.bitCount(tmp.get(EmvTag.TERMINAL_TRANSACTION_QUALIFIERS__PUNATC_TRACK2).getValueAsHexInt());
            int natc = tmp.get(EmvTag.NATC_TRACK2).getValueAsHexInt();
            int nUn = punAtc2nz - natc;
            if (nUn < 0 || nUn > 8) {
                return cardDataError(tlvDb);
            }

            if (tmp.isTagPresentAndNonEmpty(EmvTag.TRACK1_DATA)) {
                if (!tmp.isTagPresentAndNonEmpty(EmvTag.NATC_TRACK1) ||
                        !tmp.isTagPresentAndNonEmpty(EmvTag.PCVC3_TRACK1) ||
                        !tmp.isTagPresentAndNonEmpty(EmvTag.PUNATC_TRACK1)

                        ) {

                    // S7.24.1, S7.24.2
                    return cardDataError(tlvDb);
                } else {
                    int punatc1nz = Long.bitCount(tmp.get(EmvTag.PUNATC_TRACK1).getValueAsHexLong());
                    int natc1 = tmp.get(EmvTag.NATC_TRACK1).getValueAsHexInt();

                    if (punatc1nz - natc1 != nUn) {
                        return cardDataError(tlvDb);
                    }
                    int sub1 = punatc1nz - natc1;
                    if (sub1 < 0 || sub1 > 8) {
                        return cardDataError(tlvDb);
                    }
                }

                // S7.23 again
                try {
                    Track1Data t1d = new Track1Data(tmp.get(EmvTag.TRACK1_DATA).getValueAsString());
                    byte[] dd = t1d.getDiscretionaryData().getBytes();
                    forTlvDbKernel.add(new Tlv(EmvTag.DD_CARD_TRACK1, dd.length, dd));
                } catch (EmvException e) {
                    logger.warn(e.getMessage());
                    return cardDataError(tlvDb);
                }
            }


            return McAflProcessorResult.createOkResult(forTlvDb, forTlvDbKernel, null, false);
        } catch (EmvException e) {
            logger.warn(e.getMessage());
            return parsingError(tlvDb);
        }
    }


    @Override
    public void stopSignal() {
        isStopSignalReceived = true;
    }


    McAflProcessorResult processSingleAfl(Transceiver transceiver, Afl afl, TlvMapReadOnly tlvDb) throws IOException, EmvException {
        List<Tlv> forTlvDb = new ArrayList<>();

        for (int index = afl.getFirstRecord(); index <= afl.getLastRecord(); index++) {
            // S3.80, S7.18
            logger.debug("(nfc) READ RECORD AFL {}, index {}", afl, index);
            ApduCommandPackage cmd = new ApduCommandPackage(ApduCommand.READ_RECORD, (byte) index,
                    (byte) ((afl.getSfi() << 3) | 4), null, 0);

            // S3.81, S7.19
            ApduResponsePackage resp = transceiver.transceive(cmd);

            // S7.9
            if (resp.isSuccess()) {

                byte[] dataNoSuccessCode = Arrays.copyOfRange(resp.getData(), 0, resp.getData().length - 2);
                // S7.11
                if (afl.getSfi() <= 10) {
                    try {
                        List<Tlv> tlvs = TlvUtils.getTlvs(dataNoSuccessCode);
                        if (tlvs.size() > 1) {
                            logger.warn("Unexpected tags in RR response");
                            return parsingError(tlvDb);
                        }


                        // S7.12
                        if (resp.getData().length > 0 && resp.getData()[0] == EmvTag.RECORD_TEMPLATE.getTagBytes()[0]) {
                            List<Tlv> children = TlvUtils.getChildTlvs(resp.getData(), EmvTag.RECORD_TEMPLATE);

                            MastercardTags.checkInValidTemplate(children, EmvTag.RECORD_TEMPLATE);

                            forTlvDb.addAll(children);

                            resp.purgeData();

                            // S7.14, S7.15 - skip, we have the data, will deal with UDOL outside of this class
                            // S7.16, S7.17 - we are in for iteration
                        } else {
                            // S7.13.1, S7.13.2
                            return parsingError(tlvDb);
                        }
                    } catch (TlvException e) {
                        resp.purgeData();
                        return parsingError(tlvDb);
                    }
                } else {
                    return parsingError(tlvDb);
                }
            } else {
                // S7.10.1 & S7.10.2
                byte[] rawSw = Arrays.copyOfRange(resp.getData(), resp.getData().length - 2, resp.getData().length);
                MastercardErrorIndication ei;
                if (resp.getStatusWord() == ApduResponseStatusWord.SW_UNKNOWN) {
                    ei = MastercardErrorIndication.
                            createL2StatusBytesError(rawSw, ERROR_OTHER_CARD);
                } else {
                    ei = MastercardErrorIndication.
                            createL2StatusBytesError(resp.getStatusWord().getStatusWord(), ERROR_OTHER_CARD);
                }
                resp.purgeData();
                return McAflProcessorResult.createFailResult(
                        Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(true, tlvDb, ei)), false);
            }

        }

        return McAflProcessorResult.createOkResult(forTlvDb, null, null, false);
    }


    private McAflProcessorResult parsingError(TlvMapReadOnly tlvDb) {
        MastercardErrorIndication ei = MastercardErrorIndication.
                createL2Error(MastercardErrorIndication.L2Error.PARSING_ERROR, ERROR_OTHER_CARD);
        return McAflProcessorResult.createFailResult(
                Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(true, tlvDb, ei)), false);
    }


    private McAflProcessorResult cardDataMissing(TlvMapReadOnly tlvDb) {
        MastercardErrorIndication ei = MastercardErrorIndication.
                createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_MISSING, ERROR_OTHER_CARD);
        return McAflProcessorResult.createFailResult(
                Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(true, tlvDb, ei)), false);
    }


    private McAflProcessorResult cardDataError(TlvMapReadOnly tlvDb) {
        MastercardErrorIndication ei = MastercardErrorIndication.
                createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_ERROR, ERROR_OTHER_CARD);
        return McAflProcessorResult.createFailResult(
                Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(true, tlvDb, ei)), false);
    }
}
