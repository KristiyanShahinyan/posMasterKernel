package digital.paynetics.phos.kernel.mastercard.gpo;

import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationInterchangeProfile;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMap;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapImpl;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;
import digital.paynetics.phos.kernel.common.emv.tag.TlvUtils;
import digital.paynetics.phos.kernel.common.misc.NfcConnectionLostException;
import digital.paynetics.phos.kernel.common.nfc.ApduCommand;
import digital.paynetics.phos.kernel.common.nfc.ApduCommandPackage;
import digital.paynetics.phos.kernel.common.nfc.ApduResponsePackage;
import digital.paynetics.phos.kernel.common.nfc.ApduResponseStatusWord;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;
import digital.paynetics.phos.kernel.mastercard.MastercardTags;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardErrorIndication;

import static digital.paynetics.phos.kernel.mastercard.misc.MastercardMessageIdentifier.ERROR_OTHER_CARD;
import static digital.paynetics.phos.kernel.mastercard.misc.MastercardMessageIdentifier.NOT_AVAILABLE;


public class GpoExecutorImpl implements GpoExecutor {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());

    private final List<Tlv> forTlvDb = new ArrayList<>();
    private ApplicationInterchangeProfile applicationInterchangeProfile;
    private byte[] applicationFileLocator;


    @Inject
    public GpoExecutorImpl() {
    }


    @Override
    public GpoResult execute(Transceiver transceiver, byte[] pdolPrepared, boolean aipOrAflPresentAndNonEmpty) throws IOException { // S3.5
        logger.debug("(nfc) About to execute GET PROCESSING OPTIONS");

        try {
            // S1.13 & S1.14
            ApduCommandPackage cmd = new ApduCommandPackage(ApduCommand.GPO, pdolPrepared);
            // S3.1
            ApduResponsePackage respGpo = transceiver.transceive(cmd);

            // S3.8
            if (respGpo.isSuccess()) {
                // S3.10
                // parse will throw TlvException | EmvException on parse error
                boolean parsingResult = parse(Arrays.copyOfRange(respGpo.getData(), 0, respGpo.getData().length - 2),
                        aipOrAflPresentAndNonEmpty);

                // S3.11
                if (parsingResult) {
                    // S3.13
                    TlvMap map = new TlvMapImpl(forTlvDb);
                    if (map.isTagPresentAndNonEmpty(EmvTag.APPLICATION_INTERCHANGE_PROFILE) &&
                            map.isTagPresentAndNonEmpty(EmvTag.APPLICATION_FILE_LOCATOR)) {

                        respGpo.purgeData();
                        return GpoResult.createOkResult(applicationInterchangeProfile,
                                applicationFileLocator,
                                forTlvDb);

                    } else {
                        MastercardErrorIndication ei = MastercardErrorIndication.
                                createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_MISSING, ERROR_OTHER_CARD);
                        respGpo.purgeData();
                        return GpoResult.createFailResult(ei, false);
                    }
                } else {
                    // S3.12
                    MastercardErrorIndication ei = MastercardErrorIndication.
                            createL2Error(MastercardErrorIndication.L2Error.PARSING_ERROR, ERROR_OTHER_CARD);
                    respGpo.purgeData();
                    return GpoResult.createFailResult(ei, false);
                }
            } else {
                // S3.9.1, S3.9.2
                logger.warn("GPO returned error: " + respGpo.getStatusWord());
                Outcome.Builder b = new Outcome.Builder(Outcome.Type.SELECT_NEXT);
                b.start(Outcome.Start.C);

                byte[] rawSw = Arrays.copyOfRange(respGpo.getData(), respGpo.getData().length - 2, respGpo.getData().length);
                MastercardErrorIndication ei;
                if (respGpo.getStatusWord() == ApduResponseStatusWord.SW_UNKNOWN) {
                    ei = MastercardErrorIndication.
                            createL2StatusBytesError(rawSw, NOT_AVAILABLE);
                } else {
                    ei = MastercardErrorIndication.
                            createL2StatusBytesError(respGpo.getStatusWord().getStatusWord(), NOT_AVAILABLE);
                }

                respGpo.purgeData();
                return GpoResult.createFailResult(ei, false);
            }
        } catch (TlvException | EmvException e) {
            // S3.11, S3.12
            logger.warn("GPO parsing error: {}", e.getMessage());
            return parsingError();
        } catch (NfcConnectionLostException e) {
            logger.warn("Timeout during wait for GPO response");
            MastercardErrorIndication ei =
                    MastercardErrorIndication.createL1Error(MastercardErrorIndication.L1Error.TIME_OUT,
                            NOT_AVAILABLE);

            return GpoResult.createFailResult(ei, true);
        }
    }


    boolean parse(byte[] data, boolean aipOrAflPresentAndNonEmpty) throws TlvException, EmvException {
        Tlv tlv = TlvUtils.getNextTlv(data);
        if (tlv.getTag() == EmvTag.RESPONSE_MESSAGE_TEMPLATE_1) {
            logger.debug("GPO Template 1");
            int length = tlv.getLength();
            if (!(length >= 6 && (length - 2) % 4 == 0)) {
                throw new EmvException("Invalid length (S3.10)");
            }

            if (aipOrAflPresentAndNonEmpty) {
                throw new EmvException("AIP of AFL non empty (S3.10)");
            }

            byte[] tagValueData = tlv.getValueBytes();
            byte[] tagAipData = new byte[2];
            System.arraycopy(tagValueData, 0, tagAipData, 0, 2);
            forTlvDb.add(new Tlv(EmvTag.APPLICATION_INTERCHANGE_PROFILE, 2, tagAipData));
            applicationInterchangeProfile = new ApplicationInterchangeProfile(tagAipData);

            byte[] tagAflData = new byte[length - 2];

            if (tagAflData.length < 4 || tagAflData.length > 248) {
                throw new EmvException("Invalid APPLICATION_FILE_LOCATOR length");
            }

            System.arraycopy(tagValueData, 2, tagAflData, 0, length - 2);
            forTlvDb.add(new Tlv(EmvTag.APPLICATION_FILE_LOCATOR, length - 2, tagAflData));
            applicationFileLocator = tagAflData;
        } else if (tlv.getTag() == EmvTag.RESPONSE_MESSAGE_TEMPLATE_2) {
            logger.debug("GPO Template 2");
            List<Tlv> list = TlvUtils.getChildTlvs(data, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2);

            if (list.size() != 0) {
                MastercardTags.checkInValidTemplate(list, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2);

                for (Tlv item : list) {
                    if (item.getTag() == EmvTag.APPLICATION_INTERCHANGE_PROFILE) {
                        applicationInterchangeProfile = new ApplicationInterchangeProfile(item.getValueBytes());
                        forTlvDb.add(item);
                    } else if (item.getTag() == EmvTag.APPLICATION_FILE_LOCATOR) {
                        int length = item.getValueBytes().length;

                        // Check bellow is not included into S3.10 explicitly. See A.1.15 Application File Locator for
                        // length limits
                        if (length < 4 || length > 248 || (length % 4 != 0)) {
                            throw new EmvException("Invalid APPLICATION_FILE_LOCATOR length");
                        }
                        forTlvDb.add(item);
                        applicationFileLocator = item.getValueBytes();
                    } else {
                        forTlvDb.add(item);
                    }
                }
            }
        } else {
            logger.warn("Response is not TEMPLATE 1 or 2");
            return false;
        }

        List<Tlv> tlvs = TlvUtils.getTlvs(data);
        if (tlvs.size() > 1) {
            throw new EmvException("Unexpected tags in GPO response");
        }

        return true;
    }


    private GpoResult parsingError() {
        MastercardErrorIndication ei = MastercardErrorIndication.
                createL2Error(MastercardErrorIndication.L2Error.PARSING_ERROR, ERROR_OTHER_CARD);
        return GpoResult.createFailResult(ei, false);
    }
}
