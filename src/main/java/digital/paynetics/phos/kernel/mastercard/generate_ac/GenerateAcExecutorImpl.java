package digital.paynetics.phos.kernel.mastercard.generate_ac;

import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.TerminalVerificationResults;
import digital.paynetics.phos.kernel.common.emv.cert.CaPublicKeyDb;
import digital.paynetics.phos.kernel.common.emv.cert.CrlRid;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationCryptogramType;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapReadOnly;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;
import digital.paynetics.phos.kernel.common.emv.tag.TlvUtils;
import digital.paynetics.phos.kernel.common.emv.ui.ContactlessTransactionStatus;
import digital.paynetics.phos.kernel.common.emv.ui.StandardMessages;
import digital.paynetics.phos.kernel.common.emv.ui.UserInterfaceRequest;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import digital.paynetics.phos.kernel.common.misc.McTlvList;
import digital.paynetics.phos.kernel.common.misc.NfcConnectionLostException;
import digital.paynetics.phos.kernel.common.misc.TerminalCapabilities13;
import digital.paynetics.phos.kernel.common.misc.TimeProvider;
import digital.paynetics.phos.kernel.common.misc.TransactionTimestamp;
import digital.paynetics.phos.kernel.common.nfc.ApduCommand;
import digital.paynetics.phos.kernel.common.nfc.ApduCommandPackage;
import digital.paynetics.phos.kernel.common.nfc.ApduResponsePackage;
import digital.paynetics.phos.kernel.common.nfc.ApduResponseStatusWord;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;
import digital.paynetics.phos.kernel.mastercard.MastercardKernel;
import digital.paynetics.phos.kernel.mastercard.MastercardTags;
import digital.paynetics.phos.kernel.mastercard.misc.DsSummaryStatus;
import digital.paynetics.phos.kernel.mastercard.misc.IdsStatus;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardErrorIndication;
import digital.paynetics.phos.kernel.mastercard.misc.MessageStoreMc;
import digital.paynetics.phos.kernel.mastercard.misc.TlvDb;
import digital.paynetics.phos.kernel.mastercard.put_data.PutDataProcessor;
import digital.paynetics.phos.kernel.mastercard.torn.TornTransactionLog;
import java8.util.Optional;

import static digital.paynetics.phos.kernel.mastercard.misc.MastercardMessageIdentifier.ERROR_OTHER_CARD;
import static digital.paynetics.phos.kernel.mastercard.misc.MastercardMessageIdentifier.TRY_AGAIN;


public class GenerateAcExecutorImpl implements GenerateAcExecutor {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(GenerateAcExecutorImpl.class);

    private final Template1Handler template1Handler;
    private final Template2Handler template2Handler;
    private final MessageStoreMc messageStore;
    private final PutDataProcessor putDataProcessor;
    private final TornTransactionLog tornTransactionLog;
    private final TimeProvider timeProvider;


    @Inject
    public GenerateAcExecutorImpl(Template1Handler template1Handler,
                                  Template2Handler template2Handler,
                                  MessageStoreMc messageStore,
                                  PutDataProcessor putDataProcessor,
                                  TornTransactionLog tornTransactionLog,
                                  TimeProvider timeProvider) {

        this.template1Handler = template1Handler;
        this.template2Handler = template2Handler;
        this.messageStore = messageStore;
        this.putDataProcessor = putDataProcessor;
        this.tornTransactionLog = tornTransactionLog;
        this.timeProvider = timeProvider;
    }


    private static Outcome parsingError(TlvMapReadOnly tlvDb) {
        MastercardErrorIndication ei = MastercardErrorIndication.
                createL2Error(MastercardErrorIndication.L2Error.PARSING_ERROR, ERROR_OTHER_CARD);
        return Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(true, tlvDb, ei));
    }


    @Override
    public Outcome execute(Transceiver transceiver,
                           byte[] cdol1Prepared,
                           byte[] dsDolPrepared,
                           byte referenceControlParameter,
                           ApplicationCryptogramType requestedApplicationCryptogramType,
                           Outcome.Cvm cvm,
                           boolean receiptRequired,
                           TlvDb tlvDb,
                           Optional<CaPublicKeyDb> caPublicKeyDbO,
                           CrlRid crlRid,
                           byte[] pdolData,
                           TransactionTimestamp ts,
                           String pan,
                           byte[] staticDataToBeAuthenticated,
                           boolean haveIds,
                           boolean isIdsVersion2,
                           int rrpMeasuredProcessingTime,
                           int rrpCounter,
                           McTlvList deTagsToWriteYetAfterGenAc,
                           int messageHoldTime,
                           IdsStatus idsStatus,
                           DsSummaryStatus dsSummaryStatus,
                           boolean isSupportingBalanceReading,
                           TerminalVerificationResults terminalVerificationResults,
                           TerminalCapabilities13 terminalCapabilities13
    ) {
        byte[] dolFinal;
        if (idsStatus.isWrite()) {
            dolFinal = ByteUtils.byteArrayConcat(cdol1Prepared, dsDolPrepared);
        } else {
            dolFinal = cdol1Prepared;
        }

        ApduCommandPackage cmd = new ApduCommandPackage(ApduCommand.GENERATE_APPLICATION_CRYPTOGRAM,
                referenceControlParameter,
                (byte) 0,
                dolFinal,
                0);

        try {
            logger.debug("(nfc) GENERATE AC");
            // S9.1
            ApduResponsePackage resp = transceiver.transceive(cmd);

            // S9.16
            if (resp.isSuccess()) {
                // S9.18
                boolean isParsingResultGenAcOk = false;
                Tlv tlv = TlvUtils.getNextTlv(resp.getDataNoStatusBytes(), true);
                List<Tlv> genAcTlvs = null; // will be used in cdaMode()
                if (tlv.getTag() == EmvTag.RESPONSE_MESSAGE_TEMPLATE_2) {
                    genAcTlvs = template2Handler.handle(resp.getData());
                    resp.purgeData();
                    MastercardTags.checkInValidTemplate(genAcTlvs, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2);
                    // we need to check for empty tags here in order to potentially trigger parsing error
                    if (!MastercardTags.checkValidSizes(genAcTlvs)) {
                        return parsingError(tlvDb);
                    }

                    for (Tlv tlvTmp : genAcTlvs) {
                        tlvDb.updateOrAddRa(tlvTmp);
                    }

                    isParsingResultGenAcOk = true;
                } else if (tlv.getTag() == EmvTag.RESPONSE_MESSAGE_TEMPLATE_1) {
                    genAcTlvs = template1Handler.handle(tlv.getValueBytes());
                    resp.purgeData();

                    // no check for valid template because it is not parseAndStoreCardResponse
                    for (Tlv tlvTmp : genAcTlvs) {
                        tlvDb.updateOrAddRa(tlvTmp);
                    }
                    isParsingResultGenAcOk = true;
                } else {
                    resp.purgeData();
                    logger.warn("Unexpected response {}. Expected template 1 or 2", tlv.getTag());
                    // we don't do anything special in this case because isParsingResultGenAcOk remains false and will
                    // trigger S9.19 parsingError bellow
                }

                // S9.19
                if (!isParsingResultGenAcOk) {
                    // S9.20
                    logger.warn("Parsing failed");
                    MastercardErrorIndication ei = MastercardErrorIndication.
                            createL2Error(MastercardErrorIndication.L2Error.PARSING_ERROR, ERROR_OTHER_CARD);

                    return AcStageImpl.invalidResponse1(tlvDb, idsStatus.isWrite(), ei);
                }

                // S9.21
                if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.CRYPTOGRAM_INFORMATION_DATA) ||
                        !tlvDb.isTagPresentAndNonEmpty(EmvTag.APP_TRANSACTION_COUNTER)) {

                    // S9.22
                    logger.warn("Missing card data: CRYPTOGRAM_INFORMATION_DATA or APP_TRANSACTION_COUNTER");

                    MastercardErrorIndication ei = MastercardErrorIndication.
                            createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_MISSING, ERROR_OTHER_CARD);

                    return AcStageImpl.invalidResponse1(tlvDb, idsStatus.isWrite(), ei);
                }

                // S9.23
                byte[] cid = tlvDb.get(EmvTag.CRYPTOGRAM_INFORMATION_DATA).getValueBytes();
                logger.debug("CID: {}", ByteUtils.toHexString(cid));

                if (!((((cid[0] & ((byte) 0xc0)) == (byte) 0x40) &&
                        requestedApplicationCryptogramType == ApplicationCryptogramType.TC) ||

                        (((cid[0] & ((byte) 0xc0)) == (byte) 0x80) &&
                                (requestedApplicationCryptogramType == ApplicationCryptogramType.ARQC ||
                                        requestedApplicationCryptogramType == ApplicationCryptogramType.TC
                                )) ||
                        ((cid[0] & ((byte) 0xc0)) == 0)
                )) {
                    // S9.24
                    logger.warn("Invalid CRYPTOGRAM_INFORMATION_DATA S9.24");
                    MastercardErrorIndication ei = MastercardErrorIndication.
                            createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_ERROR, ERROR_OTHER_CARD);

                    return AcStageImpl.invalidResponse1(tlvDb, idsStatus.isWrite(), ei);
                }


                // S9.25
                if (isSupportingBalanceReading) {
                    AcStageImpl.balanceReadingAfterGenAc(tlvDb, transceiver);
                }


                // S9.26
                if (deTagsToWriteYetAfterGenAc.isEmpty()) {
                    // S9.27
                    UserInterfaceRequest ui = new UserInterfaceRequest(StandardMessages.CLEAR_DISPLAY,
                            ContactlessTransactionStatus.CARD_READ_SUCCESSFULLY,
                            0, null, null, 0, null);

                    messageStore.add(ui);
                }

                // S9.28
                if (tlvDb.isTagPresentAndNonEmpty(EmvTag.SIGNED_DYNAMIC_APPLICATION_DATA)) {
                    return AcStageImpl.cdaMode(tlvDb, caPublicKeyDbO, crlRid, cid,
                            tlvDb.get(EmvTag.SIGNED_DYNAMIC_APPLICATION_DATA).getValueBytes(),
                            tlvDb.get(EmvTag.PDOL_RELATED_DATA).getValueBytes(),
                            cdol1Prepared,
                            genAcTlvs, cvm, receiptRequired, ts, staticDataToBeAuthenticated, haveIds, isIdsVersion2,
                            rrpMeasuredProcessingTime > 0,
                            transceiver,
                            deTagsToWriteYetAfterGenAc,
                            messageHoldTime,
                            idsStatus,
                            dsSummaryStatus,
                            messageStore,
                            putDataProcessor,
                            terminalVerificationResults,
                            terminalCapabilities13);
                } else {
                    return AcStageImpl.noCdaMode(tlvDb, referenceControlParameter, cvm, receiptRequired,
                            requestedApplicationCryptogramType, rrpMeasuredProcessingTime, rrpCounter, transceiver,
                            deTagsToWriteYetAfterGenAc,
                            messageHoldTime,
                            messageStore,
                            putDataProcessor,
                            idsStatus,
                            terminalCapabilities13);
                }


            } else {
                // S9.17
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
                return AcStageImpl.invalidResponse1(tlvDb, idsStatus.isWrite(), ei);
            }
        } catch (IOException | NfcConnectionLostException e) {
            // S9.1
            logger.warn("Exception: {}", e.getMessage());


            // S9.5
            if (tlvDb.get(EmvTag.MAX_NUMBER_TORN_TRANSACTION_LOG_REC).getValueBytes()[0] != 0 &&
                    tlvDb.isTagPresentAndNonEmpty(EmvTag.DRDOL)) {
                return AcStageImpl.processWithCreatingTornLogRecord(tlvDb, tornTransactionLog, timeProvider);
            } else {


                // S9.6
                if (idsStatus.isWrite()) {
                    // S9.7 & S9.8
//                    return Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(true, tlvDb, ei));
                    MastercardErrorIndication ei;
                    if (e instanceof NfcConnectionLostException) {
                        ei = MastercardErrorIndication.createL1Error(MastercardErrorIndication.L1Error.TIME_OUT, ERROR_OTHER_CARD);
                    } else {
                        ei = MastercardErrorIndication.createL1Error(MastercardErrorIndication.L1Error.TRANSMISSION_ERROR,
                                ERROR_OTHER_CARD);
                    }
                    Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);
                    UserInterfaceRequest uiReq = new UserInterfaceRequest(StandardMessages.TRY_ANOTHER_CARD,
                            ContactlessTransactionStatus.NOT_READY, 13, null,
                            null, 0, null);
                    b.uiRequestOnOutcome(uiReq);
                    b.removalTimeout(0);
                    b.discretionaryData(MastercardKernel.buildDiscretionaryData(true, tlvDb, ei));
                    b.dataRecord(MastercardKernel.buildDataRecordEmv(tlvDb));
                    return b.build();

                } else {

                    MastercardErrorIndication ei;
                    if (e instanceof NfcConnectionLostException) {
                        ei = MastercardErrorIndication.createL1Error(MastercardErrorIndication.L1Error.TIME_OUT, TRY_AGAIN);
                    } else {
                        ei = MastercardErrorIndication.createL1Error(MastercardErrorIndication.L1Error.TRANSMISSION_ERROR,
                                ERROR_OTHER_CARD);
                    }

                    //S9.9 & S9.10
                    Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);

                    UserInterfaceRequest uiReq = new UserInterfaceRequest(StandardMessages.PRESENT_CARD_AGAIN,
                            ContactlessTransactionStatus.READY_TO_READ,
                            0,
                            null,
                            null,
                            0,
                            null);
                    b.start(Outcome.Start.B);
                    b.uiRequestOnRestart(uiReq);
                    b.removalTimeout(0);
                    b.discretionaryData(MastercardKernel.buildDiscretionaryData(true, tlvDb, ei));

                    return b.build();
                }
            }
        } catch (TlvException | EmvException e) {
            logger.warn("Exception: {}", e.getMessage());
            return parsingError(tlvDb);
        }
    }
}
