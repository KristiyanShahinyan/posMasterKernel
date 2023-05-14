package digital.paynetics.phos.kernel.mastercard.generate_ac;

import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.crypto.CryptoException;
import digital.paynetics.phos.kernel.common.crypto.InvalidDynamicApplicationData;
import digital.paynetics.phos.kernel.common.crypto.IssuerPublicKeyCertificate;
import digital.paynetics.phos.kernel.common.crypto.SignedDynamicApplicationData;
import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.TerminalVerificationResults;
import digital.paynetics.phos.kernel.common.emv.cert.CaPublicKeyData;
import digital.paynetics.phos.kernel.common.emv.cert.CaPublicKeyDb;
import digital.paynetics.phos.kernel.common.emv.cert.CrlRid;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationCryptogramType;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationInterchangeProfile;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMap;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapImpl;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapReadOnly;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.TagAndLength;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;
import digital.paynetics.phos.kernel.common.emv.tag.TlvUtils;
import digital.paynetics.phos.kernel.common.emv.ui.ContactlessTransactionStatus;
import digital.paynetics.phos.kernel.common.emv.ui.StandardMessages;
import digital.paynetics.phos.kernel.common.emv.ui.UserInterfaceRequest;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import digital.paynetics.phos.kernel.common.misc.Currency;
import digital.paynetics.phos.kernel.common.misc.McTlvList;
import digital.paynetics.phos.kernel.common.misc.NfcConnectionLostException;
import digital.paynetics.phos.kernel.common.misc.TerminalCapabilities13;
import digital.paynetics.phos.kernel.common.misc.TimeProvider;
import digital.paynetics.phos.kernel.common.misc.TransactionTimestamp;
import digital.paynetics.phos.kernel.common.misc.TransactionType;
import digital.paynetics.phos.kernel.common.nfc.ApduCommand;
import digital.paynetics.phos.kernel.common.nfc.ApduCommandPackage;
import digital.paynetics.phos.kernel.common.nfc.ApduResponsePackage;
import digital.paynetics.phos.kernel.common.nfc.ApduResponseStatusWord;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;
import digital.paynetics.phos.kernel.mastercard.MastercardKernel;
import digital.paynetics.phos.kernel.mastercard.MastercardTags;
import digital.paynetics.phos.kernel.mastercard.get_data.GetDataUtil;
import digital.paynetics.phos.kernel.mastercard.misc.ApplicationCapabilityInformation;
import digital.paynetics.phos.kernel.mastercard.misc.CardPublicKeyCertificate2;
import digital.paynetics.phos.kernel.mastercard.misc.DolParser;
import digital.paynetics.phos.kernel.mastercard.misc.DsOdsInfoForReader;
import digital.paynetics.phos.kernel.mastercard.misc.DsSlotManagementControl;
import digital.paynetics.phos.kernel.mastercard.misc.DsSummaryStatus;
import digital.paynetics.phos.kernel.mastercard.misc.IdsStatus;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardDolPreparer;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardErrorIndication;
import digital.paynetics.phos.kernel.mastercard.misc.MessageStoreMc;
import digital.paynetics.phos.kernel.mastercard.misc.Owhf;
import digital.paynetics.phos.kernel.mastercard.misc.PciiMessageTable;
import digital.paynetics.phos.kernel.mastercard.misc.PosCardHolderInteractionInformation;
import digital.paynetics.phos.kernel.mastercard.misc.SensitiveData;
import digital.paynetics.phos.kernel.mastercard.misc.ThirdPartyData;
import digital.paynetics.phos.kernel.mastercard.misc.TlvDb;
import digital.paynetics.phos.kernel.mastercard.misc.TvrUtil;
import digital.paynetics.phos.kernel.mastercard.put_data.PutDataProcessor;
import digital.paynetics.phos.kernel.mastercard.rrp.Rrp;
import digital.paynetics.phos.kernel.mastercard.torn.TornTransactionLog;
import digital.paynetics.phos.kernel.mastercard.torn.TornTransactionLogRecord;
import hirondelle.date4j.DateTime;
import java8.util.Optional;

import static digital.paynetics.phos.kernel.common.crypto.CryptoUtils.calculateSha1;
import static digital.paynetics.phos.kernel.mastercard.misc.ApplicationCapabilityInformation.CdaIndicator.CDA_OVER_TC_ARQC_AAC;
import static digital.paynetics.phos.kernel.mastercard.misc.MastercardMessageIdentifier.ERROR_OTHER_CARD;
import static digital.paynetics.phos.kernel.mastercard.misc.MastercardMessageIdentifier.TRY_AGAIN;


/**
 * Encapsulates functionality for the Application Cryptogram stage (i.e. final stage)
 */
public class AcStageImpl implements AcStage {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(AcStageImpl.class);
    private final GenerateAcExecutor generateAcExecutor;
    private byte referenceControlParameter;
    private final TornTransactionLog tornTransactionLog;
    private final Template1Handler template1Handler;
    private final Template2Handler template2Handler;
    private final MessageStoreMc messageStore;
    private final PutDataProcessor putDataProcessor;
    private final TimeProvider timeProvider;


    @Inject
    public AcStageImpl(GenerateAcExecutor generateAcExecutor,
                       TornTransactionLog tornTransactionLog,
                       Template1Handler template1Handler,
                       Template2Handler template2Handler,
                       MessageStoreMc messageStore,
                       PutDataProcessor putDataProcessor, TimeProvider timeProvider) {
        this.generateAcExecutor = generateAcExecutor;
        this.tornTransactionLog = tornTransactionLog;
        this.template1Handler = template1Handler;
        this.template2Handler = template2Handler;
        this.messageStore = messageStore;
        this.putDataProcessor = putDataProcessor;
        this.timeProvider = timeProvider;
    }


    private static byte resolveReferenceControlParameter(boolean isOdaStatusCdaSet,
                                                         boolean isCdaFailed,
                                                         boolean isOnDeviceCvmSupportedCard,
                                                         boolean isOnDeviceCvmSupportedCardTerminal,
                                                         ApplicationCryptogramType requestedApplicationCryptogramType,
                                                         TlvMapReadOnly tlvDb) {

        byte ret;

        // GAC.20
        if (isOdaStatusCdaSet) {
            // GAC.21
            if (isCdaFailed) {
                // GAC.22
                if (isOnDeviceCvmSupportedCard && isOnDeviceCvmSupportedCardTerminal) {
                    // GAC.23
                    requestedApplicationCryptogramType = ApplicationCryptogramType.AAC;
                }

                ret = prepareReferenceControlParameter(requestedApplicationCryptogramType, false);
            } else {
                // GAC.24
                if (requestedApplicationCryptogramType == ApplicationCryptogramType.AAC) {
                    // GAC.25
                    if (tlvDb.isTagPresentAndNonEmpty(EmvTag.APPLICATION_CAPABILITIES_INFORMATION)) {
                        ApplicationCapabilityInformation aci = ApplicationCapabilityInformation.
                                fromBytes(tlvDb.get(EmvTag.APPLICATION_CAPABILITIES_INFORMATION).getValueBytes());
                        if (aci.getCdaIndicator() == CDA_OVER_TC_ARQC_AAC) {
                            // GAC.26
                            ret = prepareReferenceControlParameter(requestedApplicationCryptogramType, true);
                        } else {
                            ret = prepareReferenceControlParameter(requestedApplicationCryptogramType, false);
                        }
                    } else {
                        ret = prepareReferenceControlParameter(requestedApplicationCryptogramType, false);
                    }
                } else {
                    ret = prepareReferenceControlParameter(requestedApplicationCryptogramType, true);
                }
            }
        } else {
            // GAC.22 again
            if (isOnDeviceCvmSupportedCard && isOnDeviceCvmSupportedCardTerminal) {
                // GAC.23
                requestedApplicationCryptogramType = ApplicationCryptogramType.AAC;
            }
            ret = prepareReferenceControlParameter(requestedApplicationCryptogramType, false);
        }

        return ret;
    }


    private static byte prepareReferenceControlParameter(ApplicationCryptogramType cryptogramType, boolean requestCda) {
        byte ret;

        switch (cryptogramType) {
            case AAC:
                ret = (byte) 0b00000000;
                break;
            case TC:
                ret = (byte) 0b01000000;
                break;
            case ARQC:
                ret = (byte) 0b10000000;
                break;
            case UNKNOWN:
                throw new IllegalStateException("Unexpected AC type");
            default:
                throw new IllegalStateException("Unexpected AC type");
        }

        if (requestCda) {
            ret |= (byte) 0b00010000;
        }

        return ret;
    }


    private static Outcome cardDataError(TlvDb tlvDb, boolean isEmvMode) {
        MastercardErrorIndication ei = MastercardErrorIndication.
                createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_ERROR, ERROR_OTHER_CARD);

        return Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));
    }


    public static Outcome validResponse(ApplicationCryptogramType actualApplicationCryptogramType,
                                        Outcome.Cvm cvm,
                                        boolean receiptRequired,
                                        TlvDb tlvDb,
                                        Transceiver transceiver,
                                        McTlvList deTagsToWriteYetAfterGenAc,
                                        int messageHoldTime,
                                        MessageStoreMc messageStore,
                                        PutDataProcessor putDataProcessor,
                                        TerminalCapabilities13 terminalCapabilities13
    ) {

        // S910.70 - will do later because we need the outcome type to create the builder, see bellow

        // S910.71
        Outcome.Builder b;

        boolean secondTapNeeded = false;
        UserInterfaceRequest userInterfaceRequestMsg;

        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.POS_CARDHOLDER_INTERACTION_INFORMATION) &&
                PosCardHolderInteractionInformation.
                        isSecondTapNeeded(tlvDb.get(EmvTag.POS_CARDHOLDER_INTERACTION_INFORMATION))) {

            logger.debug("second tap needed");
            secondTapNeeded = true;
            // S910.72
            b = new Outcome.Builder(Outcome.Type.END_APPLICATION);
            b.start(Outcome.Start.B);

            userInterfaceRequestMsg = PciiMessageTable.getUir(
                    tlvDb.get(EmvTag.POS_CARDHOLDER_INTERACTION_INFORMATION));

            // S910.78
//            logger.debug("MSG: {}", userInterfaceRequestMsg);
//            messageStore.add(userInterfaceRequestMsg);

            UserInterfaceRequest userInterfaceRequestOut = new UserInterfaceRequest(userInterfaceRequestMsg.getMessage(),
                    ContactlessTransactionStatus.READY_TO_READ,
                    0, null, null, 0, null);
            b.uiRequestOnRestart(userInterfaceRequestOut);
            b.cvm(cvm);
        } else {
            // S910.74
            if (actualApplicationCryptogramType == ApplicationCryptogramType.TC) {
                logger.error("Kernel requests APPROVED (TC cryptogram)");
                // this should never happen in our real app because we are online only
                b = new Outcome.Builder(Outcome.Type.APPROVED);

                UserInterfaceRequest.ValueQualifier valueQualifier = null;
                int value = 0;
                Currency currency = null;

                // S910.75
                if (tlvDb.isTagPresentAndNonEmpty(EmvTag.BALANCE_READ_AFTER_GEN_AC)) {

                    Optional<Currency> cO;
                    try {
                        valueQualifier = UserInterfaceRequest.ValueQualifier.BALANCE;
                        value = tlvDb.get(EmvTag.BALANCE_READ_AFTER_GEN_AC).getValueAsBcdInt();
                        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.APPLICATION_CURRENCY_CODE)) {
                            cO = Currency.find(tlvDb.get(EmvTag.APPLICATION_CURRENCY_CODE).getValueAsBcdInt());
                            if (!cO.isPresent()) {
                                return Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(true, tlvDb, null));
                            }
                            currency = cO.get();
                        }
                    } catch (TlvException e) {
                        logger.error(e.getMessage());
                        return Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(true, tlvDb, null));
                    }
                }

                if (cvm == Outcome.Cvm.OBTAIN_SIGNATURE) {
                    userInterfaceRequestMsg = new UserInterfaceRequest(StandardMessages.APPROVED_SIGN,
                            ContactlessTransactionStatus.NOT_READY,
                            messageHoldTime,
                            null,
                            valueQualifier,
                            value,
                            currency);
                } else {
                    userInterfaceRequestMsg = new UserInterfaceRequest(StandardMessages.APPROVED,
                            ContactlessTransactionStatus.NOT_READY,
                            messageHoldTime,
                            null,
                            valueQualifier,
                            value,
                            currency);
                }

                b.cvm(cvm);
            } else if (actualApplicationCryptogramType == ApplicationCryptogramType.ARQC) {
                b = new Outcome.Builder(Outcome.Type.ONLINE_REQUEST);

                Optional<Tlv> tlvLangPref = tlvDb.getAsOptional(EmvTag.LANGUAGE_PREFERENCE);
                String langPref = null;
                if (tlvLangPref.isPresent()) {
                    langPref = ByteUtils.toHexString(tlvLangPref.get().getValueBytes());
                }

                userInterfaceRequestMsg = new UserInterfaceRequest(StandardMessages.AUTHORIZING,
                        ContactlessTransactionStatus.NOT_READY,
                        0,
                        langPref,
                        null,
                        0,
                        null);
                b.cvm(cvm);
            } else {
                Tlv ttTlv = tlvDb.get(EmvTag.TRANSACTION_TYPE);

                TransactionType tt = TransactionType.valueOf(ttTlv.getValueBytes()[0]);

                if (tt == TransactionType.PURCHASE || tt == TransactionType.CASH_ADVANCE ||
                        tt == TransactionType.CASH_DISBURSEMENT || tt == TransactionType.CASHBACK) {

                    if (tlvDb.isTagPresentAndNonEmpty(EmvTag.VISA_FORM_FACTOR_INDICATOR__MS_THIRD_PARTY_DATA)) {
                        logger.debug("Third party data: {}",
                                ByteUtils.toHexString(tlvDb.get(EmvTag.VISA_FORM_FACTOR_INDICATOR__MS_THIRD_PARTY_DATA).getValueBytes()));

                        ThirdPartyData tpd = ThirdPartyData.fromBytes(
                                tlvDb.get(EmvTag.VISA_FORM_FACTOR_INDICATOR__MS_THIRD_PARTY_DATA).getValueBytes());

                        if ((ByteUtils.isByteArrayZeros(ByteUtils.byteArrayAnd(tpd.getUniqueIdentifier(), new byte[]{(byte) 0x80, 0}))
                                && (tpd.getDeviceType() == null || !tpd.getDeviceType().equals("3030"))) ||
                                !terminalCapabilities13.isIcWithContactsSupported()) {

                            userInterfaceRequestMsg = new UserInterfaceRequest(StandardMessages.NOT_AUTHORIZED,
                                    ContactlessTransactionStatus.NOT_READY,
                                    messageHoldTime,
                                    null,
                                    null,
                                    0,
                                    null);

                            b = new Outcome.Builder(Outcome.Type.DECLINED);
                            b.cvm(cvm);
                        } else {
                            userInterfaceRequestMsg = new UserInterfaceRequest(StandardMessages.INSERT_CARD,
                                    ContactlessTransactionStatus.NOT_READY,
                                    messageHoldTime,
                                    null,
                                    null,
                                    0,
                                    null);

                            b = new Outcome.Builder(Outcome.Type.TRY_ANOTHER_INTERFACE);
                            b.cvm(cvm);
                        }
                    } else {
                        logger.debug("No Third party data");
                        if (!terminalCapabilities13.isIcWithContactsSupported()) {
                            userInterfaceRequestMsg = new UserInterfaceRequest(StandardMessages.NOT_AUTHORIZED,
                                    ContactlessTransactionStatus.NOT_READY,
                                    messageHoldTime,
                                    null,
                                    null,
                                    0,
                                    null);

                            b = new Outcome.Builder(Outcome.Type.DECLINED);
                            b.cvm(cvm);
                        } else {
                            userInterfaceRequestMsg = new UserInterfaceRequest(StandardMessages.INSERT_CARD,
                                    ContactlessTransactionStatus.NOT_READY,
                                    messageHoldTime,
                                    null,
                                    null,
                                    0,
                                    null);

                            b = new Outcome.Builder(Outcome.Type.TRY_ANOTHER_INTERFACE);
                            b.cvm(cvm);
                        }
                    }
                } else {
                    userInterfaceRequestMsg = new UserInterfaceRequest(StandardMessages.CLEAR_DISPLAY,
                            ContactlessTransactionStatus.NOT_READY,
                            0,
                            null,
                            null,
                            0,
                            null);
                    b = new Outcome.Builder(Outcome.Type.END_APPLICATION);
                }
            }


            b.uiRequestOnOutcome(userInterfaceRequestMsg);
        }

        if (receiptRequired) {
            b.receiptPreference(Outcome.ReceiptPreference.YES);
        }
        // S910.76
        if (!deTagsToWriteYetAfterGenAc.isEmpty()) {
            try {
                if (putDataProcessor.processPutData(transceiver, deTagsToWriteYetAfterGenAc)) {
                    // S15.9
                    tlvDb.updateOrAddKernel(new Tlv(EmvTag.POST_GEN_AC_PUT_DATA_STATUS, 1, new byte[]{(byte) 0x80}));
                }
            } catch (IOException | NfcConnectionLostException e) {
                logger.warn("IO Error while doing PUT DATA: {}", e.getMessage());
                // do nothing, we just continue as per specs (L1RSP path)
            }

            // S15.9.1
            if (secondTapNeeded) {
                // S15.10
                UserInterfaceRequest uiReqMsg = new UserInterfaceRequest(StandardMessages.SEE_PHONE_FOR_INSTRUCTIONS,
                        ContactlessTransactionStatus.CARD_READ_SUCCESSFULLY,
                        messageHoldTime,
                        null, null, 0, null
                );

                logger.debug("MSG: {}", uiReqMsg);
                messageStore.add(uiReqMsg);
            } else {
                // S15.12
                UserInterfaceRequest uiReqMsg = new UserInterfaceRequest(StandardMessages.CLEAR_DISPLAY,
                        ContactlessTransactionStatus.CARD_READ_SUCCESSFULLY,
                        0,
                        null, null, 0, null
                );

                logger.debug("MSG: {}", uiReqMsg);
                messageStore.add(uiReqMsg);
            }
        } else {
            // S910.78.1
            if (secondTapNeeded) {
                // S910.79
                logger.debug("MSG: {}", userInterfaceRequestMsg);
                messageStore.add(userInterfaceRequestMsg);
            }
        }
        // S910.81
        b.discretionaryData(MastercardKernel.buildDiscretionaryData(true, tlvDb, null));
        // S910.70
        b.dataRecord(MastercardKernel.buildDataRecordEmv(tlvDb.asUnencrypted()));
        return b.build();
    }


    public static Outcome invalidResponse1(TlvDb tlvDb, boolean idsStatusWriteSet, MastercardErrorIndication ei) {
        // S910.50

        Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);

        // S910.51
        if (idsStatusWriteSet) {
            // S910.52
            b.dataRecord(MastercardKernel.buildDataRecordEmv(tlvDb.asUnencrypted()));
        }

        // S910.53
        UserInterfaceRequest uiReq = new UserInterfaceRequest(StandardMessages.TRY_ANOTHER_CARD,
                ContactlessTransactionStatus.NOT_READY,
                13,
                null,
                null,
                0,
                null);
        b.uiRequestOnOutcome(uiReq);
        b.removalTimeout(0);
        b.discretionaryData(MastercardKernel.buildDiscretionaryData(true, tlvDb, ei));

        return b.build();
    }


    public static Outcome invalidResponse2(TlvDb tlvDb, MastercardErrorIndication ei) {
        return Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(true, tlvDb, ei));
    }


    /**
     * Preparing DSDOL as per 4.1.4
     *
     * @param source
     * @param dolList
     * @return
     */
    public byte[] prepareDsDol(TlvMapReadOnly source, List<TagAndLength> dolList) {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            for (int i = 0; i < dolList.size(); i++) {
                TagAndLength tal = dolList.get(i);
                if (source.isTagPresentAndNonEmpty(tal.getTag())) {
                    Tlv tlv = source.get(tal.getTag());
                    if (i == dolList.size() - 1) { // is last entry
                        if (tal.getLength() > tlv.getValueBytes().length) {
                            out.write(tlv.getValueBytes());
                        } else {
                            out.write(ByteUtils.fitDolData(tal, tlv.getValueBytes()));
                            logger.debug("Preparing DSDOL, added: {} {}", tal.getTag().getName(), ByteUtils.toHexString(tlv.getValueBytes()));
                        }
                    } else {
                        out.write(ByteUtils.fitDolData(tal, tlv.getValueBytes()));
                        logger.debug("Preparing DSDOL, added: {} {}", tal.getTag().getName(), ByteUtils.toHexString(tlv.getValueBytes()));
                    }
                } else {
                    logger.warn("Preparing DSDOL, missing or empty tag: {} ({})", tal.getTag().getName(),
                            ByteUtils.toHexString(tal.getTag().getTagBytes()));
                    out.write(new byte[tal.getLength()]);
                }
            }

            return out.toByteArray();
        } catch (IOException e) {
            // cannot happen
            throw new RuntimeException(e);
        }
    }


    public static Outcome cdaMode(TlvDb tlvDb,
                                  Optional<CaPublicKeyDb> caPublicKeyDbO,
                                  CrlRid crlRid, byte[] cid, byte[] signedDynamicDataRaw,
                                  byte[] pdolPrepared,
                                  byte[] cdolPrepared,
                                  List<Tlv> genAcTlvs,
                                  Outcome.Cvm cvm,
                                  boolean receiptRequired,
                                  TransactionTimestamp ts,
                                  byte[] staticDataToBeAuthenticated,
                                  boolean haveIds,
                                  boolean idsVersion2,
                                  boolean haveRrp,
                                  Transceiver transceiver,
                                  McTlvList deTagsToWriteYetAfterGenAc,
                                  int messageHoldTime,
                                  IdsStatus idsStatus,
                                  DsSummaryStatus dsSummaryStatus,
                                  MessageStoreMc messageStore,
                                  PutDataProcessor putDataProcessor,
                                  TerminalVerificationResults terminalVerificationResults,
                                  TerminalCapabilities13 terminalCapabilities13) {

        byte[] pdolData;
        try {
            pdolData = TlvUtils.getNextTlv(pdolPrepared).getValueBytes();
        } catch (TlvException e) {
            throw new AssertionError("Cannot happen because we created that value");
        }

        Optional<SignedDynamicApplicationData> signedDynamicApplicationDataO = verifySignedDynamicApplicationData(tlvDb,
                caPublicKeyDbO, crlRid, ts, staticDataToBeAuthenticated, signedDynamicDataRaw, haveIds, idsVersion2,
                haveRrp, cid, pdolData, cdolPrepared, genAcTlvs);

        if (!signedDynamicApplicationDataO.isPresent()) {
            return camFailed(tlvDb, terminalVerificationResults, idsStatus.isWrite());
        }

        SignedDynamicApplicationData signedDynamicData = signedDynamicApplicationDataO.get();

        Tlv tlvIccDynamicNumber = new Tlv(EmvTag.ICC_DYNAMIC_NUMBER, signedDynamicData.getIccDynamicNumber().length,
                signedDynamicData.getIccDynamicNumber());
        tlvDb.addKernel(tlvIccDynamicNumber);

        Tlv tlvApplicationCryptogram = new Tlv(EmvTag.APP_CRYPTOGRAM,
                signedDynamicData.getApplicationCryptogram().length,
                signedDynamicData.getApplicationCryptogram());
        tlvDb.addKernel(tlvApplicationCryptogram);

        // S910.2
        if (idsStatus.isRead()) {
            // S910.2.2
            if (haveRrp) {
                // S910.3.1
                if (signedDynamicData.getDsSummary2() == null || signedDynamicData.getDsSummary3() == null) {
                    return camFailed(tlvDb, terminalVerificationResults, idsStatus.isWrite());
                }
                tlvDb.updateOrAddKernel(new Tlv(EmvTag.DS_SUMMARY_2,
                        signedDynamicData.getDsSummary2().length,
                        signedDynamicData.getDsSummary2()));
                tlvDb.updateOrAddKernel(new Tlv(EmvTag.DS_SUMMARY_3,
                        signedDynamicData.getDsSummary3().length,
                        signedDynamicData.getDsSummary3()));

                Optional<Outcome> rrpRez = checkRrp(tlvDb, signedDynamicData, terminalVerificationResults, idsStatus.isWrite());
                if (rrpRez.isPresent()) {
                    return rrpRez.get();
                }
            } else {
                // S910.3
                if (signedDynamicData.getDsSummary2() != null) {
                    tlvDb.updateOrAddKernel(new Tlv(EmvTag.DS_SUMMARY_2,
                            signedDynamicData.getDsSummary2().length,
                            signedDynamicData.getDsSummary2()));
                }


                if (signedDynamicData.getDsSummary3() != null) {
                    tlvDb.updateOrAddKernel(new Tlv(EmvTag.DS_SUMMARY_3,
                            signedDynamicData.getDsSummary3().length,
                            signedDynamicData.getDsSummary3()));

                }
            }

            // S910.5 - since we reached here, we are OK

            // S910.8
            if (signedDynamicData.getDsSummary2() != null) {
                // S910.10
                if (Arrays.equals(tlvDb.get(EmvTag.DS_SUMMARY_1).getValueBytes(), signedDynamicData.getDsSummary2())) {
                    // S910.12
                    dsSummaryStatus.setSuccessfulRead(true);
                    tlvDb.updateOrAddKernel(dsSummaryStatus.toTlv());

                    // S910.13
                    if (idsStatus.isWrite()) {
                        // S910.14
                        if (signedDynamicData.getDsSummary3() != null) {
                            // S910.16
                            if (!Arrays.equals(signedDynamicData.getDsSummary2(), signedDynamicData.getDsSummary3())) {
                                // S910.17
                                dsSummaryStatus.setSuccessfulWrite(true);
                                tlvDb.updateOrAddKernel(dsSummaryStatus.toTlv());

                                // from here we go to CDA successful
                            } else {
                                DsOdsInfoForReader tmpDsInfo = DsOdsInfoForReader.fromByte(tlvDb.get(EmvTag.DS_ODS_INFO_FOR_READER).
                                        getValueBytes()[0]);

                                if (tmpDsInfo.isStopIfWriteFailed()) {
                                    MastercardErrorIndication ei = MastercardErrorIndication.
                                            createL2Error(MastercardErrorIndication.L2Error.IDS_WRITE_ERROR, ERROR_OTHER_CARD);
                                    return AcStageImpl.invalidResponse2(tlvDb, ei);
                                }
                            }
                        } else {
                            // S910.15
                            MastercardErrorIndication ei = MastercardErrorIndication.
                                    createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_MISSING, ERROR_OTHER_CARD);

                            return AcStageImpl.invalidResponse1(tlvDb, idsStatus.isWrite(), ei);
                        }
                    }
                } else {
                    // S910.11
                    logger.error("IDS_READ_ERROR S910.11");
                    MastercardErrorIndication ei = MastercardErrorIndication.
                            createL2Error(MastercardErrorIndication.L2Error.IDS_READ_ERROR, ERROR_OTHER_CARD);

                    return AcStageImpl.invalidResponse1(tlvDb, idsStatus.isWrite(), ei);
                }
            } else {
                // S910.9
                MastercardErrorIndication ei = MastercardErrorIndication.
                        createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_MISSING, ERROR_OTHER_CARD);

                return AcStageImpl.invalidResponse1(tlvDb, idsStatus.isWrite(), ei);
            }
        } else {
            // S910.2.1
            if (haveRrp) {
                // S910.4.1
                Optional<Outcome> rrpRez = checkRrp(tlvDb, signedDynamicData, terminalVerificationResults, idsStatus.isWrite());
                if (rrpRez.isPresent()) {
                    return rrpRez.get();
                }
            } else {
                // S910.4
                // empty, we added ICC_DYNAMIC_NUMBER and APP_CRYPTOGRAM above, after checking if sdad is valid
            }
        }


        logger.warn("CDA Successful");

        // we are done, gg
        ApplicationCryptogramType act = ApplicationCryptogramType.resolveType(signedDynamicData.getCryptogramInformationData());

        return validResponse(act, cvm, receiptRequired, tlvDb, transceiver, deTagsToWriteYetAfterGenAc, messageHoldTime,
                messageStore, putDataProcessor, terminalCapabilities13);
    }


    public static Outcome noCdaMode(TlvDb tlvDb,
                                    byte referenceControlParameter,
                                    Outcome.Cvm cvm,
                                    boolean receiptRequired,
                                    ApplicationCryptogramType requestedCryptogramType,
                                    int rrpMeasuredProcessingTime,
                                    int rrpCounter,
                                    Transceiver transceiver,
                                    McTlvList deTagsToWriteYetAfterGenAc,
                                    int messageHoldTime,
                                    MessageStoreMc messageStore,
                                    PutDataProcessor putDataProcessor,
                                    IdsStatus idsStatus,
                                    TerminalCapabilities13 terminalCapabilities13) {

        // S910.30
        if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.APP_CRYPTOGRAM)) {
            MastercardErrorIndication ei = MastercardErrorIndication.
                    createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_MISSING, ERROR_OTHER_CARD);

            return AcStageImpl.invalidResponse1(tlvDb, false, ei);
        }

        ApplicationCryptogramType actualApplicationCryptogramType =
                ApplicationCryptogramType.resolveType(
                        tlvDb.get(EmvTag.CRYPTOGRAM_INFORMATION_DATA).getValueBytes()[0]);

        // S910.32
        if (actualApplicationCryptogramType == ApplicationCryptogramType.AAC) {
            // S910.33
            if (idsStatus.isRead()) {
                // S910.37
                logger.warn("S910.33 yes ->  S910.37");
                MastercardErrorIndication ei = MastercardErrorIndication.
                        createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_ERROR, ERROR_OTHER_CARD);

                return AcStageImpl.invalidResponse1(tlvDb, idsStatus.isWrite(), ei);
            } else {
                // S910.35
                if (requestedCryptogramType == ApplicationCryptogramType.AAC) {
                    // S910.36
                    if (isCdaRequested(referenceControlParameter)) {
                        // S910.37
                        logger.warn("CDA requested but not performed");
                        MastercardErrorIndication ei = MastercardErrorIndication.
                                createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_ERROR, ERROR_OTHER_CARD);

                        return AcStageImpl.invalidResponse1(tlvDb, idsStatus.isWrite(), ei);
                    } else {
                        Outcome oc = AcStageImpl.validResponse(actualApplicationCryptogramType, cvm, receiptRequired, tlvDb, transceiver,
                                deTagsToWriteYetAfterGenAc, messageHoldTime, messageStore, putDataProcessor, terminalCapabilities13);
                        return oc;
                    }
                } else {
                    Outcome oc = AcStageImpl.validResponse(actualApplicationCryptogramType, cvm, receiptRequired, tlvDb, transceiver,
                            deTagsToWriteYetAfterGenAc, messageHoldTime, messageStore, putDataProcessor, terminalCapabilities13);
                    return oc;
                }
            }

        } else {
            // S910.34
            if (isCdaRequested(referenceControlParameter)) {
                // S910.37
                logger.warn("S910.34 yes -> S910.37");
                MastercardErrorIndication ei = MastercardErrorIndication.
                        createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_ERROR, ERROR_OTHER_CARD);

                return AcStageImpl.invalidResponse1(tlvDb, idsStatus.isWrite(), ei);
            } else {
                // S910.38
                if (rrpMeasuredProcessingTime > 0) { // if RRP is performed rrpMeasuredProcessingTime is always > 0
                    // S910.39
                    if (tlvDb.isTagPresentAndNonEmpty(EmvTag.TRACK_2_EQV_DATA)) {
                        Optional<SensitiveData> t2eqO = tlvDb.getTrack2Eqv();

                        String t2eq = ByteUtils.toHexString(t2eqO.get().getData()).toUpperCase();

                        int separatorPos = t2eq.indexOf("D");
                        if (separatorPos > 0 && t2eq.substring(separatorPos).length() > 6) {
                            String t2eqPref = t2eq.substring(0, separatorPos + 1 + 7);
                            String dd;
                            if (separatorPos <= 16) {
                                dd = "0000000000000";
                            } else {
                                dd = "0000000000";
                            }

                            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.CA_PUBLIC_KEY_INDEX_CARD)) {
                                byte keyIndex = tlvDb.get(EmvTag.CA_PUBLIC_KEY_INDEX_CARD).getValueBytes()[0];
                                if (keyIndex < 0x0a) {
                                    String keyIndexStr = ByteUtils.toHexString(new byte[]{keyIndex});
                                    dd = keyIndexStr.substring(1) + dd.substring(1);
                                }
                            }

                            dd = dd.substring(0, 1) + rrpCounter + dd.substring(2);
                            byte[] lsEntropy = Arrays.copyOfRange(tlvDb.get(EmvTag.DEVICE_RELAY_RESISTANCE_ENTROPY).getValueBytes(), 2, 4);
                            int lsEntropyInt = ByteUtils.byteArrayToInt(lsEntropy);
                            String lsEntropyStr = String.format("%05d", lsEntropyInt);

                            dd = dd.substring(0, 2) + lsEntropyStr + dd.substring(7);
                            int additionalOffset = 0;
                            if (separatorPos <= 16) {
                                additionalOffset = 3;
                                int lsbEntropyInt = ByteUtils.byteArrayToInt(
                                        new byte[]{tlvDb.get(EmvTag.DEVICE_RELAY_RESISTANCE_ENTROPY).getValueBytes()[1]});

                                String lsbEntropyStr = String.format("%03d", lsbEntropyInt);
                                dd = dd.substring(0, 7) + lsbEntropyStr + dd.substring(10);
                            }

                            int rrpMeasuredProcessingTimeMillis = rrpMeasuredProcessingTime / 10;
                            if (rrpMeasuredProcessingTimeMillis > 999) {
                                rrpMeasuredProcessingTimeMillis = 999;
                            }
                            String rrpMeasuredProcessingTimeMillisStr = String.format("%03d", rrpMeasuredProcessingTimeMillis);
                            dd = dd.substring(0, 7 + additionalOffset) + rrpMeasuredProcessingTimeMillisStr;

                            String finalT2eq = t2eqPref + dd;
                            if (finalT2eq.length() % 2 != 0) {
                                finalT2eq += "F";
                            }
                            byte[] finalT2eqByte = ByteUtils.fromString(finalT2eq);
                            tlvDb.updateOrAddKernel(new Tlv(EmvTag.TRACK_2_EQV_DATA, finalT2eqByte.length, finalT2eqByte));
                        }
                    } else {
                        logger.error("Cannot find field separator in Track 2 eqv data for S910.38");
                    }
                }

                // S910.70
                Outcome oc = AcStageImpl.validResponse(actualApplicationCryptogramType, cvm, receiptRequired, tlvDb, transceiver,
                        deTagsToWriteYetAfterGenAc, messageHoldTime, messageStore, putDataProcessor, terminalCapabilities13);
                return oc;
            }
        }
    }


    private static Outcome camFailed(TlvDb tlvDb,
                                     TerminalVerificationResults terminalVerificationResults,
                                     final boolean idsStatusIsWrite) {

        // S910.7
        MastercardErrorIndication ei = MastercardErrorIndication.
                createL2Error(MastercardErrorIndication.L2Error.CAM_FAILED, ERROR_OTHER_CARD);

        // S910.7.1
        terminalVerificationResults.setCdaFailed(true);
        tlvDb.updateOrAddKernel(TvrUtil.asTlv(terminalVerificationResults));

        return invalidResponse1(tlvDb, idsStatusIsWrite, ei);
    }


    private static Optional<Outcome> checkRrp(TlvDb tlvDb,
                                              SignedDynamicApplicationData signedDynamicData,
                                              TerminalVerificationResults terminalVerificationResults,
                                              final boolean idsStatusIsWrite

    ) {
        if (!Arrays.equals(tlvDb.get(EmvTag.TERMINAL_RELAY_RESISTANCE_ENTROPY).getValueBytes(),
                signedDynamicData.getTerminalRelayResistanceEntropy())) {

            logger.warn("Wrong TERMINAL_RELAY_RESISTANCE_ENTROPY");
            return Optional.of(camFailed(tlvDb, terminalVerificationResults, idsStatusIsWrite));
        }

        if (!Arrays.equals(tlvDb.get(EmvTag.DEVICE_RELAY_RESISTANCE_ENTROPY).getValueBytes(),
                signedDynamicData.getDeviceRelayResistanceEntropy())) {

            logger.warn("Wrong DEVICE_RELAY_RESISTANCE_ENTROPY");
            return Optional.of(camFailed(tlvDb, terminalVerificationResults, idsStatusIsWrite));
        }

        if (!Arrays.equals(tlvDb.get(EmvTag.MIN_TIME_FOR_PROCESSING_RELAY_RESISTANCE_APDU).getValueBytes(),
                signedDynamicData.getMinTimeForProcessingRelayResistanceApdu())) {

            logger.warn("Wrong MIN_TIME_FOR_PROCESSING_RELAY_RESISTANCE_APDU");
            return Optional.of(camFailed(tlvDb, terminalVerificationResults, idsStatusIsWrite));
        }

        if (!Arrays.equals(tlvDb.get(EmvTag.MAX_TIME_FOR_PROCESSING_RELAY_RESISTANCE_APDU).getValueBytes(),
                signedDynamicData.getMaxTimeForProcessingRelayResistanceApdu())) {

            logger.warn("Wrong MAX_TIME_FOR_PROCESSING_RELAY_RESISTANCE_APDU");
            return Optional.of(camFailed(tlvDb, terminalVerificationResults, idsStatusIsWrite));
        }

        if (!Arrays.equals(tlvDb.get(EmvTag.DEVICE_ESTIMATED_TRANSMISSION_TIME_FOR_RELAY_RESISTANCE_RAPDU).getValueBytes(),
                signedDynamicData.getDeviceEstimatedTransmissionTimeForRelayResistanceRapdu())) {

            logger.warn("Wrong DEVICE_ESTIMATED_TRANSMISSION_TIME_FOR_RELAY_RESISTANCE_RAPDU");
            return Optional.of(camFailed(tlvDb, terminalVerificationResults, idsStatusIsWrite));
        }

        return Optional.empty();
    }


    private static boolean verifySdad(SignedDynamicApplicationData signedDynamicData,
                                      TlvDb tlvDb,
                                      byte[] cid,
                                      byte[] pdolData,
                                      byte[] cdolPrepared,
                                      List<Tlv> genAcTlvs
    ) {
        // Book 2, 6.6.2, 6
        if (signedDynamicData.getCryptogramInformationData() != cid[0]) {
            logger.warn("Cryptogram Information Data different");
            return false;
        }

        // Book 2, 6.6.2, 7-9
        if (!signedDynamicData.checkHashValid(tlvDb.get(EmvTag.UNPREDICTABLE_NUMBER).getValueBytes())) {
            logger.warn("Wrong hash");
            return false;
        }

        // Book 2, 6.6.2, 10
        ByteArrayOutputStream bis = new ByteArrayOutputStream();

        bis.write(pdolData, 0, pdolData.length);
        bis.write(cdolPrepared, 0, cdolPrepared.length);
        for (Tlv t : genAcTlvs) {
            if (t.getTag() != EmvTag.SIGNED_DYNAMIC_APPLICATION_DATA) {
                bis.write(t.getTagBytes(), 0, t.getTagBytes().length);
                bis.write(t.getLength());
                bis.write(t.getValueBytes(), 0, t.getValueBytes().length);
            }
        }

        // Book 2, 6.6.2, 11
        byte[] actualTransactionDataHash = calculateSha1(bis.toByteArray());
        try {
            bis.close();
        } catch (IOException e) {
            // cannot happen
        }

        // Book 2, 6.6.2, 12
        logger.debug("actualTransactionDataHash: {}", ByteUtils.toHexString(actualTransactionDataHash));
        logger.debug("signedDynamicData hash: {}", ByteUtils.toHexString(signedDynamicData.getTransactionDataHash()));
        if (!Arrays.equals(actualTransactionDataHash, signedDynamicData.getTransactionDataHash())) {
            logger.warn("Wrong transaction data hash");
            return false;
        }

        return true;
    }


    private static Optional<SignedDynamicApplicationData> verifySignedDynamicApplicationData(TlvDb tlvDb,
                                                                                             Optional<CaPublicKeyDb> caPublicKeyDbO,
                                                                                             CrlRid crlRid,
                                                                                             TransactionTimestamp ts,
                                                                                             byte[] staticDataToBeAuthenticated,
                                                                                             byte[] signedDynamicDataRaw,
                                                                                             boolean haveIds,
                                                                                             boolean isIdsVersion2,
                                                                                             boolean haveRrp,
                                                                                             byte[] cid,
                                                                                             byte[] pdolData,
                                                                                             byte[] cdol1Prepared,
                                                                                             List<Tlv> genAcTlvs
    ) {

        Optional<IssuerPublicKeyCertificate> issuerPublicKeyCertificateO = retrieveIssuerPublicKeyCertificate(tlvDb,
                caPublicKeyDbO, crlRid, ts);

        if (!issuerPublicKeyCertificateO.isPresent()) {
            return Optional.empty();
        }

        Optional<CardPublicKeyCertificate2> cardPublicKeyCertO = retrieveCardPublicKeyCertificate(tlvDb,
                issuerPublicKeyCertificateO.get(),
                ts,
                staticDataToBeAuthenticated);
        if (!cardPublicKeyCertO.isPresent()) {
            return Optional.empty();
        }


        SignedDynamicApplicationData signedDynamicData;
        try {
            signedDynamicData = SignedDynamicApplicationData.fromBytes(signedDynamicDataRaw,
                    cardPublicKeyCertO.get().getPublicKey(), haveIds, isIdsVersion2, haveRrp);
        } catch (InvalidDynamicApplicationData e) {
            logger.warn("Failed parsing Signed Dynamic Data");
            cardPublicKeyCertO.get().purge();
            return Optional.empty();
        }

        cardPublicKeyCertO.get().purge();

        if (verifySdad(signedDynamicData, tlvDb, cid, pdolData, cdol1Prepared, genAcTlvs)) {
            return Optional.of(signedDynamicData);
        } else {
            return Optional.empty();
        }
    }


    private static boolean isCertificateExpired(byte[] certExpirationDate, TransactionTimestamp ts) {
        String certDateStr = ByteUtils.toHexString(certExpirationDate); // date is MMYY
        String certMonthStr = certDateStr.substring(0, 2);
        String certYearStr = certDateStr.substring(2, 4);

        int certMonth = Integer.parseInt(certMonthStr);
        int certYear = Integer.parseInt(certYearStr);

        if (certYear > 50) {
            certYear += 1900;
        } else {
            certYear += 2000;
        }

        DateTime dtCert1 = DateTime.forDateOnly(certYear, certMonth, 1);
        DateTime dtCert2 = DateTime.forDateOnly(certYear, certMonth, dtCert1.getNumDaysInMonth());

        DateTime compare = DateTime.forDateOnly(ts.getTs().getYear(), ts.getTs().getMonth(), ts.getTs().getDay());

        return compare.gt(dtCert2);
    }


    private static boolean isCdaRequested(byte referenceControlParameter) {
        BigInteger bi = BigInteger.valueOf(referenceControlParameter);
        return bi.testBit(4);
    }


    public static void balanceReadingAfterGenAc(TlvDb tlvDb, Transceiver transceiver) throws IOException {
        // BR1.2
        if (tlvDb.isTagPresent(EmvTag.BALANCE_READ_AFTER_GEN_AC)) {
            // BR1.3 & BR1.4
            try {
                ApduResponsePackage resp2 = GetDataUtil.executeGetData(transceiver, EmvTag.OFFLINE_ACCUMULATOR_BALANCE);
                // S16.8
                if (resp2.isSuccess()) {
                    // S16.9
                    if (resp2.getDataNoStatusBytes().length == 9) {
                        try {
                            Tlv tlvBalance = TlvUtils.getNextTlv(resp2.getData());
                            if (tlvBalance.getTag() == EmvTag.OFFLINE_ACCUMULATOR_BALANCE &&
                                    tlvBalance.getValueBytes().length == 6) {

                                tlvDb.updateOrAddKernel(new Tlv(EmvTag.BALANCE_READ_AFTER_GEN_AC,
                                        6,
                                        tlvBalance.getValueBytes()));
                            }
                        } catch (TlvException e) {
                            // do nothing
                        }
                    }
                }
                resp2.purgeData();
            } catch (NfcConnectionLostException e) {
                // do nothing
            }
        }
    }


    private static Optional<IssuerPublicKeyCertificate> retrieveIssuerPublicKeyCertificate(TlvDb tlvDb,
                                                                                           Optional<CaPublicKeyDb> caPublicKeyDbO,
                                                                                           CrlRid crlRid,
                                                                                           TransactionTimestamp ts) {
        // S910.1
        int caCertIndex = tlvDb.get(EmvTag.CA_PUBLIC_KEY_INDEX_CARD).getValueAsHexInt();

        if (!caPublicKeyDbO.isPresent()) {
            logger.warn("caPublicKeyDbO is empty");
            return Optional.empty();
        }

        Optional<CaPublicKeyData> caPublicKeyDataO = caPublicKeyDbO.get().getByIndex(caCertIndex);
        if (!caPublicKeyDataO.isPresent()) {
            logger.warn("Cannot find CaPublicKeyData");
            return Optional.empty();
        }

        CaPublicKeyData caPublicKeyData = caPublicKeyDataO.get();

        byte[] issuerPublicKeyCertRaw = tlvDb.get(EmvTag.ISSUER_PUBLIC_KEY_CERT).getValueBytes();
        byte[] issuerPublicKeyExponent = tlvDb.get(EmvTag.ISSUER_PUBLIC_KEY_EXPONENT).getValueBytes();
        byte[] issuerPublicKeyRemainder = null;
        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.ISSUER_PUBLIC_KEY_REMAINDER)) {
            issuerPublicKeyRemainder = tlvDb.get(EmvTag.ISSUER_PUBLIC_KEY_REMAINDER).getValueBytes();
        }


        if (issuerPublicKeyCertRaw.length != caPublicKeyData.getPublicKey().getModulus().length) {
            logger.warn("If the Issuer Public Key Certificate has a length different from the length\n" +
                    "of the Certification Authority Public Key Modulus. Book 2, 6.3 (1)");
            return Optional.empty();
        }

        IssuerPublicKeyCertificate issuerPublicKeyCert;
        try {
            issuerPublicKeyCert = IssuerPublicKeyCertificate.fromBytes(issuerPublicKeyCertRaw,
                    issuerPublicKeyRemainder,
                    issuerPublicKeyExponent, caPublicKeyData.getPublicKey());

            if (crlRid.isPresent(caCertIndex, issuerPublicKeyCert.getCertSerialNumber())) {
                logger.warn("certificate is present on Certificate Revocation List");
                return Optional.empty();
            }

            if (!issuerPublicKeyCert.isHashValid(caPublicKeyData.getPublicKey())) {
                logger.warn("Invalid hash for Issuer Public Cert. Book 2, 6.3 (7)");
                return Optional.empty();
            }

            Optional<SensitiveData> panSdO = tlvDb.getPan();
            char[] panCh = ByteUtils.toHexChars(panSdO.get().getData(), false);
            panSdO.get().purge();
            char[] iiCh = issuerPublicKeyCert.getIssuerIdentifier().toCharArray();
            char[] panStartCh = Arrays.copyOfRange(panCh, 0, iiCh.length);
            if (!Arrays.equals(panStartCh, iiCh)) {
                logger.warn("Issue identifier does not match PAN start. Book 2, 6.3 (8)");
                return Optional.empty();
            }

            ByteUtils.purge(iiCh);
            ByteUtils.purge(panStartCh);
            ByteUtils.purge(panCh);

            if (isCertificateExpired(issuerPublicKeyCert.getCertExpirationDate(), ts)) {
                logger.warn("Issue certificate expired. Book 2, 6.3 (9)");
                return Optional.empty();
            }

            if (issuerPublicKeyCert.getIssuerPublicKeyAlgorithmIndicator() != 1) {
                logger.warn("Issue public key algorithm not recognized. Book 2, 6.3 (10)");
                return Optional.empty();
            }

        } catch (CryptoException e) {
            logger.warn("Cannot retrieve issuer public cert {}", e.getMessage());
            return Optional.empty();
        }

        return Optional.of(issuerPublicKeyCert);
    }


    private static Optional<CardPublicKeyCertificate2> retrieveCardPublicKeyCertificate(TlvDb tlvDb,
                                                                                        IssuerPublicKeyCertificate issuerPublicKeyCert,
                                                                                        TransactionTimestamp ts,
                                                                                        byte[] staticDataToBeAuthenticated) {

        byte[] cardPublicKeyCertRaw = tlvDb.get(EmvTag.ICC_PUBLIC_KEY_CERT).getValueBytes();
        byte[] cardPublicKeyExponent = tlvDb.get(EmvTag.ICC_PUBLIC_KEY_EXPONENT).getValueBytes();
        byte[] cardPublicKeyRemainder = null;
        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.ICC_PUBLIC_KEY_REMAINDER)) {
            cardPublicKeyRemainder = tlvDb.get(EmvTag.ICC_PUBLIC_KEY_REMAINDER).getValueBytes();
        }

        if (cardPublicKeyCertRaw.length != issuerPublicKeyCert.getPublicKey().getModulus().length) {
            logger.warn("ICC Public Key Certificate has a length different from the length of\n" +
                    "            the Issuer Public Key Modulus. Book 2, 6.4 (1)");
            return Optional.empty();
        }

        CardPublicKeyCertificate2 cardPublicKeyCert;
        try {
            cardPublicKeyCert = CardPublicKeyCertificate2.fromBytes(cardPublicKeyCertRaw, cardPublicKeyRemainder,
                    cardPublicKeyExponent, issuerPublicKeyCert.getPublicKey());

            if (!cardPublicKeyCert.isHashValid(issuerPublicKeyCert.getPublicKey(), staticDataToBeAuthenticated)) {
                logger.warn("Invalid hash for ICC Public Cert. Book 2, 6.4 (7)");
                cardPublicKeyCert.purge();
                return Optional.empty();
            }

            Optional<SensitiveData> panSdO = tlvDb.getPan();


            byte[] pan1NoPadding = ByteUtils.stripPanPadding(panSdO.get().getData());
            byte[] pan2NoPadding = ByteUtils.stripPanPadding(cardPublicKeyCert.getPanRaw());

            if (!Arrays.equals(pan1NoPadding, pan2NoPadding)) {
                logger.warn("PAN from TLV does not match PAN in ICC public cert. Book 2, 6.3 (8)");
                panSdO.get().purge();
                ByteUtils.purge(pan1NoPadding);
                ByteUtils.purge(pan2NoPadding);
                return Optional.empty();
            }
            panSdO.get().purge();
            ByteUtils.purge(pan1NoPadding);
            ByteUtils.purge(pan2NoPadding);

            if (isCertificateExpired(cardPublicKeyCert.getCertExpirationDate(), ts)) {
                logger.warn("ICC certificate expired. Book 2, 6.4 (9)");
                return Optional.empty();
            }

            if (issuerPublicKeyCert.getIssuerPublicKeyAlgorithmIndicator() != 1) {
                logger.warn("ICC public key algorithm not recognized. Book 2, 6.4 (10)");
                return Optional.empty();
            }
        } catch (CryptoException e) {
            logger.warn("Cannot retrieve card public cert {}", e.getMessage());
            return Optional.empty();
        }

        return Optional.of(cardPublicKeyCert);
    }


    private static Tlv createDrdolRelatedData(TlvDb tlvDb) throws TlvException {
        List<TagAndLength> drdolList = DolParser.parse(tlvDb.get(EmvTag.DRDOL).getValueBytes());
        byte[] drdolData = prepareDrdolDol(tlvDb, drdolList);
        return new Tlv(EmvTag.DRDOL_RELATED_DATA, drdolData.length, drdolData);
    }


    public static Outcome processWithCreatingTornLogRecord(TlvDb tlvDb,
                                                           TornTransactionLog tornTransactionLog,
                                                           TimeProvider timeProvider) {
        // S9.11
        try {
            tlvDb.updateOrAddKernel(createDrdolRelatedData(tlvDb));
            Optional<SensitiveData> panSdO = tlvDb.getPan();

            SensitiveData panSd = panSdO.get();

            TornTransactionLogRecord rec = new TornTransactionLogRecord(tlvDb,
                    AcStage.computePanHash(panSd, tlvDb.getAsOptional(EmvTag.PAN_SEQUENCE_NUMBER)), timeProvider.getWallClockTime());

            // S9.13
            Optional<TornTransactionLogRecord> evictedO = tornTransactionLog.add(rec);
            if (evictedO.isPresent()) {
                Tlv tlvTorn = evictedO.get().toTlv();
                tlvDb.updateOrAddKernel(tlvTorn);
            }
            panSd.purge();


            // S9.14 & S9.15
            MastercardErrorIndication ei =
                    MastercardErrorIndication.createL1Error(MastercardErrorIndication.L1Error.TIME_OUT,
                            TRY_AGAIN);

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
        } catch (TlvException e1) {
            MastercardErrorIndication ei = MastercardErrorIndication.
                    createL2Error(MastercardErrorIndication.L2Error.PARSING_ERROR, ERROR_OTHER_CARD);
            return Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(true, tlvDb, ei));
        }
    }


    private static byte[] prepareDrdolDol(TlvDb tlvDb, List<TagAndLength> dolList) {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            for (TagAndLength tal : dolList) {

                if (tlvDb.isTagPresentAndNonEmpty(tal.getTag())) {
                    if (tal.getTag() == EmvTag.PAN) {
                        Optional<SensitiveData> sdO = tlvDb.getPan();
                        byte[] dataFinal;
                        byte[] data = sdO.get().getData();
                        if (data.length >= tal.getLength()) {
                            dataFinal = data;
                        } else {
                            char[] source = ByteUtils.toHexChars(data, false);
                            char[] target = new char[tal.getLength() * 2];
                            Arrays.fill(target, 'F');
                            System.arraycopy(source, 0, target, 0, source.length);
                            dataFinal = ByteUtils.fromString(new String(target));
                        }
                        out.write(ByteUtils.fitDolData(tal, dataFinal));
                        logger.debug("Preparing DOL, added: {} hidden", tal.getTag().getName());
                    } else {
                        Tlv tlv = tlvDb.get(tal.getTag());
                        out.write(ByteUtils.fitDolData(tal, tlv.getValueBytes()));
                        logger.debug("Preparing DOL, added: {} {}", tal.getTag().getName(), ByteUtils.toHexString(tlv.getValueBytes()));
                    }
                } else {
                    logger.warn("Preparing DOL, missing or empty tag: {} ({})", tal.getTag().getName(),
                            ByteUtils.toHexString(tal.getTag().getTagBytes()));
                    out.write(new byte[tal.getLength()]);
                }
            }

            return out.toByteArray();
        } catch (IOException e) {
            // cannot happen
            throw new RuntimeException(e);
        }
    }


    @Override
    public Outcome recoverAcRoute(Transceiver transceiver,
                                  TlvDb tlvDb,
                                  TerminalVerificationResults terminalVerificationResults,
                                  IdsStatus idsStatus,
                                  boolean isEmvMode,
                                  ApplicationCryptogramType requestedApplicationCryptogramType,
                                  ApplicationCapabilityInformation applicationCapabilitiesInformation,
                                  Rrp.RrpResult rrpRez,
                                  boolean isOdaStatusCdaSet,
                                  ApplicationInterchangeProfile applicationInterchangeProfile,
                                  boolean isDeviceCvmSupported,
                                  List<TagAndLength> cdol1,
                                  CrlRid crlRid,
                                  Outcome.Cvm cvm,
                                  boolean receiptRequired,
                                  Optional<CaPublicKeyDb> caPublicKeyDb,
                                  byte[] pdolData,
                                  TransactionTimestamp ts,
                                  byte[] staticDataToBeAuthenticated,
                                  McTlvList deTagsToWriteYetAfterGenAc,
                                  int messageHoldTime,
                                  DsSummaryStatus dsSummaryStatus,
                                  TornTransactionLogRecord tornTransactionLogRecord,
                                  boolean isSupportingBalanceReading,
                                  boolean haveIds,
                                  boolean isIdsVersion2,
                                  TerminalCapabilities13 terminalCapabilities13)
            throws IOException {

        TlvMap mapTornTransactionRecord = new TlvMapImpl(tornTransactionLogRecord.getTlvs());
        // S456.48
        tlvDb.updateOrAddKernel(mapTornTransactionRecord.get(EmvTag.DRDOL_RELATED_DATA));
        logger.debug("(nfc) RECOVER AC");
        ApduCommandPackage cmd = new ApduCommandPackage(ApduCommand.RECOVER_APPLICATION_CRYPTOGRAM,
                (byte) 0,
                (byte) 0,
                mapTornTransactionRecord.get(EmvTag.DRDOL_RELATED_DATA).getValueBytes(),
                0);


        boolean hasRrp = rrpRez != null && rrpRez.isOk();
        int rrpMeasuredProcessingTime = hasRrp ? rrpRez.getMeasuredProcessingTime() : 0;
        int rrpCounter = hasRrp ? rrpRez.getRrpCounter() : 0;

        try {
            ApduResponsePackage resp = transceiver.transceive(cmd);

            // S10.7
            if (resp.isSuccess()) {
                // S10.10
                tornTransactionLog.remove(tornTransactionLogRecord.getPanHash());

                // S10.11
                for (Tlv tlv : tornTransactionLogRecord.getTlvs()) {
                    if (tlv.getTag() == EmvTag.REFERENCE_CONTROL_PARAMETER) {
                        referenceControlParameter = tlv.getValueBytes()[0];
                    } else if (tlv.getTag() == EmvTag.IDS_STATUS) {
                        idsStatus = IdsStatus.fromByte(tlv.getValueBytes()[0]);
                        haveIds = idsStatus.isRead();
                    } else if (tlv.getTag() == EmvTag.TERMINAL_VERIFICATION_RESULTS) {
                        terminalVerificationResults = TvrUtil.fromBytes(tlv.getValueBytes());
                    } else if (tlv.getTag() == EmvTag.RRP_COUNTER) {
                        rrpCounter = tlv.getValueAsBcdInt();
                    }

                    tlvDb.updateOrAddKernel(tlv);
                }


                // S10.12
                boolean isParsingResultRecoverAcOk = false;
                List<Tlv> recAcTlvs = null;
                Tlv tlv = TlvUtils.getNextTlv(resp.getDataNoStatusBytes(), true);
                if (tlv.getTag() == EmvTag.RESPONSE_MESSAGE_TEMPLATE_2) {
                    recAcTlvs = template2Handler.handle(resp.getData());
                    resp.purgeData();
                    MastercardTags.checkInValidTemplate(recAcTlvs, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2);
                    // we need to check for empty tags here in order to potentially trigger parsing error
                    if (!MastercardTags.checkValidSizes(recAcTlvs)) {
                        MastercardErrorIndication ei = MastercardErrorIndication.
                                createL2Error(MastercardErrorIndication.L2Error.PARSING_ERROR, ERROR_OTHER_CARD);

                        return invalidResponse1(tlvDb, idsStatus.isWrite(), ei);
                    }

                    for (Tlv tlvTmp : recAcTlvs) {
                        tlvDb.updateOrAddRa(tlvTmp);
                    }
                    isParsingResultRecoverAcOk = true;
                }

                // S10.13
                if (isParsingResultRecoverAcOk) {
                    // S10.15
                    if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.CRYPTOGRAM_INFORMATION_DATA) ||
                            !tlvDb.isTagPresentAndNonEmpty(EmvTag.APP_TRANSACTION_COUNTER)) {

                        // S10.16
                        logger.warn("Missing card data: CRYPTOGRAM_INFORMATION_DATA or APP_TRANSACTION_COUNTER");

                        MastercardErrorIndication ei = MastercardErrorIndication.
                                createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_MISSING, ERROR_OTHER_CARD);

                        return invalidResponse1(tlvDb, idsStatus.isWrite(), ei);
                    }

                    // S10.17
                    byte[] cid = tlvDb.get(EmvTag.CRYPTOGRAM_INFORMATION_DATA).getValueBytes();
                    logger.debug("CID: {}", ByteUtils.toHexString(cid));

                    requestedApplicationCryptogramType = ApplicationCryptogramType.resolveType(referenceControlParameter);

                    if (!((((cid[0] & ((byte) 0xc0)) == (byte) 0x40) &&
                            requestedApplicationCryptogramType == ApplicationCryptogramType.TC) ||

                            (((cid[0] & ((byte) 0xc0)) == (byte) 0x80) &&
                                    (requestedApplicationCryptogramType == ApplicationCryptogramType.ARQC ||
                                            requestedApplicationCryptogramType == ApplicationCryptogramType.TC
                                    )) ||
                            ((cid[0] & ((byte) 0xc0)) == 0)
                    )) {
                        // S10.18
                        logger.warn("Invalid CRYPTOGRAM_INFORMATION_DATA S10.18");
                        MastercardErrorIndication ei = MastercardErrorIndication.
                                createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_ERROR, ERROR_OTHER_CARD);

                        return AcStageImpl.invalidResponse1(tlvDb, idsStatus.isWrite(), ei);
                    }


                    // S9.25
                    if (isSupportingBalanceReading) {
                        // BR1.2
                        if (tlvDb.isTagPresent(EmvTag.BALANCE_READ_AFTER_GEN_AC)) {
                            // BR1.3 & BR1.4
                            ApduResponsePackage resp2 = GetDataUtil.executeGetData(transceiver, EmvTag.OFFLINE_ACCUMULATOR_BALANCE);
                            // S16.8
                            if (resp2.isSuccess()) {
                                // S16.9
                                if (resp2.getDataNoStatusBytes().length == 9) {
                                    try {
                                        Tlv tlvBalance = TlvUtils.getNextTlv(resp2.getData());
                                        if (tlvBalance.getTag() == EmvTag.OFFLINE_ACCUMULATOR_BALANCE &&
                                                tlvBalance.getValueBytes().length == 6) {

                                            tlvDb.updateOrAddKernel(new Tlv(EmvTag.BALANCE_READ_AFTER_GEN_AC, 6, tlvBalance.getValueBytes()));
                                        }
                                    } catch (TlvException e) {
                                        // do nothing
                                    }
                                }
                            }
                            resp2.purgeData();
                        }
                    }


                    // S9.26
                    if (deTagsToWriteYetAfterGenAc.isEmpty()) {
                        // S9.27
                        UserInterfaceRequest ui = new UserInterfaceRequest(StandardMessages.CLEAR_DISPLAY,
                                ContactlessTransactionStatus.CARD_READ_SUCCESSFULLY,
                                0, null, null, 0, null);

                        messageStore.add(ui);
                    }

//                    byte[] cdol2Prepared = KernelUtils.prepareDol(tlvDb, cdol2);


                    TlvMap tmp = new TlvMapImpl();
                    tmp.addAll(tornTransactionLogRecord.getTlvs());
                    byte[] cdol1Prepared = tmp.get(EmvTag.CDOL1_RELATED_DATA).getValueBytes();
//                    byte[] cdol1Prepared = KernelUtils.prepareDol(tmp, cdol1);


                    // S9.28
                    if (tlvDb.isTagPresentAndNonEmpty(EmvTag.SIGNED_DYNAMIC_APPLICATION_DATA)) {
                        return cdaMode(tlvDb, caPublicKeyDb, crlRid, cid,
                                tlvDb.get(EmvTag.SIGNED_DYNAMIC_APPLICATION_DATA).getValueBytes(),
                                tlvDb.get(EmvTag.PDOL_RELATED_DATA).getValueBytes(),
                                cdol1Prepared,
                                recAcTlvs, cvm, receiptRequired, ts, staticDataToBeAuthenticated,
                                haveIds, isIdsVersion2,
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
                        return noCdaMode(tlvDb, referenceControlParameter, cvm, receiptRequired,
                                requestedApplicationCryptogramType, rrpMeasuredProcessingTime, rrpCounter, transceiver,
                                deTagsToWriteYetAfterGenAc,
                                messageHoldTime,
                                messageStore,
                                putDataProcessor,
                                idsStatus,
                                terminalCapabilities13);
                    }

                } else {
                    // S10.14
                    MastercardErrorIndication ei = MastercardErrorIndication.
                            createL2Error(MastercardErrorIndication.L2Error.PARSING_ERROR, ERROR_OTHER_CARD);

                    return invalidResponse1(tlvDb, idsStatus.isWrite(), ei);
                }
            } else {
                logger.debug("Gen AC 2 route");

                resp.purgeData();

                List<TagAndLength> dsDolList = new ArrayList<>();

                gac(idsStatus, terminalVerificationResults, tlvDb, isEmvMode, requestedApplicationCryptogramType, dsDolList,
                        applicationCapabilitiesInformation, isOdaStatusCdaSet, applicationInterchangeProfile, isDeviceCvmSupported);

                // S10.8 & S10.9
                return generateAc2Route(transceiver, tlvDb, terminalVerificationResults, idsStatus, isEmvMode,
                        requestedApplicationCryptogramType,
                        applicationCapabilitiesInformation, rrpRez, isOdaStatusCdaSet, applicationInterchangeProfile,
                        isDeviceCvmSupported, cdol1,
                        crlRid, cvm, receiptRequired, caPublicKeyDb,
                        tlvDb.get(EmvTag.PDOL_RELATED_DATA).getValueBytes(),
                        ts, staticDataToBeAuthenticated,
                        deTagsToWriteYetAfterGenAc, messageHoldTime, dsSummaryStatus, tornTransactionLogRecord,
                        terminalCapabilities13,
                        dsDolList);
            }

        } catch (IOException e) {
            logger.warn("Exception: {}", e.getMessage());
            throw e;
        } catch (EmvException | TlvException e) {
            logger.warn("Exception: {}", e.getMessage());
            MastercardErrorIndication ei = MastercardErrorIndication.
                    createL2Error(MastercardErrorIndication.L2Error.PARSING_ERROR, ERROR_OTHER_CARD);

            return invalidResponse1(tlvDb, idsStatus.isWrite(), ei);
        }

    }


    private Optional<Outcome> gac(IdsStatus idsStatus,
                                  TerminalVerificationResults terminalVerificationResults,
                                  TlvDb tlvDb,
                                  boolean isEmvMode,
                                  ApplicationCryptogramType requestedApplicationCryptogramType,
                                  List<TagAndLength> dsDolList,
                                  ApplicationCapabilityInformation applicationCapabilitiesInformation,
                                  boolean isOdaStatusCdaSet,
                                  ApplicationInterchangeProfile applicationInterchangeProfile,
                                  boolean isDeviceCvmSupported

    ) {
        // GAC.1
        if (idsStatus.isRead()) {
            // GAC.2
            if (!terminalVerificationResults.isCdaFailed()) {
                // GAC.3 & GAC.4
                if (tlvDb.isTagPresentAndNonEmpty(EmvTag.DS_ODS_INFO) && tlvDb.isTagPresentAndNonEmpty(EmvTag.DSDOL)) {
                    // GAC.5
                    if (!(tlvDb.isTagPresentAndNonEmpty(EmvTag.DS_AC_TYPE)
                            && tlvDb.isTagPresentAndNonEmpty(EmvTag.DS_ODS_INFO_FOR_READER)
                    )) {

                        // GAC.6
                        MastercardErrorIndication ei = MastercardErrorIndication.
                                createL2Error(MastercardErrorIndication.L2Error.IDS_DATA_ERROR, ERROR_OTHER_CARD);

                        return Optional.of(Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei)));
                    }

                    ApplicationCryptogramType dsAcType = ApplicationCryptogramType.resolveType(tlvDb.get(EmvTag.DS_AC_TYPE).
                            getValueBytes()[0]);


                    try {
                        List<TagAndLength> dsDolListTmp = DolParser.parse(tlvDb.get(EmvTag.DSDOL).getValueBytes());
                        dsDolList.addAll(dsDolListTmp);
                    } catch (TlvException e) {
                        logger.warn("Cannot parse DSDOL");
                        return Optional.of(cardDataError(tlvDb, isEmvMode));
                    }

                    // GAC.7
                    if (dsAcType == ApplicationCryptogramType.AAC || requestedApplicationCryptogramType == dsAcType ||
                            (dsAcType == ApplicationCryptogramType.ARQC &&
                                    requestedApplicationCryptogramType == ApplicationCryptogramType.TC)) {
                        // GAC.8
                        requestedApplicationCryptogramType = dsAcType;

                        idsWrite(tlvDb, requestedApplicationCryptogramType, applicationCapabilitiesInformation, dsDolList, idsStatus);
                    } else {
                        // GAC.9
                        DsOdsInfoForReader tmp = DsOdsInfoForReader.fromByte(tlvDb.get(EmvTag.DS_ODS_INFO_FOR_READER).
                                getValueBytes()[0]);

                        if ((requestedApplicationCryptogramType == ApplicationCryptogramType.AAC &&
                                tmp.isUsableForAac()) ||
                                (requestedApplicationCryptogramType == ApplicationCryptogramType.ARQC &&
                                        tmp.isUsableForArqc())) {

                            idsWrite(tlvDb, requestedApplicationCryptogramType, applicationCapabilitiesInformation, dsDolList, idsStatus);
                        } else {
                            // GAC.10
                            if (tmp.isStopIfNoOdsTerm()) {
                                // GAC.11
                                MastercardErrorIndication ei = MastercardErrorIndication.
                                        createL2Error(MastercardErrorIndication.L2Error.IDS_NO_MATCHING_AC, ERROR_OTHER_CARD);

                                return Optional.of(Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei)));
                            } else {
                                referenceControlParameter = prepareReferenceControlParameter(requestedApplicationCryptogramType, true);
                            }
                        }
                    }
                } else {
                    // GAC.27
                    referenceControlParameter = prepareReferenceControlParameter(requestedApplicationCryptogramType, true);
                }
            } else {
                referenceControlParameter = resolveReferenceControlParameter(isOdaStatusCdaSet,
                        terminalVerificationResults.isCdaFailed(),
                        applicationInterchangeProfile.isOnDeviceCvmSupported(),
                        isDeviceCvmSupported,
                        requestedApplicationCryptogramType,
                        tlvDb
                );
            }
        } else {
            referenceControlParameter = resolveReferenceControlParameter(isOdaStatusCdaSet,
                    terminalVerificationResults.isCdaFailed(),
                    applicationInterchangeProfile.isOnDeviceCvmSupported(),
                    isDeviceCvmSupported,
                    requestedApplicationCryptogramType,
                    tlvDb
            );
        }

        tlvDb.updateOrAddKernel(new Tlv(EmvTag.REFERENCE_CONTROL_PARAMETER, 1, new byte[]{referenceControlParameter}));
        return Optional.empty();
    }


    private void idsWrite(TlvDb tlvDb,
                          ApplicationCryptogramType requestedApplicationCryptogramType,
                          ApplicationCapabilityInformation applicationCapabilitiesInformation,
                          List<TagAndLength> dsDolList,
                          IdsStatus idsStatus) {


        boolean dsDigestHPresent = false;
        for (TagAndLength tl : dsDolList) {
            if (tl.getTag() == EmvTag.DS_DIGEST_H) {
                dsDigestHPresent = true;
                break;
            }
        }

        // GAC.40, GAC.41
        if (dsDigestHPresent && tlvDb.isTagPresent(EmvTag.DS_INPUT_TERM)) {
            byte[] dsDigestHBytes;
            byte[] dsOpId;

            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.DS_SLOT_MANAGEMENT_CONTROL)) {
                DsSlotManagementControl tmpDsSM = DsSlotManagementControl.
                        fromByte(tlvDb.get(EmvTag.DS_SLOT_MANAGEMENT_CONTROL).getValueBytes()[0]);

                byte tmpDsInfo = tlvDb.get(EmvTag.DS_ODS_INFO).getValueBytes()[0];
                boolean isVolatileSlotType = ((tmpDsInfo & 0b01000000) == 0b01000000);

                if (tmpDsSM.isPermanentSlotType() && isVolatileSlotType) {
                    dsOpId = new byte[8];
                } else {
                    dsOpId = tlvDb.get(EmvTag.DS_REQUESTED_OPERATOR_ID).getValueBytes();
                }
            } else {
                dsOpId = tlvDb.get(EmvTag.DS_REQUESTED_OPERATOR_ID).getValueBytes();
            }

            // GAC.42
            if (applicationCapabilitiesInformation.isDataStorageVersion1()) {
                // GAC.43
                dsDigestHBytes = Owhf.owhf2(tlvDb.get(EmvTag.DS_ID).getValueBytes(),
                        dsOpId,
                        tlvDb.get(EmvTag.DS_INPUT_TERM).getValueBytes());
            } else {
                // GAC.44
                dsDigestHBytes = Owhf.owhf2aes(tlvDb.get(EmvTag.DS_ID).getValueBytes(),
                        dsOpId,
                        tlvDb.get(EmvTag.DS_INPUT_TERM).getValueBytes());
            }

            tlvDb.updateOrAddKernel(new Tlv(EmvTag.DS_DIGEST_H, dsDigestHBytes.length, dsDigestHBytes));
        }

        // GAC.45
        referenceControlParameter = prepareReferenceControlParameter(requestedApplicationCryptogramType, true);

        logger.debug("IDS write := true");
        idsStatus.setWrite(true);
        tlvDb.updateOrAddKernel(idsStatus.toTlv());
    }


    @Override
    public Outcome generateAcRoute(Transceiver transceiver,
                                   TlvDb tlvDb,
                                   TerminalVerificationResults terminalVerificationResults,
                                   IdsStatus idsStatus,
                                   boolean isEmvMode,
                                   ApplicationCryptogramType requestedApplicationCryptogramType,
                                   ApplicationCapabilityInformation applicationCapabilitiesInformation,
                                   Rrp.RrpResult rrpRez,
                                   boolean isOdaStatusCdaSet,
                                   ApplicationInterchangeProfile applicationInterchangeProfile,
                                   boolean isDeviceCvmSupported,
                                   List<TagAndLength> cdol1,
                                   CrlRid crlRid,
                                   Outcome.Cvm cvm,
                                   boolean receiptRequired,
                                   Optional<CaPublicKeyDb> caPublicKeyDb,
                                   byte[] pdolData,
                                   TransactionTimestamp ts,
                                   byte[] staticDataToBeAuthenticated,
                                   McTlvList deTagsToWriteYetAfterGenAc,
                                   int messageHoldTime,
                                   DsSummaryStatus dsSummaryStatus,
                                   TerminalCapabilities13 terminalCapabilities13
    ) {
        // S456.45 - Preparing GENERATE AC command as in 7.6

        List<TagAndLength> dsDolList = new ArrayList<>();

        Optional<Outcome> ocErr = gac(idsStatus, terminalVerificationResults, tlvDb, isEmvMode, requestedApplicationCryptogramType, dsDolList,
                applicationCapabilitiesInformation, isOdaStatusCdaSet, applicationInterchangeProfile, isDeviceCvmSupported);

        if (ocErr.isPresent()) {
            return ocErr.get();
        }


        byte[] cdol1Prepared = MastercardDolPreparer.prepareDol(tlvDb, cdol1);

        byte[] dsDolPrepared = null;
        if (idsStatus.isWrite()) {
            dsDolPrepared = prepareDsDol(tlvDb, dsDolList);
        }

        tlvDb.updateOrAddKernel(new Tlv(EmvTag.CDOL1_RELATED_DATA, cdol1Prepared.length, cdol1Prepared));

        boolean hasRrp = rrpRez != null && rrpRez.isOk();

        Outcome oc = generateAcExecutor.execute(transceiver,
                cdol1Prepared,
                dsDolPrepared,
                referenceControlParameter,
                requestedApplicationCryptogramType,
                cvm,
                receiptRequired,
                tlvDb,
                caPublicKeyDb,
                crlRid,
                pdolData,
                ts,
                ByteUtils.toHexString(tlvDb.get(EmvTag.PAN).getValueBytes()),
                staticDataToBeAuthenticated,
                idsStatus.isRead(),
                applicationCapabilitiesInformation != null && applicationCapabilitiesInformation.isDataStorageVersion2(),
                hasRrp ? rrpRez.getMeasuredProcessingTime() : 0,
                hasRrp ? rrpRez.getRrpCounter() : 0,
                deTagsToWriteYetAfterGenAc,
                messageHoldTime,
                idsStatus,
                dsSummaryStatus,
                applicationCapabilitiesInformation != null && applicationCapabilitiesInformation.isSupportBalanceReading(),
                terminalVerificationResults,
                terminalCapabilities13
        );


        return oc;
    }


    private Outcome generateAc2Route(Transceiver transceiver,
                                     TlvDb tlvDb,
                                     TerminalVerificationResults terminalVerificationResults,
                                     IdsStatus idsStatus,
                                     boolean isEmvMode,
                                     ApplicationCryptogramType requestedApplicationCryptogramType,
                                     ApplicationCapabilityInformation applicationCapabilitiesInformation,
                                     Rrp.RrpResult rrpRez,
                                     boolean isOdaStatusCdaSet,
                                     ApplicationInterchangeProfile applicationInterchangeProfile,
                                     boolean isDeviceCvmSupported,
                                     List<TagAndLength> cdol2,
                                     CrlRid crlRid,
                                     Outcome.Cvm cvm,
                                     boolean receiptRequired,
                                     Optional<CaPublicKeyDb> caPublicKeyDb,
                                     byte[] pdolData,
                                     TransactionTimestamp ts,
                                     byte[] staticDataToBeAuthenticated,
                                     McTlvList deTagsToWriteYetAfterGenAc,
                                     int messageHoldTime,
                                     DsSummaryStatus dsSummaryStatus,
                                     TornTransactionLogRecord tornTransactionLogRecord,
                                     TerminalCapabilities13 terminalCapabilities13,
                                     List<TagAndLength> dsDolList) {


        byte[] cdol2prepared = MastercardDolPreparer.prepareDol(tlvDb, cdol2);

        tlvDb.updateOrAddKernel(new Tlv(EmvTag.CDOL1_RELATED_DATA, cdol2prepared.length, cdol2prepared));

        byte[] dolFinal;
        if (idsStatus.isWrite()) {
            byte[] dsDolPrepared = prepareDsDol(tlvDb, dsDolList);
            dolFinal = ByteUtils.byteArrayConcat(cdol2prepared, dsDolPrepared);
        } else {
            dolFinal = cdol2prepared;
        }

        // S10.8
        ApduCommandPackage cmd = new ApduCommandPackage(ApduCommand.GENERATE_APPLICATION_CRYPTOGRAM,
                referenceControlParameter,
                (byte) 0,
                dolFinal,
                0);
        try {
            // S10.9
            logger.debug("(nfc) GENERATE AC 2");
            ApduResponsePackage resp = transceiver.transceive(cmd);

            // S11.5
            tornTransactionLog.remove(tornTransactionLogRecord.getPanHash());

            // S11.6
            if (resp.isSuccess()) {
                // S11.8
                boolean isParsingResultGenAc2Ok = false;
                List<Tlv> genAc2Tlvs = null;
                Tlv tlv = TlvUtils.getNextTlv(resp.getDataNoStatusBytes(), true);
                if (tlv.getTag() == EmvTag.RESPONSE_MESSAGE_TEMPLATE_2) {
                    genAc2Tlvs = template2Handler.handle(resp.getData());
                    resp.purgeData();
                    MastercardTags.checkInValidTemplate(genAc2Tlvs, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2);
                    // we need to check for empty tags here in order to potentially trigger parsing error
                    if (!MastercardTags.checkValidSizes(genAc2Tlvs)) {
                        MastercardErrorIndication ei = MastercardErrorIndication.
                                createL2Error(MastercardErrorIndication.L2Error.PARSING_ERROR, ERROR_OTHER_CARD);

                        return invalidResponse1genAc2(tlvDb, idsStatus.isWrite(), ei, tornTransactionLogRecord);
                    }

                    for (Tlv tlvTmp : genAc2Tlvs) {
                        tlvDb.updateOrAddRa(tlvTmp);
                    }
                    isParsingResultGenAc2Ok = true;
                } else if (tlv.getTag() == EmvTag.RESPONSE_MESSAGE_TEMPLATE_1) {
                    genAc2Tlvs = template1Handler.handle(tlv.getValueBytes());
                    resp.purgeData();

                    // no check for valid template because it is not parseAndStoreCardResponse
                    for (Tlv tlvTmp : genAc2Tlvs) {
                        tlvDb.updateOrAddRa(tlvTmp);
                    }
                    isParsingResultGenAc2Ok = true;

                }

                if (!isParsingResultGenAc2Ok) {
                    // S11.10
                    MastercardErrorIndication ei = MastercardErrorIndication.
                            createL2Error(MastercardErrorIndication.L2Error.PARSING_ERROR, ERROR_OTHER_CARD);

                    return invalidResponse1genAc2(tlvDb, idsStatus.isWrite(), ei, tornTransactionLogRecord);
                }

                // S11.18
                if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.CRYPTOGRAM_INFORMATION_DATA) ||
                        !tlvDb.isTagPresentAndNonEmpty(EmvTag.APP_TRANSACTION_COUNTER)) {

                    // S11.19
                    logger.warn("Missing card data: CRYPTOGRAM_INFORMATION_DATA or APP_TRANSACTION_COUNTER");

                    MastercardErrorIndication ei = MastercardErrorIndication.
                            createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_MISSING, ERROR_OTHER_CARD);

                    return invalidResponse1genAc2(tlvDb, idsStatus.isWrite(), ei, tornTransactionLogRecord);
                }


                // S11.20
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
                    // S11.21
                    logger.warn("Invalid CRYPTOGRAM_INFORMATION_DATA S11.21");
                    MastercardErrorIndication ei = MastercardErrorIndication.
                            createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_ERROR, ERROR_OTHER_CARD);

                    return invalidResponse1genAc2(tlvDb, idsStatus.isWrite(), ei, tornTransactionLogRecord);
                }


                // S11.22
                if (applicationCapabilitiesInformation != null && applicationCapabilitiesInformation.isSupportBalanceReading()) {
                    balanceReadingAfterGenAc(tlvDb, transceiver);
                }

                // S11.23
                if (deTagsToWriteYetAfterGenAc.isEmpty()) {
                    // S11.24
                    UserInterfaceRequest ui = new UserInterfaceRequest(StandardMessages.CLEAR_DISPLAY,
                            ContactlessTransactionStatus.CARD_READ_SUCCESSFULLY,
                            0, null, null, 0, null);

                    messageStore.add(ui);
                }

                boolean hasRrp = rrpRez != null && rrpRez.isOk();
                int rrpMeasuredProcessingTime = hasRrp ? rrpRez.getMeasuredProcessingTime() : 0;
                int rrpCounter = hasRrp ? rrpRez.getRrpCounter() : 0;

                TlvMap tmpMap = new TlvMapImpl(tornTransactionLogRecord.getTlvs());


                if (tlvDb.isTagPresentAndNonEmpty(EmvTag.SIGNED_DYNAMIC_APPLICATION_DATA)) {
                    return cdaModeGenAc2(tlvDb, caPublicKeyDb, crlRid, cid,
                            tlvDb.get(EmvTag.SIGNED_DYNAMIC_APPLICATION_DATA).getValueBytes(),
                            pdolData,
                            cdol2prepared,
                            genAc2Tlvs, cvm, receiptRequired, ts, staticDataToBeAuthenticated,
                            applicationCapabilitiesInformation != null && applicationCapabilitiesInformation.isDataStorageVersion2(),
                            rrpMeasuredProcessingTime > 0,
                            transceiver,
                            deTagsToWriteYetAfterGenAc,
                            messageHoldTime,
                            idsStatus,
                            dsSummaryStatus,
                            messageStore,
                            putDataProcessor,
                            terminalVerificationResults,
                            tornTransactionLogRecord,
                            terminalCapabilities13);
                } else {
                    return noCdaMode(tlvDb, referenceControlParameter, cvm, receiptRequired,
                            requestedApplicationCryptogramType, rrpMeasuredProcessingTime, rrpCounter, transceiver,
                            deTagsToWriteYetAfterGenAc,
                            messageHoldTime,
                            messageStore,
                            putDataProcessor,
                            idsStatus,
                            terminalCapabilities13);
                }
            } else {
                byte[] rawSw = Arrays.copyOfRange(resp.getData(), resp.getData().length - 2, resp.getData().length);
                MastercardErrorIndication ei;
                if (resp.getStatusWord() == ApduResponseStatusWord.SW_UNKNOWN) {
                    ei = MastercardErrorIndication.createL2StatusBytesError(rawSw, ERROR_OTHER_CARD);
                } else {
                    ei = MastercardErrorIndication.createL2StatusBytesError(resp.getStatusWord().getStatusWord(), ERROR_OTHER_CARD);
                }
                resp.purgeData();
                return invalidResponse1genAc2(tlvDb, idsStatus.isWrite(), ei, tornTransactionLogRecord);
            }
        } catch (IOException | NfcConnectionLostException e) {
            // S11.11
            TlvMap map = new TlvMapImpl(tornTransactionLogRecord.getTlvs());
            Tlv tlvIdStatus = map.get(EmvTag.IDS_STATUS);
            BigInteger bi = BigInteger.valueOf(tlvIdStatus.getValueBytes()[0]);

            // S11.12
            if (!bi.testBit(7 - 1)) {
                tornTransactionLog.remove(tornTransactionLogRecord.getPanHash());
            }

            // S11.13
            return AcStageImpl.processWithCreatingTornLogRecord(tlvDb, tornTransactionLog, timeProvider);
        } catch (EmvException | TlvException e) {
            MastercardErrorIndication ei = MastercardErrorIndication.
                    createL2Error(MastercardErrorIndication.L2Error.PARSING_ERROR, ERROR_OTHER_CARD);

            return invalidResponse1genAc2(tlvDb, idsStatus.isWrite(), ei, tornTransactionLogRecord);
        }
    }


    private Outcome invalidResponse1genAc2(TlvDb tlvDb,
                                           boolean idsWrite,
                                           MastercardErrorIndication ei,
                                           TornTransactionLogRecord tornTransactionLogRecord) {

        // S11.90

        // S11.91
        TlvMap map = new TlvMapImpl(tornTransactionLogRecord.getTlvs());
        Tlv tlvIdStatus = map.get(EmvTag.IDS_STATUS);
        BigInteger bi = BigInteger.valueOf(tlvIdStatus.getValueBytes()[0]);

        if (bi.testBit(7 - 1)) {
            //S11.92
            tlvDb.updateOrAddKernel(tornTransactionLogRecord.toTlv());
        }

        Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);
        if (idsWrite) {
            b.dataRecord(MastercardKernel.buildDataRecordEmv(tlvDb.asUnencrypted()));
        }

        UserInterfaceRequest uiReq = new UserInterfaceRequest(StandardMessages.TRY_ANOTHER_CARD,
                ContactlessTransactionStatus.NOT_READY,
                13,
                null,
                null,
                0,
                null);
        b.uiRequestOnOutcome(uiReq);
        b.removalTimeout(0);
        b.discretionaryData(MastercardKernel.buildDiscretionaryData(true, tlvDb, ei));

        return b.build();
    }


    private Outcome cdaModeGenAc2(TlvDb tlvDb,
                                  Optional<CaPublicKeyDb> caPublicKeyDbO,
                                  CrlRid crlRid, byte[] cid, byte[] signedDynamicDataRaw,
                                  byte[] pdolPrepared,
                                  byte[] cdol1Prepared,
                                  List<Tlv> genAcTlvs,
                                  Outcome.Cvm cvm,
                                  boolean receiptRequired,
                                  TransactionTimestamp ts,
                                  byte[] staticDataToBeAuthenticated,
                                  boolean idsVersion2,
                                  boolean haveRrp,
                                  Transceiver transceiver,
                                  McTlvList deTagsToWriteYetAfterGenAc,
                                  int messageHoldTime,
                                  IdsStatus idsStatus,
                                  DsSummaryStatus dsSummaryStatus,
                                  MessageStoreMc messageStore,
                                  PutDataProcessor putDataProcessor,
                                  TerminalVerificationResults terminalVerificationResults,
                                  TornTransactionLogRecord tornTransactionLogRecord,
                                  TerminalCapabilities13 terminalCapabilities13) {

        byte[] pdolData;
        try {
            pdolData = TlvUtils.getNextTlv(pdolPrepared).getValueBytes();
        } catch (TlvException e) {
            throw new AssertionError("Cannot happen because we created that value");
        }

        Optional<SignedDynamicApplicationData> signedDynamicApplicationDataO = verifySignedDynamicApplicationData(tlvDb,
                caPublicKeyDbO, crlRid, ts, staticDataToBeAuthenticated, signedDynamicDataRaw, idsStatus.isRead(), idsVersion2,
                haveRrp, cid, pdolData, cdol1Prepared, genAcTlvs);

        if (!signedDynamicApplicationDataO.isPresent()) {
            return invalidResponse1genAc2CamFailed(tlvDb,
                    terminalVerificationResults,
                    idsStatus.isWrite(),
                    tornTransactionLogRecord);
        }

        SignedDynamicApplicationData signedDynamicData = signedDynamicApplicationDataO.get();

        ApplicationCryptogramType act = ApplicationCryptogramType.resolveType(signedDynamicData.getCryptogramInformationData());

        Tlv tlvIccDynamicNumber = new Tlv(EmvTag.ICC_DYNAMIC_NUMBER, signedDynamicData.getIccDynamicNumber().length,
                signedDynamicData.getIccDynamicNumber());
        tlvDb.addKernel(tlvIccDynamicNumber);

        Tlv tlvApplicationCryptogram = new Tlv(EmvTag.APP_CRYPTOGRAM,
                signedDynamicData.getApplicationCryptogram().length,
                signedDynamicData.getApplicationCryptogram());
        tlvDb.addKernel(tlvApplicationCryptogram);

        // S11.41
        if (idsStatus.isRead()) {
            // S11.41.2
            if (haveRrp) {
                // S11.42.1
                if (signedDynamicData.getDsSummary2() == null || signedDynamicData.getDsSummary3() == null) {
                    return invalidResponse1genAc2CamFailed(tlvDb,
                            terminalVerificationResults,
                            idsStatus.isWrite(),
                            tornTransactionLogRecord);
                }
                if (signedDynamicData.getDsSummary2() != null) {
                    tlvDb.updateOrAddKernel(new Tlv(EmvTag.DS_SUMMARY_2,
                            signedDynamicData.getDsSummary2().length,
                            signedDynamicData.getDsSummary2()));
                }

                if (signedDynamicData.getDsSummary3() != null) {
                    tlvDb.updateOrAddKernel(new Tlv(EmvTag.DS_SUMMARY_3,
                            signedDynamicData.getDsSummary3().length,
                            signedDynamicData.getDsSummary3()));

                }
            } else {
                // S11.42
                if (signedDynamicData.getDsSummary2() != null) {
                    tlvDb.updateOrAddKernel(new Tlv(EmvTag.DS_SUMMARY_2,
                            signedDynamicData.getDsSummary2().length,
                            signedDynamicData.getDsSummary2()));
                }


                if (signedDynamicData.getDsSummary3() != null) {
                    tlvDb.updateOrAddKernel(new Tlv(EmvTag.DS_SUMMARY_3,
                            signedDynamicData.getDsSummary3().length,
                            signedDynamicData.getDsSummary3()));

                }
            }

            // S11.47
            TlvMap map = new TlvMapImpl(tornTransactionLogRecord.getTlvs());
            Tlv tlvIdStatus = map.get(EmvTag.IDS_STATUS);
            BigInteger bi = BigInteger.valueOf(tlvIdStatus.getValueBytes()[0]);
            if (bi.testBit(7 - 1)) {
                // S11.48
                if (!Arrays.equals(tlvDb.get(EmvTag.DS_SUMMARY_1).getValueBytes(),
                        map.get(EmvTag.DS_SUMMARY_1).getValueBytes())) {

                    // S11.49
                    logger.error("IDS_READ_ERROR S11.49");
                    MastercardErrorIndication ei = MastercardErrorIndication.
                            createL2Error(MastercardErrorIndication.L2Error.IDS_READ_ERROR, ERROR_OTHER_CARD);
                    return invalidResponse1genAc2(tlvDb, idsStatus.isWrite(), ei, tornTransactionLogRecord);
                }
            }

            // S11.50
            if (signedDynamicData.getDsSummary2() == null) {
                // S11.51
                MastercardErrorIndication ei = MastercardErrorIndication.
                        createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_MISSING, ERROR_OTHER_CARD);
                return invalidResponse1genAc2(tlvDb, idsStatus.isWrite(), ei, tornTransactionLogRecord);
            }


            // S11.52
            if (!Arrays.equals(tlvDb.get(EmvTag.DS_SUMMARY_1).getValueBytes(), signedDynamicData.getDsSummary2())) {
                // S11.53
                logger.error("IDS_READ_ERROR S11.53");
                MastercardErrorIndication ei = MastercardErrorIndication.
                        createL2Error(MastercardErrorIndication.L2Error.IDS_READ_ERROR, ERROR_OTHER_CARD);
                return invalidResponse1genAc2(tlvDb, idsStatus.isWrite(), ei, tornTransactionLogRecord);
            }

            // S11.54
            dsSummaryStatus.setSuccessfulRead(true);
            tlvDb.updateOrAddKernel(dsSummaryStatus.toTlv());

            // S11.55
            if (!idsStatus.isWrite()) {
                return validResponse(act, cvm, receiptRequired, tlvDb, transceiver, deTagsToWriteYetAfterGenAc, messageHoldTime,
                        messageStore, putDataProcessor, terminalCapabilities13);
            }

            // S11.56
            if (signedDynamicData.getDsSummary3() == null) {
                // S11.57
                MastercardErrorIndication ei = MastercardErrorIndication.
                        createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_MISSING, ERROR_OTHER_CARD);
                return invalidResponse1genAc2(tlvDb, idsStatus.isWrite(), ei, tornTransactionLogRecord);
            }

            // S11.58
            if (!Arrays.equals(signedDynamicData.getDsSummary2(), signedDynamicData.getDsSummary3())) {
                // S11.59
                dsSummaryStatus.setSuccessfulWrite(true);
                tlvDb.updateOrAddKernel(dsSummaryStatus.toTlv());

                return validResponse(act, cvm, receiptRequired, tlvDb, transceiver, deTagsToWriteYetAfterGenAc, messageHoldTime,
                        messageStore, putDataProcessor, terminalCapabilities13);
            } else {
                DsOdsInfoForReader tmpDsInfo = DsOdsInfoForReader.fromByte(tlvDb.get(EmvTag.DS_ODS_INFO_FOR_READER).
                        getValueBytes()[0]);

                // S11.60
                if (tmpDsInfo.isStopIfWriteFailed()) {
                    // S11.61
                    MastercardErrorIndication ei = MastercardErrorIndication.
                            createL2Error(MastercardErrorIndication.L2Error.IDS_WRITE_ERROR, ERROR_OTHER_CARD);
                    return invalidResponse2(tlvDb, ei);
                } else {
                    return validResponse(act, cvm, receiptRequired, tlvDb, transceiver, deTagsToWriteYetAfterGenAc, messageHoldTime,
                            messageStore, putDataProcessor, terminalCapabilities13);
                }
            }
        } else {
            return validResponse(act, cvm, receiptRequired, tlvDb, transceiver, deTagsToWriteYetAfterGenAc, messageHoldTime,
                    messageStore, putDataProcessor, terminalCapabilities13);
        }
    }


    private Outcome invalidResponse1genAc2CamFailed(TlvDb tlvDb,
                                                    TerminalVerificationResults terminalVerificationResults,
                                                    boolean idsWrite,
                                                    TornTransactionLogRecord tornTransactionLogRecord) {

        // S11.46
        MastercardErrorIndication ei = MastercardErrorIndication.
                createL2Error(MastercardErrorIndication.L2Error.CAM_FAILED, ERROR_OTHER_CARD);

        // S11.46.1
        terminalVerificationResults.setCdaFailed(true);
        tlvDb.updateOrAddKernel(TvrUtil.asTlv(terminalVerificationResults));

        return invalidResponse1genAc2(tlvDb, idsWrite, ei, tornTransactionLogRecord);

    }

}

