package digital.paynetics.phos.kernel.mastercard;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;

import digital.paynetics.phos.kernel.common.crypto.EncDec;
import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.TerminalVerificationResults;
import digital.paynetics.phos.kernel.common.emv.cert.CaPublicKeyData;
import digital.paynetics.phos.kernel.common.emv.cert.CaPublicKeyDb;
import digital.paynetics.phos.kernel.common.emv.cert.CaRidDbReadOnly;
import digital.paynetics.phos.kernel.common.emv.cert.CertificateRevocationListReadOnly;
import digital.paynetics.phos.kernel.common.emv.cert.CrlRid;
import digital.paynetics.phos.kernel.common.emv.cert.CrlRidImpl;
import digital.paynetics.phos.kernel.common.emv.entry_point.misc.IssuerCodeTableIndex;
import digital.paynetics.phos.kernel.common.emv.entry_point.misc.TransactionData;
import digital.paynetics.phos.kernel.common.emv.entry_point.selection.SelectedApplication;
import digital.paynetics.phos.kernel.common.emv.kernel.common.Afl;
import digital.paynetics.phos.kernel.common.emv.kernel.common.AflsExtractor;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationCryptogramType;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationInterchangeProfile;
import digital.paynetics.phos.kernel.common.emv.kernel.common.CardDataMissingException;
import digital.paynetics.phos.kernel.common.emv.kernel.common.CvmSelectionResult;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.kernel.common.KernelType;
import digital.paynetics.phos.kernel.common.emv.kernel.common.KernelUtils;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ParsingException;
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
import digital.paynetics.phos.kernel.common.misc.CountryCode;
import digital.paynetics.phos.kernel.common.misc.Currency;
import digital.paynetics.phos.kernel.common.misc.ForUnitTestsOnly;
import digital.paynetics.phos.kernel.common.misc.McEmvTagList;
import digital.paynetics.phos.kernel.common.misc.McTlvList;
import digital.paynetics.phos.kernel.common.misc.NfcConnectionLostException;
import digital.paynetics.phos.kernel.common.misc.PhosMessageFormat;
import digital.paynetics.phos.kernel.common.misc.RandomGenerator;
import digital.paynetics.phos.kernel.common.misc.TerminalCapabilities13;
import digital.paynetics.phos.kernel.common.misc.TerminalCapabilities2Cvm;
import digital.paynetics.phos.kernel.common.misc.TerminalType;
import digital.paynetics.phos.kernel.common.misc.TimeProvider;
import digital.paynetics.phos.kernel.common.misc.TransactionTimestamp;
import digital.paynetics.phos.kernel.common.misc.TransactionType;
import digital.paynetics.phos.kernel.common.nfc.ApduCommand;
import digital.paynetics.phos.kernel.common.nfc.ApduCommandPackage;
import digital.paynetics.phos.kernel.common.nfc.ApduResponsePackage;
import digital.paynetics.phos.kernel.common.nfc.ApduResponseStatusWord;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;
import digital.paynetics.phos.kernel.mastercard.afl.McAflProcessorResult;
import digital.paynetics.phos.kernel.mastercard.afl.McAflRecord;
import digital.paynetics.phos.kernel.mastercard.afl.magstripe.McMagstripeModeAflProcessor;
import digital.paynetics.phos.kernel.mastercard.ccc.Ccc1;
import digital.paynetics.phos.kernel.mastercard.ccc.Ccc2;
import digital.paynetics.phos.kernel.mastercard.ccc.CccResult;
import digital.paynetics.phos.kernel.mastercard.dek_det.DekDetProcessor;
import digital.paynetics.phos.kernel.mastercard.generate_ac.AcStage;
import digital.paynetics.phos.kernel.mastercard.get_data.GetDataUtil;
import digital.paynetics.phos.kernel.mastercard.gpo.GpoExecutor;
import digital.paynetics.phos.kernel.mastercard.gpo.GpoResult;
import digital.paynetics.phos.kernel.mastercard.misc.ApplicationCapabilityInformation;
import digital.paynetics.phos.kernel.mastercard.misc.DolParser;
import digital.paynetics.phos.kernel.mastercard.misc.DsSlotManagementControl;
import digital.paynetics.phos.kernel.mastercard.misc.DsSummaryStatus;
import digital.paynetics.phos.kernel.mastercard.misc.IdsStatus;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardDolPreparer;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardErrorIndication;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardKernelConfiguration;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardMagstripeFailedCounter;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardMessageIdentifier;
import digital.paynetics.phos.kernel.mastercard.misc.MessageStoreMc;
import digital.paynetics.phos.kernel.mastercard.misc.OutcomePresenter;
import digital.paynetics.phos.kernel.mastercard.misc.SensitiveData;
import digital.paynetics.phos.kernel.mastercard.misc.TagsToReadYetList;
import digital.paynetics.phos.kernel.mastercard.misc.TlvDb;
import digital.paynetics.phos.kernel.mastercard.misc.TlvDbImpl;
import digital.paynetics.phos.kernel.mastercard.misc.TvrUtil;
import digital.paynetics.phos.kernel.mastercard.procedures.ProcessingRestrictions;
import digital.paynetics.phos.kernel.mastercard.procedures.TerminalActionAnalysis;
import digital.paynetics.phos.kernel.mastercard.procedures.cvm_selection.CvmSelection;
import digital.paynetics.phos.kernel.mastercard.put_data.PutDataProcessor;
import digital.paynetics.phos.kernel.mastercard.rrp.Rrp;
import digital.paynetics.phos.kernel.mastercard.torn.TornTransactionLog;
import digital.paynetics.phos.kernel.mastercard.torn.TornTransactionLogRecord;
import java8.util.Optional;

import static digital.paynetics.phos.kernel.common.emv.tag.EmvTag.AMOUNT_AUTHORISED_NUMERIC;
import static digital.paynetics.phos.kernel.common.emv.tag.EmvTag.AMOUNT_OTHER_NUMERIC;
import static digital.paynetics.phos.kernel.common.emv.tag.EmvTag.PDOL_RELATED_DATA;
import static digital.paynetics.phos.kernel.common.emv.tag.EmvTag.RESPONSE_MESSAGE_TEMPLATE_2;
import static digital.paynetics.phos.kernel.common.emv.tag.EmvTag.TRANSACTION_CURRENCY_CODE;
import static digital.paynetics.phos.kernel.common.emv.tag.EmvTag.TRANSACTION_TYPE;
import static digital.paynetics.phos.kernel.common.misc.ByteUtils.intToUnpackedBcd;
import static digital.paynetics.phos.kernel.common.misc.ByteUtils.leftPad;
import static digital.paynetics.phos.kernel.mastercard.misc.MastercardMessageIdentifier.ERROR_OTHER_CARD;
import static digital.paynetics.phos.kernel.mastercard.misc.MastercardMessageIdentifier.NOT_AVAILABLE;
import static digital.paynetics.phos.kernel.mastercard.misc.MastercardMessageIdentifier.TRY_AGAIN;


public class MastercardKernelImpl implements MastercardKernel {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final int ID = 2;
    private static final int KERNEL_APPLICATION_VERSION_NUMBER = 2;

    private static final String DEFAULT_ENCODING = "ISO-8859-1";

    // as in C-2, Table 4.7 - Data Record Detail for EMV Mode Transaction
    private TlvDb tlvDb;
    private final GpoExecutor gpoExecutor;
    private final CvmSelection cvmSelection;
    private final ProcessingRestrictions processingRestrictions;
    private final TerminalActionAnalysis terminalActionAnalysis;
    private final Provider<McMagstripeModeAflProcessor> magstripeModeAflProcessorProvider;
    private final RandomGenerator randomGenerator;
    private final Ccc1 ccc1;
    private final Ccc2 ccc2;
    private final MessageStoreMc messageStore;
    private final Rrp rrp;
    private final DekDetProcessor dekDetProcessor;
    private final AflsExtractor aflsExtractor;
    private final PutDataProcessor putDataProcessor;
    private final AcStage acStage;
    private final TornTransactionLog tornTransactionLog;
    private final TimeProvider timeProvider;


    private TerminalVerificationResults terminalVerificationResults = new TerminalVerificationResults();

    private TerminalCapabilities2Cvm cvmCapabilities;
    private boolean receiptRequired = false;

    private boolean isInitialized;
    private MastercardMagstripeFailedCounter mastercardMagstripeFailedCounter;

    private boolean isOdaStatusCdaSet = false;

    private ByteArrayOutputStream staticDataToBeAuthenticated = new ByteArrayOutputStream();

    private CaRidDbReadOnly caRidDb;
    private CertificateRevocationListReadOnly crl;
    private TerminalCapabilities13 terminalCapabilities13;
    private byte mobileSupportIndicator;
    private final boolean emptyTransactionCategoryCode;
    private boolean isEmvMode = false;

    private volatile boolean isStopSignalReceived = false;
    private volatile boolean isAcStage = false;
    private volatile boolean isCccStage = false;

    private volatile Transceiver transceiver;

    private MastercardKernelConfiguration configuration;

    private SelectedApplication selectedAppReprocessed;

    private final McEmvTagList deDataNeeded = new McEmvTagList();
    private final McTlvList deDataToSend = new McTlvList();
    private TagsToReadYetList deTagsToReadYet = new TagsToReadYetList();
    private McTlvList deTagsToWriteYetBeforeGenAc = new McTlvList();
    private McTlvList deTagsToWriteYetAfterGenAc = new McTlvList();


    private IdsStatus idsStatus;
    private DsSummaryStatus dsSummaryStatus;

    private final boolean noAmountAuthorizedNumericInAct;
    private final boolean zeroLengthAuthorizedNumericInAct;
    private final boolean extendedRrpMaxGrace;
    private final boolean emptyAmountOther;
    private final boolean amountOther250;
    private final boolean noTransactionType;
    private final boolean noTransactionCurrencyCodeAndAmountOther;
    private final boolean transactionType21;
    private final boolean noTransactionCategoryCode;
    private final boolean emptyMerchantCustomData;
    private final boolean useLightLogging;
    private final boolean useAmountOtherZero;

    private int fieldOffRequest = -1; // not used, tests are not using it, we can't turn off the field on android also

    private NextCmd nextCmd;
    private Queue<McAflRecord> aflRecordsQueue = new LinkedList<>();
    private ApduResponsePackage getDataResp;
    private EmvTag expectedGetDataResponseTag;
    private ApduResponsePackage readRecordResp;
    private McAflRecord currentMcAflRecord;

    private int messageHoldTime;
    private EmvTag getDataTag;
    boolean terminateOnNextRa = false;


    @SuppressWarnings("WeakerAccess")
    @Inject
    public MastercardKernelImpl(
            GpoExecutor gpoExecutor,
            CvmSelection cvmSelection,
            ProcessingRestrictions processingRestrictions,
            TerminalActionAnalysis terminalActionAnalysis,
            Provider<McMagstripeModeAflProcessor> magstripeModeAflProcessorProvider,
            @Named("RandomGenerator for MastercardKernelImpl") RandomGenerator randomGenerator,
            Ccc1 ccc1,
            Ccc2 ccc2,
            MessageStoreMc messageStore,
            Rrp rrp,
            DekDetProcessor dekDetProcessor,
            AflsExtractor aflsExtractor,
            PutDataProcessor putDataProcessor,
            AcStage acStage,
            TornTransactionLog tornTransactionLog,
            TimeProvider timeProvider,
            @Named("no Amount in ACT") boolean noAmountAuthorizedNumericInAct,
            @Named("zero length Amount in ACT") boolean zeroLengthAuthorizedNumericInAct,
            @Named("extended RRP max grace period") boolean extendedRrpMaxGrace,
            @Named("empty amount other") boolean emptyAmountOther,
            @Named("amount other 2.50") boolean amountOther250,
            @Named("no transaction type in ACT") boolean noTransactionType,
            @Named("no transaction currency code in ACT") boolean noTransactionCurrencyCodeAndAmountOther,
            @Named("transaction type 21") boolean transactionType21,
            @Named("empty transaction category code") boolean emptyTransactionCategoryCode,
            @Named("no transaction category code") boolean noTransactionCategoryCode,
            @Named("empty merchant custom data") boolean emptyMerchantCustomData,
            @Named("use light logging") boolean useLightLogging,
            @Named("use amount other zero") boolean useAmountOtherZero) {

        this.gpoExecutor = gpoExecutor;
        this.cvmSelection = cvmSelection;
        this.processingRestrictions = processingRestrictions;
        this.terminalActionAnalysis = terminalActionAnalysis;
        this.magstripeModeAflProcessorProvider = magstripeModeAflProcessorProvider;
        this.randomGenerator = randomGenerator;
        this.ccc1 = ccc1;
        this.ccc2 = ccc2;
        this.messageStore = messageStore;
        this.rrp = rrp;
        this.dekDetProcessor = dekDetProcessor;
        this.aflsExtractor = aflsExtractor;
        this.putDataProcessor = putDataProcessor;
        this.acStage = acStage;
        this.tornTransactionLog = tornTransactionLog;
        this.timeProvider = timeProvider;
        this.noAmountAuthorizedNumericInAct = noAmountAuthorizedNumericInAct;
        this.zeroLengthAuthorizedNumericInAct = zeroLengthAuthorizedNumericInAct;
        this.extendedRrpMaxGrace = extendedRrpMaxGrace;
        this.emptyAmountOther = emptyAmountOther;
        this.amountOther250 = amountOther250;
        this.noTransactionType = noTransactionType;
        this.noTransactionCurrencyCodeAndAmountOther = noTransactionCurrencyCodeAndAmountOther;
        this.transactionType21 = transactionType21;
        this.emptyTransactionCategoryCode = emptyTransactionCategoryCode;
        this.noTransactionCategoryCode = noTransactionCategoryCode;
        this.emptyMerchantCustomData = emptyMerchantCustomData;
        this.useLightLogging = useLightLogging;
        this.useAmountOtherZero = useAmountOtherZero;
    }


    private static int computeNun(Tlv punAtcTlv, Tlv natcTlv) {
        // S78.15
        int punAtc2nz;
        int natc;
        try {
            punAtc2nz = Integer.bitCount(punAtcTlv.getValueAsHexInt());
            natc = natcTlv.getValueAsBcdInt();
        } catch (TlvException e) {
            throw new RuntimeException("Invalid configuration data");
        }

        return punAtc2nz - natc;
    }


    @Override
    public KernelType getKernelType() {
        return KernelType.MASTERCARD;
    }


    @Override
    public int getAppKernelId() {
        return ID;
    }


    private static char[] prepareRandom(RandomGenerator rng, int nUn) {
        byte[] random = new byte[4];
        rng.nextBytes(random);

        int randomInt = ByteBuffer.wrap(random).getInt();
        char[] randomCh = Integer.toString(randomInt).toCharArray();

        char[] randomCh8 = ByteUtils.fitCharArray(randomCh, 8);
        int toZero = 8 - nUn;
        for (int i = 0; i < toZero; i++) {
            randomCh8[i] = '0';
        }

        return randomCh8;
    }


    private static boolean isSdaPresentAndOnlyAip(TlvMapReadOnly tlvDb) {
        // S456.26
        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.STATIC_DATA_AUTHENTICATION_TAG_LIST)) {
            Tlv sdaTlv = tlvDb.get(EmvTag.STATIC_DATA_AUTHENTICATION_TAG_LIST);
            byte[] sdaRaw = sdaTlv.getValueBytes();
            //noinspection RedundantIfStatement
            if (sdaRaw.length == 1 && sdaRaw[0] == (byte) 0x82) {
                return true;
            }
        }

        return false;
    }


    private static void prepareTlvDb(TlvDb tlvDb,
                                     TlvMapReadOnly commonDolData,
                                     List<Tlv> customTlvs,
                                     boolean noAmountAuthorizedNumericInAct,
                                     boolean zeroLengthAuthorizedNumericInAct,
                                     boolean extendedRrpMaxGrace,
                                     boolean emptyAmountOther,
                                     boolean amountOther250,
                                     boolean noTransactionType,
                                     TransactionType transactionType,
                                     boolean noTransactionCurrencyCodeAndAmountOther,
                                     boolean transactionType21,
                                     boolean emptyTransactionCategoryCode,
                                     boolean noTransactionCategoryCode,
                                     boolean noMerchantCustomData,
                                     boolean useAmountOtherZero
    ) {

        for (Tlv tlv : commonDolData.asList()) {
            tlvDb.updateOrAddKernel(tlv);

            if (tlv.getTag() == EmvTag.AMOUNT_OTHER_NUMERIC) {
                if (emptyAmountOther) {
                    Tlv tlvTmp = new Tlv(EmvTag.AMOUNT_OTHER_NUMERIC, 0, new byte[0]);
                    tlvDb.updateOrAddKernel(tlvTmp);
                } else {
                    if (transactionType != TransactionType.CASHBACK) {
                        if (amountOther250) {
                            Tlv tlvTmp = new Tlv(EmvTag.AMOUNT_OTHER_NUMERIC, 6, new byte[]{0, 0, 0, 0, 2, 0x50});
                            tlvDb.updateOrAddKernel(tlvTmp);
                        } else {
                            tlvDb.remove(EmvTag.AMOUNT_OTHER_NUMERIC);
                        }
                    }
                }
            } else if (tlv.getTag() == EmvTag.AMOUNT_AUTHORISED_NUMERIC) {
                if (amountOther250) {
                    int amount = 0;
                    try {
                        amount = tlv.getValueAsBcdInt();
                    } catch (TlvException e) {
                        // cannot happen
                    }

                    if (transactionType != TransactionType.CASHBACK) {
                        byte[] amountAuthorizedB = leftPad(ByteUtils.intToUnpackedBcd(amount + 250), 6);
                        Tlv tlvTmp = new Tlv(EmvTag.AMOUNT_AUTHORISED_NUMERIC, 6, amountAuthorizedB);
                        tlvDb.updateOrAddKernel(tlvTmp);
                    }
                }
            }
        }


        if (customTlvs != null) {
            for (Tlv tlv : customTlvs) {
                tlvDb.updateOrAddKernel(tlv);
            }
        }

        TlvMapReadOnly defaultTlvs = MastercardKernel.createDefaultKernelTlvs();
        for (Tlv tlv : defaultTlvs.asList()) {
            if (!tlvDb.isTagPresentAndNonEmpty(tlv.getTag())) {
                tlvDb.addKernel(tlv);
            }
        }

        if (noAmountAuthorizedNumericInAct) {
            tlvDb.remove(AMOUNT_AUTHORISED_NUMERIC);
        }

        if (zeroLengthAuthorizedNumericInAct) {
            tlvDb.updateOrAddKernel(new Tlv(EmvTag.AMOUNT_AUTHORISED_NUMERIC, 0, new byte[0]));
        }

        if (extendedRrpMaxGrace) {
            tlvDb.updateOrAddKernel(new Tlv(EmvTag.MAXIMUM_RELAY_RESISTANCE_GRACE_PERIOD, 2, new byte[]{(byte) 15, (byte) 255}));
        }

        if (noTransactionType) {
            tlvDb.updateOrAddKernel(new Tlv(EmvTag.TRANSACTION_TYPE, 1, new byte[1]));
        }

        if (noTransactionCurrencyCodeAndAmountOther) {
            tlvDb.remove(EmvTag.TRANSACTION_CURRENCY_CODE);
            tlvDb.remove(EmvTag.AMOUNT_OTHER_NUMERIC);
        }

        if (transactionType21) {
            Tlv tlv = new Tlv(EmvTag.TRANSACTION_TYPE, 1, new byte[]{0x21});
            tlvDb.updateOrAddKernel(tlv);
        }

        if (emptyTransactionCategoryCode) {
            tlvDb.updateOrAddKernel(new Tlv(EmvTag.TRANSACTION_CATEGORY_CODE, 0, new byte[0]));
        }

        if (noMerchantCustomData) {
            tlvDb.updateOrAddKernel(new Tlv(EmvTag.MERCHANT_CUSTOM_DATA, 0, new byte[0]));
        }

        if (noTransactionCategoryCode) {
            tlvDb.remove(EmvTag.TRANSACTION_CATEGORY_CODE);
        }

        if (useAmountOtherZero) {
            tlvDb.updateOrAddKernel(new Tlv(EmvTag.AMOUNT_OTHER_NUMERIC, 6, new byte[6]));
        }

    }


    @Override
    public void init(MastercardMagstripeFailedCounter mastercardMagstripeFailedCounter,
                     CaRidDbReadOnly caRidDb,
                     CertificateRevocationListReadOnly crl,
                     EncDec encDec) {

        this.mastercardMagstripeFailedCounter = mastercardMagstripeFailedCounter;

        this.caRidDb = caRidDb;
        this.crl = crl;

        tlvDb = new TlvDbImpl(encDec);

        isInitialized = true;
    }


    public static void logOutcome(Logger logger, Outcome oc, boolean dontLogDataRecord) {
        logger.debug("(outc) Outcome: \n    {}", OutcomePresenter.present(oc));
        if (oc.getDiscretionaryData() != null && oc.getDiscretionaryData().size() > 0) {
            logger.debug("(outc) +++++++++++++++++ Discretionary data +++++++++++++++++");
            for (Tlv tlv : oc.getDiscretionaryData()) {
                if (tlv.getTag() == EmvTag.ERROR_INDICATION) {
                    MastercardErrorIndication ei = MastercardErrorIndication.fromBytes(tlv.getValueBytes());
                    logger.debug("(tlvs) Tag: {} ({}), {}", tlv.getTag().getName(), ByteUtils.toHexString(tlv.getTag().getTagBytes()),
                            OutcomePresenter.present(ei, tlv.getValueBytes()));
                } else {
                    logTlv(logger, tlv);
                }
            }
        }

        if (oc.getUiRequestOnOutcome().isPresent()) {
            logger.debug("(outc) User Interface Request on Outcome:\n    {}", OutcomePresenter.present(oc.getUiRequestOnOutcome().get()));
        }

        if (oc.getUiRequestOnRestart().isPresent()) {
            logger.debug("(outc) User Interface Request on Restart:\n    {}", OutcomePresenter.present(oc.getUiRequestOnRestart().get()));
        }

        if (!dontLogDataRecord) {
            if (oc.getDataRecord() != null && oc.getDataRecord().size() > 0) {
                logger.debug("(outc) +++++++++++++++++ Data record +++++++++++++++++");
                {
                    for (Tlv tlv : oc.getDataRecord()) {
                        logTlv(logger, tlv);
                    }
                }
            }
        }
    }


    @Override
    public Outcome process(Transceiver transceiver,
                           TlvMap commonDolData,
                           CountryCode countryCode,
                           TransactionData transactionData,
                           SelectedApplication selectedApp,
                           TransactionTimestamp ts
    ) throws IOException {
        messageStore.clear();
        try {
            Outcome oc = processActual(transceiver, commonDolData, countryCode, transactionData, selectedApp, ts);

//            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.TRACK1_DATA)) {
//                logger.debug("Track 1 data IN: {}", tlvDb.get(EmvTag.TRACK1_DATA).getValueAsString());
//            }
//            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.TRACK2_DATA)) {
//                logger.debug("Track 2 data IN: {}", tlvDb.get(EmvTag.TRACK2_DATA).getValueAsHex());
//            }

            Optional<UserInterfaceRequest> uirOut = prepareUserInterfaceRequest(oc.getUiRequestOnOutcome());
            Optional<UserInterfaceRequest> uirRestart = prepareUserInterfaceRequest(oc.getUiRequestOnRestart());

            List<UserInterfaceRequest> uirList = messageStore.getAll();
            messageStore.clear();
            for (UserInterfaceRequest uir : uirList) {
                messageStore.add(prepareUserInterfaceRequest(Optional.of(uir)).get());
            }

            return new Outcome(oc.getType(), oc.getStart(), oc.getOnlineResponseDataRestartCondition(), oc.getOnlineResponseData(),
                    oc.getCvm(), uirOut, uirRestart, oc.getDataRecord(),
                    oc.getDiscretionaryData(), oc.getAlternateInterfacePreference(), oc.getReceiptPreference(),
                    oc.getFieldOffRequest() == 0 ? fieldOffRequest : -1,
                    oc.getRemovalTimeout(), null);
        } catch (NfcConnectionLostException e) {
            if (isStopSignalReceived) {
                return MastercardKernel.createStopOutcome();
            } else {
                throw e;
            }
        }
    }


    private Optional<UserInterfaceRequest> prepareUserInterfaceRequest(Optional<UserInterfaceRequest> uiO) {

        if (uiO.isPresent()) {
            UserInterfaceRequest ui = uiO.get();
            String str;
            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.LANGUAGE_PREFERENCE)) {
                str = ByteUtils.toHexString(tlvDb.get(EmvTag.LANGUAGE_PREFERENCE).getValueBytes());
                str = String.format("%-16s", str).replace(' ', '0');

            } else {
                str = "0000000000000000";
            }

            return Optional.of(new UserInterfaceRequest(ui.getMessage(), ui.getStatus(), ui.getHoldTime(), str,
                    ui.getValueQualifier().isPresent() ? ui.getValueQualifier().get() : null, ui.getValue(),
                    ui.getCurrency().isPresent() ? ui.getCurrency().get() : null));
        } else {
            return Optional.empty();
        }
    }


    private void invalidCccResponse() {
        try {
            logger.debug("CCCtimer (sleep): {} ms", Math.pow(2, mastercardMagstripeFailedCounter.get()) * 300);
            Thread.sleep((long) (Math.pow(2, mastercardMagstripeFailedCounter.get()) * 300));
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        mastercardMagstripeFailedCounter.increment();
    }


    private Outcome invalidCccResponseSw(byte[] statusWord) {
        invalidCccResponse();

        UserInterfaceRequest uiReq = new UserInterfaceRequest(StandardMessages.TRY_ANOTHER_CARD,
                ContactlessTransactionStatus.NOT_READY, 0, null, null, 0, null);
        Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);
        b.uiRequestOnOutcome(uiReq);
        b.start(Outcome.Start.NOT_APPLICABLE);
        MastercardErrorIndication ei =
                MastercardErrorIndication.createL2StatusBytesError(statusWord, MastercardMessageIdentifier.ERROR_OTHER_CARD);

        b.discretionaryData(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));

        return b.build();
    }


    private Outcome l1rsp(boolean isTimeout) {
        invalidCccResponse();

        UserInterfaceRequest uiReq = new UserInterfaceRequest(StandardMessages.PRESENT_CARD_AGAIN,
                ContactlessTransactionStatus.READY_TO_READ, 0, null, null, 0, null);
        Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);
        b.uiRequestOnRestart(uiReq);
        b.start(Outcome.Start.B);

        MastercardErrorIndication ei;
        if (isTimeout) {
            ei = MastercardErrorIndication.createL1Error(MastercardErrorIndication.L1Error.TIME_OUT, TRY_AGAIN);
        } else {
            ei = MastercardErrorIndication.createL1Error(MastercardErrorIndication.L1Error.TRANSMISSION_ERROR, TRY_AGAIN);
        }

        b.discretionaryData(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));

        return b.build();
    }


    @Override
    public boolean stopSignal() {
        if (!isAcStage && !isCccStage) {
            isStopSignalReceived = true;
            if (transceiver != null) {
                transceiver.close();
            }
            return true;
        } else {
            return false;
        }
    }


    private Outcome selectNext(List<Tlv> discretionaryData) {
        Outcome.Builder b = new Outcome.Builder(Outcome.Type.SELECT_NEXT);
        b.start(Outcome.Start.C);
        b.fieldOffRequest(-1);
        b.discretionaryData(discretionaryData);

        return b.build();
    }


    private byte[] resolveFinalApplicationFileLocatorEmv(byte[] applicationFileLocator) {
        byte[] optimizedAflTest = {0x08, 0x01, 0x01, 0x00};
        // S3.30
        if (applicationFileLocator.length >= 4 &&
                Arrays.equals(Arrays.copyOfRange(applicationFileLocator, 0, 4), optimizedAflTest) &&
                !configuration.isMagstripeModeNotSupported()) {

            // S3.32
            return Arrays.copyOfRange(applicationFileLocator, 4, applicationFileLocator.length);
        } else {
            // S3.31
            return applicationFileLocator;
        }
    }


    private Outcome magstripeNotSupported() {
        // S3.90.1, S3.90.2
        MastercardErrorIndication ei = MastercardErrorIndication.createL2Error(
                MastercardErrorIndication.L2Error.MAGSTRIPE_NOT_SUPPORTED,
                ERROR_OTHER_CARD);

        return Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));
    }


    private byte[] resolveFinalApplicationFileLocatorMagstripe(byte[] applicationFileLocator) {
        byte[] optimizedAflTest = {0x08, 0x01, 0x01, 0x00};
        // S3.30
        if (applicationFileLocator.length >= 4 &&
                Arrays.equals(Arrays.copyOfRange(applicationFileLocator, 0, 4), optimizedAflTest)) {

            // S3.32
            return optimizedAflTest;
        } else {
            // S3.31
            return applicationFileLocator;
        }
    }


    private static void processTagsToReadYet(TlvDb tlvDb, McEmvTagList deTagsToReadYet, McTlvList deDataToSend) {
        for (EmvTag tag : deTagsToReadYet.asList()) {
            if (tlvDb.isTagPresentAndNonEmpty(tag)) {
                addToDeDataToSend(tlvDb, tag, deDataToSend);

                deTagsToReadYet.remove(tag);
            }
        }
    }


    /**
     * This method is used when test case is retarded and required PAN ot other sensitive data to be send
     *
     * @param tlvDb
     * @param tag
     * @param deDataToSend
     */
    private static void addToDeDataToSend(TlvDb tlvDb, EmvTag tag, McTlvList deDataToSend) {
        if (tag == EmvTag.TRACK1_DATA) {
            Optional<SensitiveData> sd = tlvDb.getTrack1();
            deDataToSend.add(new Tlv(EmvTag.TRACK1_DATA, sd.get().getData().length, sd.get().getData()));
            sd.get().purge();
        } else if (tag == EmvTag.TRACK2_DATA) {
            Optional<SensitiveData> sd = tlvDb.getTrack2();
            deDataToSend.add(new Tlv(EmvTag.TRACK2_DATA, sd.get().getData().length, sd.get().getData()));
            sd.get().purge();
        } else if (tag == EmvTag.TRACK_2_EQV_DATA) {
            Optional<SensitiveData> sd = tlvDb.getTrack2Eqv();
            deDataToSend.add(new Tlv(EmvTag.TRACK_2_EQV_DATA, sd.get().getData().length, sd.get().getData()));
            sd.get().purge();
        } else if (tag == EmvTag.PAN) {
            Optional<SensitiveData> sd = tlvDb.getPan();
            deDataToSend.add(new Tlv(EmvTag.PAN, sd.get().getData().length, sd.get().getData()));
            sd.get().purge();
        } else {
            deDataToSend.add(tlvDb.get(tag));
        }
    }


    @Override
    public int getKernelApplicationVersion() {
        return KERNEL_APPLICATION_VERSION_NUMBER;
    }


    @Override
    public Outcome clean(int ttrTtlSeconds) {

        // S1.5
        List<TornTransactionLogRecord> evictedTornTransactionLogRecords = tornTransactionLog.clean(timeProvider.getWallClockTime(),
                ttrTtlSeconds);

        Collections.reverse(evictedTornTransactionLogRecords);

        for (TornTransactionLogRecord tr : evictedTornTransactionLogRecords) {
            Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);
            List<Tlv> dd = new ArrayList<>();

            dd.add(tr.toTlv());

            b.discretionaryData(dd);

            if (!useLightLogging) {
                logOutcome(logger, b.build(), true);
            }
        }

        Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);
        b.discretionaryData(new ArrayList<>());
        return b.build();
    }


    @Override
    public TlvDb getTlvDb() {
        return tlvDb;
    }


    @Override
    public boolean isEmvMode() {
        return isEmvMode;
    }


    private Outcome invalidCccResponseParsingError() {
        invalidCccResponse();
        return parsingError();
    }


    private Outcome magStripeMode(Transceiver transceiver,
                                  byte[] applicationFileLocator,
                                  TransactionData transactionData,
                                  ApplicationInterchangeProfile applicationInterchangeProfile,
                                  ReaderLimits readerLimits) throws IOException, TlvException, EmvException {

        logger.debug("Magstripe mode");

        int readerContactlessTransactionLimit;

        // S3.70, S3.71, S3.72
        applicationFileLocator = resolveFinalApplicationFileLocatorMagstripe(applicationFileLocator);

        // S3.73
        if (applicationInterchangeProfile.isOnDeviceCvmSupported() && configuration.isDeviceCvmSupported()) {
            // S3.74
            readerContactlessTransactionLimit = readerLimits.contactlessReaderLimitOnDeviceCvm;
        } else {
            // S3.75
            readerContactlessTransactionLimit = readerLimits.contactlessReaderLimitNoOnDeviceCvm;
        }

        // S3.76
        processTagsToReadYet(tlvDb, deTagsToReadYet, deDataToSend);

        // S3.77
        if ((!deDataNeeded.isEmpty() || !deDataToSend.isEmpty()) && deTagsToReadYet.isEmpty()) {
            // S3.78
            logger.debug("S3.78");
            dekDet();
        }


        McMagstripeModeAflProcessor p = magstripeModeAflProcessorProvider.get();
        McAflProcessorResult rez = p.process(transceiver, applicationFileLocator, tlvDb);
        if (rez.isOk()) {
            for (Tlv tlv : rez.getForTlvDb()) {
                tlvDb.updateOrAddRa(tlv);
                // S7.14
                if (tlv.getTag() == EmvTag.VISA_CARD_AUTHENTICATION_RELATED_DATA__MASTERCARD_UDOL) {
                    List<TagAndLength> udolList = DolParser.parse(tlv.getValueBytes());
                    for (TagAndLength tl : udolList) {
                        // S7.15
                        if (tlvDb.isTagPresent(tl.getTag())) {
//                            if (tl.getTag() != EmvTag.UNKNOWN) {
                            Tlv tlv2 = tlvDb.get(tl.getTag());
                            if (tlv2.getValueBytes().length == 0) {
                                deDataNeeded.add(tl.getTag());
//                                }
                            }
                        }
                    }
                }
            }
            for (Tlv tlv : rez.getForTlvDbKernel()) {
                tlvDb.updateOrAddKernel(tlv);
            }
        } else {
            return rez.getOutcome();
        }

        if (isStopSignalReceived) {
            return MastercardKernel.createStopOutcome();
        }


        boolean loopForData = false;
        long start = 0;
        int timeout = tlvDb.get(EmvTag.TIME_OUT_VALUE).getValueAsHexInt();

        boolean noDetResponse = false;
        boolean dekSent;

        do {
            dekSent = false;

            // S78.1
            if (tlvDb.isTagPresent(EmvTag.PROCEED_TO_FIRST_WRITE_FLAG) &&
                    tlvDb.get(EmvTag.PROCEED_TO_FIRST_WRITE_FLAG).getLength() == 0) {
                // S78.2
                deDataNeeded.add(EmvTag.PROCEED_TO_FIRST_WRITE_FLAG);
                loopForData = true;
            } else {
                // S78.7
                if ((tlvDb.isTagPresentAndNonEmpty(EmvTag.PROCEED_TO_FIRST_WRITE_FLAG))) {
                    loopForData = tlvDb.get(EmvTag.PROCEED_TO_FIRST_WRITE_FLAG).getValueBytes()[0] == 0;
                }
            }

            if (loopForData) {
                // S78.3
                processTagsToReadYet(tlvDb, deTagsToReadYet, deDataToSend);

                // S78.4
                if (!deDataNeeded.isEmpty() || (!deDataToSend.isEmpty() && deTagsToReadYet.isEmpty())) {
                    // S78.5
                    logger.debug("S78.5");
                    dekSent = true;
                    DekDetProcessor.Result dekDetRez = dekDet();

                    if (dekDetRez.isAllDetEmpty()) {
                        noDetResponse = true;
                    }
                    if (dekDetRez.isDekFound() && !dekDetRez.isAllDetEmpty()) {
                        start = 0; // stop timer
                    } else {
                        try {

                            if ((tlvDb.isTagPresentAndNonEmpty(EmvTag.PROCEED_TO_FIRST_WRITE_FLAG))) {
                                loopForData = tlvDb.get(EmvTag.PROCEED_TO_FIRST_WRITE_FLAG).getValueBytes()[0] == 0;
                            }
                            if (loopForData) {
                                logger.debug("Starting timeout timer for PROCEED_TO_FIRST_WRITE_FLAG S78.6");
                                start = timeProvider.getVmTime();

                                do {
                                    Thread.sleep(20);
                                    if (start > 0 && timeProvider.getVmTime() > (start + timeout)) {
                                        logger.warn("Timeout during wait for PROCEED_TO_FIRST_WRITE_FLAG");

                                        MastercardErrorIndication ei = MastercardErrorIndication.
                                                createL3Error(MastercardErrorIndication.L3Error.TIME_OUT, null);

                                        Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);

                                        b.discretionaryData(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));

                                        return b.build();
                                    }
                                } while (true);
                            }
                        } catch (InterruptedException e) {
                            // cannot happen
                        }
                    }
                }

                if (start == 0) {
                    // S78.6
                    logger.debug("Starting timeout timer for PROCEED_TO_FIRST_WRITE_FLAG S78.6");
                    start = timeProvider.getVmTime();
                }
            }


            if (loopForData && (!dekSent || noDetResponse)) {
                try {
                    do {
                        Thread.sleep(20);
                        if (start > 0 && timeProvider.getVmTime() > (start + timeout)) {
                            logger.warn("Timeout during wait for PROCEED_TO_FIRST_WRITE_FLAG S78.6 - 2");

                            MastercardErrorIndication ei = MastercardErrorIndication.
                                    createL3Error(MastercardErrorIndication.L3Error.TIME_OUT, NOT_AVAILABLE);

                            Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);
                            b.discretionaryData(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));

                            return b.build();
                        }
                    } while (true);
                } catch (InterruptedException e) {
                    // ignore
                }
            }
        } while (loopForData);


        // S78.8
        if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.AMOUNT_AUTHORISED_NUMERIC)) {
            // S78.9
            MastercardErrorIndication ei = MastercardErrorIndication.
                    createL3Error(MastercardErrorIndication.L3Error.AMOUNT_NOT_PRESENT, NOT_AVAILABLE);

            Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);

            b.discretionaryData(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));

            return b.build();
        }

        // S78.10
        if (transactionData.getAmountAuthorized() > readerContactlessTransactionLimit) {
            // S78.11
            MastercardErrorIndication ei = MastercardErrorIndication.
                    createL2Error(MastercardErrorIndication.L2Error.MAX_LIMIT_EXCEEDED, NOT_AVAILABLE);

            return selectNext(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));
        }

        // S78.12
        for (EmvTag tag : deTagsToReadYet.asList()) {
            if (tlvDb.isTagPresentAndNonEmpty(tag)) {
                addToDeDataToSend(tlvDb, tag, deDataToSend);
                deTagsToReadYet.remove(tag);
            } else {
                if (MastercardTags.isKnown(tag)) {
                    deDataToSend.add(new Tlv(tag, 0, new byte[0]));
                }
            }
        }

        // S78.13
        if (!deDataToSend.isEmpty()) {
            // S78.14
            logger.debug("S78.14");
            dekDet(true);
        }

        // S78.15
        int nUn = computeNun(tlvDb.get(EmvTag.TERMINAL_TRANSACTION_QUALIFIERS__PUNATC_TRACK2), tlvDb.get(EmvTag.NATC_TRACK2));
        char[] random = prepareRandom(randomGenerator, nUn);
        String r = new String(random);
        int randomInt = Integer.parseInt(r);

        Outcome.Cvm cvm = Outcome.Cvm.NOT_APPLICABLE;

        // S78.16
        if (applicationInterchangeProfile.isOnDeviceCvmSupported() && configuration.isDeviceCvmSupported()) {
            // S78.19
            if (transactionData.getAmountAuthorized() > readerLimits.readerCvmRequiredLimit) {
                // S78.20
                mobileSupportIndicator = (byte) (mobileSupportIndicator | 0b00000010);
                cvm = Outcome.Cvm.CONFIRMATION_CODE_VERIFIED;
            }
        }

        tlvDb.updateOrAddKernel(new Tlv(EmvTag.MOBILE_SUPPORT_INDICATOR, 1, new byte[]{mobileSupportIndicator}));

        // S78.17, S78.21
        Tlv udol;
        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.VISA_CARD_AUTHENTICATION_RELATED_DATA__MASTERCARD_UDOL)) {
            udol = tlvDb.get(EmvTag.VISA_CARD_AUTHENTICATION_RELATED_DATA__MASTERCARD_UDOL);
        } else {
            udol = tlvDb.get(EmvTag.DEFAULT_UDOL);
        }

        List<TagAndLength> udolList = DolParser.parse(udol.getValueBytes());

        TlvMap udolTlvs = new TlvMapImpl();
        udolTlvs.addAll(tlvDb.asUnencrypted().asList());
        Tlv tlvUnpredictable = new Tlv(EmvTag.UNPREDICTABLE_NUMBER_NUMERIC, 4, intToUnpackedBcd(randomInt, 4));
        udolTlvs.updateOrAdd(tlvUnpredictable);
        tlvDb.addKernel(tlvUnpredictable);
        byte[] udolPrepared = KernelUtils.prepareDol(udolTlvs, udolList);

        for (Tlv tlv : udolTlvs.asList()) {
            switch (tlv.getTag()) {
                case TRACK1_DATA:
                    // fall trough
                case TRACK2_DATA:
                    // fall trough
                case TRACK_2_EQV_DATA:
                    // fall trough
                case PAN:
                    tlv.purge();
                    break;
            }
        }

        isCccStage = true;
        ApduCommandPackage cmd = new ApduCommandPackage(ApduCommand.COMPUTE_CRYPTOGRAPHIC_CHECKSUM, udolPrepared);
        // S78.18, S78.22
        logger.debug("(nfc) About to send COMPUTE_CRYPTOGRAPHIC_CHECKSUM");
        ApduResponsePackage resp;
        try {
            resp = transceiver.transceive(cmd);
        } catch (IOException e) {
            return l1rsp(false);
        } catch (NfcConnectionLostException e) {
            return l1rsp(true);
        }

        try {
            // S13.9, S14.9
            if (!resp.isSuccess()) {
                byte[] rawSw = Arrays.copyOfRange(resp.getData(), resp.getData().length - 2, resp.getData().length);
                resp.purgeData();
                if (resp.getStatusWord() == ApduResponseStatusWord.SW_UNKNOWN) {
                    return invalidCccResponseSw(rawSw);
                } else {
                    return invalidCccResponseSw(resp.getStatusWord().getStatusWord());
                }
            } else {
                // S13.11, S14.11
                // S13.12, S14.12
                if (resp.getData().length > 0 && resp.getData()[0] != RESPONSE_MESSAGE_TEMPLATE_2.getTagBytes()[0]) {
                    logger.warn("S13.11, S14.11");

                    invalidCccResponse();

                    return parsingError();
                }

                List<Tlv> list = TlvUtils.getChildTlvs(resp.getData(), RESPONSE_MESSAGE_TEMPLATE_2);
                MastercardTags.checkInValidTemplate(list, RESPONSE_MESSAGE_TEMPLATE_2);
                for (Tlv tlv : list) {
                    try {
                        tlvDb.updateOrAddRa(tlv);
                    } catch (EmvException e) {
                        logger.warn(e.getMessage());

                        invalidCccResponse();

                        return parsingError();
                    }
                }

                List<Tlv> tlvs = TlvUtils.getTlvs(Arrays.copyOfRange(resp.getData(), 0, resp.getData().length - 2));
                resp.purgeData();
                if (tlvs.size() > 1) {
                    logger.warn("Unexpected tag in CCC");
                    invalidCccResponse();
                    return parsingError();
                }


                // S13.12, S14.12 - skip, externally observed behaviour will be as needed because we will have outcome
                // very soon


                if (!(applicationInterchangeProfile.isOnDeviceCvmSupported() && configuration.isDeviceCvmSupported())) {
                    // CCC1
                    CccResult rezCcc;
                    try {
                        rezCcc = ccc1.process(tlvDb, mastercardMagstripeFailedCounter, nUn, random,
                                transactionData.getAmountAuthorized(), readerLimits.readerCvmRequiredLimit, messageHoldTime);

                    } catch (EmvException e) {
                        logger.warn(e.getMessage());
                        return parsingError();
                    }
                    return rezCcc.getOutcome();
                } else {
                    // CCC2
                    CccResult rezCcc = ccc2.process(tlvDb, mastercardMagstripeFailedCounter, nUn, random,
                            transactionData.getAmountAuthorized(), readerLimits.readerCvmRequiredLimit, cvm, messageHoldTime);
                    return rezCcc.getOutcome();
                }
            }
        } catch (TlvException | EmvException e) {
            logger.warn("Exception: ", e);
            return invalidCccResponseParsingError();
        }
    }


    private DekDetProcessor.Result dekDet() {
        return dekDet(false);
    }


    private DekDetProcessor.Result dekDet(boolean noDataNeeded) {
        try {
            DekDetProcessor.Result rez = dekDetProcessor.process(deDataNeeded.asList(), deDataToSend.asList(), noDataNeeded);
            deDataNeeded.initialize();
            deDataToSend.initialize();
            // this bellow is essentially UpdateWithDetData(Terminal Sent Data)
            for (Tlv tlv : rez.getData()) {
                Optional<MastercardTag> mtO = MastercardTags.get(tlv.getTag());
                if ((mtO.isPresent() || tlvDb.isTagPresent(tlv.getTag())) &&
                        mtO.get().isDetUpdateAllowed()
                ) {

                    if (MastercardTags.isTestTag(mtO.get())) {
                        if (!tlvDb.isTagPresentAndNonEmpty(tlv.getTag())) {
                            continue;
                        }
                    }
                    tlvDb.updateOrAddDet(tlv);
                    if (tlv.getTag() == EmvTag.TAGS_TO_READ) {
                        List<EmvTag> tagsToRead = TlvUtils.extractTagsList(tlvDb.get(EmvTag.TAGS_TO_READ).getValueBytes());
                        deTagsToReadYet.addAll(tagsToRead);
                    }

                    if (tlv.getTag() == EmvTag.TAGS_TO_WRITE_BEFORE_GEN_AC) {
                        List<Tlv> tagsToWriteBeforeGenAc = TlvUtils.getTlvs(tlv.getValueBytes());
                        deTagsToWriteYetBeforeGenAc.addAll(tagsToWriteBeforeGenAc);
                    }

                    if (tlv.getTag() == EmvTag.TAGS_TO_WRITE_AFTER_GEN_AC) {
                        List<Tlv> tagsToWriteAfterGenAc = TlvUtils.getTlvs(tlv.getValueBytes());
                        deTagsToWriteYetAfterGenAc.addAll(tagsToWriteAfterGenAc);
                    }
                }
            }

            return rez;
        } catch (TlvException e) {
            logger.error("Problem with DEK-DET: {}", e.getMessage());
            return new DekDetProcessor.Result(new ArrayList<>(), false, false);
        }
    }


    /**
     * This method handles S1.7
     *
     * @param selectedApp
     * @return
     * @throws ParsingException
     * @throws CardDataMissingException
     */
    private SelectedApplication reprocessSelectedApp(SelectedApplication selectedApp) throws ParsingException,
            CardDataMissingException {

        SelectedApplication.Builder b = new SelectedApplication.Builder(selectedApp.getCandidate());

        try {
            List<Tlv> tlvsFci = TlvUtils.getChildTlvs(selectedApp.getRawData(), EmvTag.FCI_TEMPLATE);
            try {
                MastercardTags.checkInValidTemplate(tlvsFci, EmvTag.FCI_TEMPLATE);
                MastercardTags.checkValidSizes(tlvsFci, false);
            } catch (EmvException e) {
                throw new ParsingException(e);
            }

            for (Tlv tlv : tlvsFci) {
                try {
                    tlvDb.updateOrAddRa(tlv);
                } catch (EmvException e) {
                    throw new ParsingException(e);
                }
            }


            if (tlvDb.isTagPresent(EmvTag.FCI_PROPRIETARY_TEMPLATE)) {
                List<Tlv> tlvsA5 = TlvUtils.getTlvs(tlvDb.get(EmvTag.FCI_PROPRIETARY_TEMPLATE).getValueBytes());

                if (tlvsA5.size() > 0) {
                    try {
                        MastercardTags.checkInValidTemplate(tlvsA5, EmvTag.FCI_PROPRIETARY_TEMPLATE);
                        MastercardTags.checkValidSizes(tlvsA5, false);
                    } catch (EmvException e) {
                        throw new ParsingException(e);
                    }

                    for (Tlv tlv : tlvsA5) {
                        try {
                            tlvDb.updateOrAddRa(tlv);
                        } catch (EmvException e) {
                            throw new ParsingException(e);
                        }
                    }
                }
            }


            if (tlvDb.isTagPresent(EmvTag.FCI_ISSUER_DISCRETIONARY_DATA)) {
                List<Tlv> tlvsBf0c = TlvUtils.getTlvs(tlvDb.get(EmvTag.FCI_ISSUER_DISCRETIONARY_DATA).getValueBytes());

                if (tlvsBf0c.size() > 0) {
                    try {
                        MastercardTags.checkInValidTemplate(tlvsBf0c, EmvTag.FCI_ISSUER_DISCRETIONARY_DATA);
                        MastercardTags.checkValidSizes(tlvsBf0c, false);
                    } catch (EmvException e) {
                        throw new ParsingException(e);
                    }

                    for (Tlv tlv : tlvsBf0c) {
                        try {
                            tlvDb.updateOrAddRa(tlv);
                        } catch (EmvException e) {
                            throw new ParsingException(e);
                        }
                    }
                }
            }


            if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.DEDICATED_FILE_NAME) || !tlvDb.isTagPresent(EmvTag.FCI_PROPRIETARY_TEMPLATE)) {
                throw new CardDataMissingException("Missing DEDICATED_FILE_NAME");
            }

            b.dfName(tlvDb.get(EmvTag.DEDICATED_FILE_NAME).getValueBytes());

            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.APPLICATION_LABEL)) {
                b.label(tlvDb.get(EmvTag.APPLICATION_LABEL).getValueAsString());
            }


            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.APPLICATION_PRIORITY_INDICATOR)) {
                b.priorityIndicator(tlvDb.get(EmvTag.APPLICATION_PRIORITY_INDICATOR).getValueAsHexInt());
            }

            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.LANGUAGE_PREFERENCE)) {
                b.languagePreference(tlvDb.get(EmvTag.LANGUAGE_PREFERENCE).getValueAsString());
            }

            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.PDOL)) {
                b.pdol(tlvDb.get(EmvTag.PDOL).getValueBytes());
            }

            IssuerCodeTableIndex encodingEnum = null;
            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.ISSUER_CODE_TABLE_INDEX)) {
                int encoding = tlvDb.get(EmvTag.ISSUER_CODE_TABLE_INDEX).getValueAsHexInt();
                encodingEnum = IssuerCodeTableIndex.valueOf(encoding);
                if (encodingEnum == null) {
                    logger.warn("Unable to resolve IssuerCodeTableIndex with value: " + encoding);
                }
            }


            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.APP_PREFERRED_NAME)) {
                if (encodingEnum != null) {
                    try {
                        String appPreferredName = new String(tlvDb.get(EmvTag.APP_PREFERRED_NAME).getValueBytes(), encodingEnum.getCodeTableName());
                        b.applicationPreferredName(appPreferredName);
                    } catch (UnsupportedEncodingException e) {
                        logger.error("Error: {}", e);
                    }
                } else {
                    try {
                        String appPreferredName = new String(tlvDb.get(EmvTag.APP_PREFERRED_NAME).getValueBytes(), DEFAULT_ENCODING);
                        b.applicationPreferredName(appPreferredName);
                    } catch (UnsupportedEncodingException e) {
                        logger.error("Error: {}", e);
                    }
                }

            }

        } catch (TlvException e) {
            throw new ParsingException("Unable to get child tlvs for FCI");
        }


        return b.build();
    }


    private MastercardKernelConfiguration extractConfiguration(TlvMapReadOnly map) {
        boolean idsSupported = false;
        boolean emvModeNotSupported = false;
        boolean magstripeModeNotSupported = false;
        boolean balanceReadingSupported = false;
        boolean tornTransactionRecoverySupported = false;
        boolean deviceCvmSupported = false;
        boolean relayResistanceSupported = false;
        byte[] terminalActionCodeDefault = {0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] terminalActionCodeDenial = {0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] terminalActionCodeOnline = {0x00, 0x00, 0x00, 0x00, 0x00};

        if (map.isTagPresentAndNonEmpty(EmvTag.KERNEL_CONFIGURATION)) {
            Tlv kernelConfig = map.get(EmvTag.KERNEL_CONFIGURATION);

            BigInteger bi = BigInteger.valueOf(kernelConfig.getValueBytes()[0]);
            magstripeModeNotSupported = bi.testBit(8 - 1);
            emvModeNotSupported = bi.testBit(7 - 1);
            deviceCvmSupported = bi.testBit(6 - 1);
            relayResistanceSupported = bi.testBit(5 - 1);
        }


        if (map.isTagPresentAndNonEmpty(EmvTag.TERMINAL_ACTION_CODE_DEFAULT)) {
            Tlv kernelConfig = map.get(EmvTag.TERMINAL_ACTION_CODE_DEFAULT);
            terminalActionCodeDefault = kernelConfig.getValueBytes();
        }

        if (map.isTagPresentAndNonEmpty(EmvTag.TERMINAL_ACTION_CODE_DENIAL)) {
            Tlv kernelConfig = map.get(EmvTag.TERMINAL_ACTION_CODE_DENIAL);
            terminalActionCodeDenial = kernelConfig.getValueBytes();
        }

        if (map.isTagPresentAndNonEmpty(EmvTag.TERMINAL_ACTION_CODE_ONLINE)) {
            Tlv kernelConfig = map.get(EmvTag.TERMINAL_ACTION_CODE_ONLINE);
            terminalActionCodeOnline = kernelConfig.getValueBytes();
        }


        return new MastercardKernelConfiguration(emvModeNotSupported, magstripeModeNotSupported, deviceCvmSupported,
                relayResistanceSupported, terminalActionCodeDefault, terminalActionCodeDenial, terminalActionCodeOnline);
    }


    private Outcome emvModeProcessing(Transceiver transceiver,
                                      byte[] applicationFileLocator,
                                      ApplicationInterchangeProfile applicationInterchangeProfile,
                                      TransactionTimestamp ts,
                                      CountryCode countryCode,
                                      ReaderLimits readerLimits,
                                      String aid,
                                      byte[] pdolData,
                                      byte[] terminalCapabilitiesRaw,
                                      ApplicationCapabilityInformation applicationCapabilitiesInformation) throws IOException {


        try {
            logger.debug("EMV mode");
            isEmvMode = true;

            int readerContactlessTransactionLimit;


            // S3.30, S3.31, S3.32
            applicationFileLocator = resolveFinalApplicationFileLocatorEmv(applicationFileLocator);


            // S3.33
            if (applicationInterchangeProfile.isOnDeviceCvmSupported() && configuration.isDeviceCvmSupported()) {
                // S3.34
                readerContactlessTransactionLimit = readerLimits.contactlessReaderLimitOnDeviceCvm;
            } else {
                // S3.35
                readerContactlessTransactionLimit = readerLimits.contactlessReaderLimitNoOnDeviceCvm;
            }


            // RRP
            // S3.60
            Rrp.RrpResult rrpRez = null;
            if (configuration.isRelayResistanceSupported() && applicationInterchangeProfile.isRelayResistanceSupported()) {
                logger.debug("RRP supported, will execute it.");
                rrpRez = rrp.process(transceiver, tlvDb);
                if (!rrpRez.isOk()) {
                    if (rrpRez.getErrorType() == Rrp.RrpResult.ErrorType.PARSE_ERROR) {
                        logger.warn("RRP parsing error");
                        return parsingError();
                    } else if (rrpRez.getErrorType() == Rrp.RrpResult.ErrorType.TRY_ANOTHER_CARD_ERROR) {
                        MastercardErrorIndication ei;
                        if (rrpRez.getSw() != null) {
                            ei = MastercardErrorIndication.createL2StatusBytesError(rrpRez.getSw(),
                                    MastercardMessageIdentifier.ERROR_OTHER_CARD);
                        } else {
                            ei = MastercardErrorIndication.
                                    createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_ERROR,
                                            ERROR_OTHER_CARD);

                        }
                        return Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));
                    } else {
                        throw new AssertionError("Must not reach here. Probably you added another enum value to ErrorType and forgot " +
                                "to handle it here");
                    }
                } else {
                    terminalVerificationResults.setRelayResistancePerformed(TerminalVerificationResults.RelayResistancePerformed.PERFORMED);

                    if (rrpRez.isRelayResistanceThresholdExceeded()) {
                        terminalVerificationResults.setRelayResistanceThresholdExceeded(true);
                    }

                    if (rrpRez.isRelayResistanceTimeLimitsExceeded()) {
                        terminalVerificationResults.setRelayResistanceTimeLimitsExceeded(true);
                    }

                    tlvDb.updateOrAddKernel(TvrUtil.asTlv(terminalVerificationResults));
                }
            } else {
                // S3.65
                terminalVerificationResults.setRelayResistancePerformed(
                        TerminalVerificationResults.RelayResistancePerformed.NOT_PERFORMED);
                tlvDb.updateOrAddKernel(TvrUtil.asTlv(terminalVerificationResults));
            }

            // S3R1.1
            try {
                List<Afl> afls = aflsExtractor.extractAfls(applicationFileLocator);
                if (afls == null || afls.size() == 0) {
                    // S3R1.5
                    return cardDataError();
                }

                aflRecordsQueue.addAll(McAflRecord.explodeAfls(afls));
            } catch (EmvException e) {
                // S3R1.6
                return cardDataError();
            }


            getDataTag = deTagsToReadYet.getNextGetDataTag();
            if (getDataTag != null) {
                // S3R1.2, S3R1.3 - postponing execution of the command until S3R1.21, we don't want multithreading
                // S3R1.4
                nextCmd = NextCmd.GET_DATA;
                getDataResp = executeGetData(getDataTag);
            } else {
                // S3R1.7, S3R1.8 - postponing execution of the command until S3R1.21, we don't want multithreading
                // S3R1.9
                nextCmd = NextCmd.READ_RECORD;
                readRecordResp = executeReadRecord(aflRecordsQueue.remove());
            }


            // S3R1.10
            if (idsStatus.isRead()) {
                // S3R1.11
                if (tlvDb.isTagPresentAndNonEmpty(EmvTag.DS_SLOT_AVAILABILITY)) {
                    deDataToSend.add(tlvDb.get(EmvTag.DS_SLOT_AVAILABILITY));
                }
                if (tlvDb.isTagPresentAndNonEmpty(EmvTag.DS_SUMMARY_1)) {
                    deDataToSend.add(tlvDb.get(EmvTag.DS_SUMMARY_1));
                }
                if (tlvDb.isTagPresentAndNonEmpty(EmvTag.DS_UNPREDICTABLE_NUMBER)) {
                    deDataToSend.add(tlvDb.get(EmvTag.DS_UNPREDICTABLE_NUMBER));
                }
                if (tlvDb.isTagPresentAndNonEmpty(EmvTag.DS_SLOT_MANAGEMENT_CONTROL)) {
                    deDataToSend.add(tlvDb.get(EmvTag.DS_SLOT_MANAGEMENT_CONTROL));
                }
                if (tlvDb.isTagPresent(EmvTag.DS_ODS_CARD)) {
                    deDataToSend.add(tlvDb.get(EmvTag.DS_ODS_CARD));
                }

                // UNPREDICTABLE_NUMBER is added to tlvDb by commonDolDataPreparer
                deDataToSend.add(tlvDb.get(EmvTag.UNPREDICTABLE_NUMBER));

                // S3R1.12
                if (!((tlvDb.isTagPresentAndNonEmpty(EmvTag.DS_SLOT_AVAILABILITY) &&
                        tlvDb.isTagPresentAndNonEmpty(EmvTag.DS_SUMMARY_1) &&
                        tlvDb.isTagPresentAndNonEmpty(EmvTag.DS_UNPREDICTABLE_NUMBER) &&
                        !tlvDb.isTagPresent(EmvTag.DS_ODS_CARD)) ||
                        (tlvDb.isTagPresentAndNonEmpty(EmvTag.DS_SUMMARY_1) && tlvDb.isTagPresent(EmvTag.DS_ODS_CARD))
                )) {

                    // S3R1.13
                    idsStatus.setRead(false);
                    tlvDb.updateOrAddKernel(idsStatus.toTlv());
                }
            }

            // S3R1.14
            processTagsToReadYet(tlvDb, deTagsToReadYet, deDataToSend);

            // S3R1.15
            if (!deDataNeeded.isEmpty() || (!deDataToSend.isEmpty() && deTagsToReadYet.isEmpty())) {
                // S3R1.16
                logger.debug("S3R1.16");
                dekDet();
            }


            // S3R1.17
            if (applicationInterchangeProfile.isCdaSupported() && terminalCapabilities13.isCdaSupported()) {
                // S3R1.19
                isOdaStatusCdaSet = true;
            } else {
                // S3R1.18
                if (idsStatus.isRead()) {
                    // S3R1.19
                    isOdaStatusCdaSet = true;
                } else {
                    // S3R1.20
                    terminalVerificationResults.setOfflineDataAuthenticationNotPerformed(true);
                    tlvDb.updateOrAddKernel(TvrUtil.asTlv(terminalVerificationResults));
                }
            }

            boolean exitLoop = false;
            long start = 0;
            do {
                // S3R1.21
                switch (nextCmd) {
                    case GET_DATA:
                        processGetData(getDataResp, getDataTag);
                        break;
                    case READ_RECORD:
                        if (terminateOnNextRa) {
                            logger.warn("Terminate on next (this) RA");
                            return parsingError();
                        }
                        try {
                            byte[] statusWord = processReadRecord(readRecordResp, currentMcAflRecord);
                            if (isStopSignalReceived) { // S4.7
                                // S4.8
                                return MastercardKernel.createStopOutcome();
                            }

                            if (statusWord != null) {
                                // S4.10.1 & S4.10.2
                                UserInterfaceRequest uiReq = new UserInterfaceRequest(StandardMessages.TRY_ANOTHER_CARD,
                                        ContactlessTransactionStatus.NOT_READY, 0, null, null, 0, null);
                                Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);
                                b.uiRequestOnOutcome(uiReq);
                                b.start(Outcome.Start.NOT_APPLICABLE);


                                MastercardErrorIndication ei =
                                        MastercardErrorIndication.createL2StatusBytesError(statusWord, MastercardMessageIdentifier.ERROR_OTHER_CARD);

                                b.discretionaryData(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));

                                return b.build();
                            }
                        } catch (EmvException e) {
                            logger.warn(e.getMessage());
                            return parsingError();
                        }
                        break;
                    case NONE:
                        boolean loopForData = false;
                        boolean noDetResponse = false;
                        boolean dekSent;
                        int timeout = tlvDb.get(EmvTag.TIME_OUT_VALUE).getValueAsHexInt();

                        do {
                            dekSent = false;
                            // S456.5
                            if (tlvDb.isTagPresent(EmvTag.PROCEED_TO_FIRST_WRITE_FLAG) &&
                                    tlvDb.get(EmvTag.PROCEED_TO_FIRST_WRITE_FLAG).getLength() == 0) {
                                // S456.6
                                deDataNeeded.add(EmvTag.PROCEED_TO_FIRST_WRITE_FLAG);
                                loopForData = true;
                            } else {
                                // S456.11
                                if ((tlvDb.isTagPresentAndNonEmpty(EmvTag.PROCEED_TO_FIRST_WRITE_FLAG))) {
                                    loopForData = tlvDb.get(EmvTag.PROCEED_TO_FIRST_WRITE_FLAG).getValueBytes()[0] == 0;
                                }
                            }

                            if (loopForData) {
                                // S456.7
                                processTagsToReadYet(tlvDb, deTagsToReadYet, deDataToSend);

                                // S456.8
                                if (!deDataNeeded.isEmpty() || (!deDataToSend.isEmpty() && deTagsToReadYet.isEmpty())) {
                                    // S456.9
                                    logger.debug("S456.9");
                                    dekSent = true;
                                    DekDetProcessor.Result dekDetRez = dekDet();
                                    if (dekDetRez.isDekFound()) {
                                        if (!dekDetRez.isAllDetEmpty()) {
                                            start = 0; // stop timer
                                        } else {
                                            noDetResponse = true;
                                        }

                                        getDataTag = deTagsToReadYet.getNextGetDataTag();
                                        if (getDataTag != null) {
                                            // S4.16
                                            nextCmd = NextCmd.GET_DATA;
                                            if (getDataResp != null) {
                                                getDataResp.purgeData();
                                            }
                                            getDataResp = executeGetData(getDataTag);
                                        } else {
                                            exitLoop = true;
                                        }
                                    } else {
                                        // no DET found, exit
                                        exitLoop = true;
                                        loopForData = false;
                                    }
                                }

                                if (start == 0) {
                                    // S456.10
                                    logger.debug("Starting timeout timer for PROCEED_TO_FIRST_WRITE_FLAG S456.10");
                                    start = timeProvider.getVmTime();
                                }
                            } else {
                                if (nextCmd == NextCmd.NONE) {
                                    exitLoop = true;
                                }
                            }

                            if ((tlvDb.isTagPresentAndNonEmpty(EmvTag.PROCEED_TO_FIRST_WRITE_FLAG))) {
                                loopForData = tlvDb.get(EmvTag.PROCEED_TO_FIRST_WRITE_FLAG).getValueBytes()[0] == 0;
                            }

                            if (loopForData && (!dekSent || noDetResponse)) {
                                try {
                                    do {
                                        Thread.sleep(20);
                                        if (start > 0 && timeProvider.getVmTime() > (start + timeout)) {
                                            logger.warn("Timeout during wait for PROCEED_TO_FIRST_WRITE_FLAG");

                                            MastercardErrorIndication ei = MastercardErrorIndication.
                                                    createL3Error(MastercardErrorIndication.L3Error.TIME_OUT, NOT_AVAILABLE);

                                            Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);
                                            b.discretionaryData(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));

                                            return b.build();
                                        }
                                    } while (true);
                                } catch (InterruptedException e) {
                                    // ignore
                                }
                            }
                        } while (loopForData);
                        break;
                }
            } while (!exitLoop);

//        // S456.1 - skip, we are NextCmd.NONE here
//
//        // S456.2
//        processTagsToReadYet(tlvDb, deTagsToReadYet, deDataToSend);
//
//        // S456.3
//        if (!deDataToSend.isEmpty() && deTagsToReadYet.isEmpty()) {
//            logger.debug("S456.4 - RR1");
//            dekDet();
//        }


            // S456.12
            if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.AMOUNT_AUTHORISED_NUMERIC)) {
                // S456.13
                MastercardErrorIndication ei = MastercardErrorIndication.
                        createL3Error(MastercardErrorIndication.L3Error.AMOUNT_NOT_PRESENT, NOT_AVAILABLE);

                Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);

                b.discretionaryData(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));

                return b.build();
            }

            // Creating new transaction data because DEK-DET might update it (retarted)
            TransactionData transactionData = null;
            try {
                Currency newCurrency = null;
                if (tlvDb.isTagPresentAndNonEmpty(TRANSACTION_CURRENCY_CODE)) {
                    Optional<Currency> newCurrencyO = Currency.find(tlvDb.get(TRANSACTION_CURRENCY_CODE).getValueAsBcdInt());
                    if (newCurrencyO.isPresent()) {
                        newCurrency = newCurrencyO.get();
                    }
                }
                transactionData = new TransactionData(
                        tlvDb.get(AMOUNT_AUTHORISED_NUMERIC).getValueAsBcdInt(),
                        tlvDb.isTagPresentAndNonEmpty(AMOUNT_OTHER_NUMERIC) ? tlvDb.get(AMOUNT_OTHER_NUMERIC).getValueAsBcdInt() : 0,
                        newCurrency,
                        TransactionType.valueOf(tlvDb.get(TRANSACTION_TYPE).getValueBytes()[0])
                );
                logger.debug("{}", transactionData);
            } catch (TlvException e) {
                throw new AssertionError("Cannot happen");
            }

            // S456.14
            if (transactionData.getAmountAuthorized() > readerContactlessTransactionLimit) {
                MastercardErrorIndication ei = MastercardErrorIndication.
                        createL2Error(MastercardErrorIndication.L2Error.MAX_LIMIT_EXCEEDED, NOT_AVAILABLE);

                return selectNext(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));
            }

            List<TagAndLength> cdol1 = null;
            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.CDOL1)) {
                Tlv cdol1Tlv = tlvDb.get(EmvTag.CDOL1);
                try {
                    cdol1 = DolParser.parse(cdol1Tlv.getValueBytes());
                } catch (TlvException e) {
                    logger.warn("cdol1 parsing error");
                    return parsingError();
                }
            }


            // S456.16
            if (cdol1 == null || cdol1.size() == 0 ||
                    !tlvDb.isTagPresentAndNonEmpty(EmvTag.PAN) ||
                    !tlvDb.isTagPresentAndNonEmpty(EmvTag.APP_EXPIRATION_DATE)) {

                // S456.17.1 & S456.17.2
                logger.warn("S456.17.1 & S456.17.2");
                return cardDataMissing();
            }

            // S456.18
            if (idsStatus.isRead()) {
                // S456.19

                SensitiveData panSd = tlvDb.getPan().get();
                byte[] panBa = panSd.getData();

                String pan = ByteUtils.toHexString(panBa).replace("F", "");
                String panSeqNum;
                if (tlvDb.isTagPresentAndNonEmpty(EmvTag.PAN_SEQUENCE_NUMBER)) {
                    panSeqNum = ByteUtils.toHexString(tlvDb.get(EmvTag.PAN_SEQUENCE_NUMBER).getValueBytes());
                } else {
                    panSeqNum = "00";
                }
                String cmpPan = pan + panSeqNum;
                if (cmpPan.length() % 2 != 0) {
                    cmpPan = "0" + cmpPan;
                }

                panSd.purge();
                ByteUtils.purge(panBa);

                cmpPan = StringUtils.leftPad(cmpPan, 16, "0");
                String dsId = tlvDb.get(EmvTag.DS_ID).getValueAsHex();
                if (!cmpPan.equals(dsId)) {
                    // S456.20.1, S456.20.2
                    logger.warn("S456.20.1");
                    return cardDataError();
                }
            }

            // S456.21
            processTagsToReadYet(tlvDb, deTagsToReadYet, deDataToSend);
//        for (EmvTag tag : deTagsToReadYet.asList()) {
//            if (tlvDb.isTagPresent(tag)) {
//                deDataToSend.add(tlvDb.get(tag));
//            } else {
//                Optional<MastercardTag> mo = MastercardTags.get(tag);
//                if (mo.isPresent()) {
//                    deDataToSend.add(new Tlv(tag, 0, new byte[0]));
//                }
//            }
//        }

            // S456.22
            if (!deDataToSend.isEmpty()) {
                // S456.23
                logger.debug("S456.23");
                dekDet(true);
            }


            String rid = aid.substring(0, 10);
            Optional<CaPublicKeyDb> caPublicKeyDb = caRidDb.getByRid(rid);

            // S456.24
            if (isOdaStatusCdaSet) {
                // S456.25
                if (!checkAllCdaObjectsPresent(tlvDb)) {
                    terminalVerificationResults.setIccDataMissing(true);
                    terminalVerificationResults.setCdaFailed(true);
                    tlvDb.updateOrAddKernel(TvrUtil.asTlv(terminalVerificationResults));
                } else {
                    int caCertIndex = tlvDb.get(EmvTag.CA_PUBLIC_KEY_INDEX_CARD).getValueAsHexInt();
                    Optional<CaPublicKeyData> caPublicKeyDataO = caPublicKeyDb.get().getByIndex(caCertIndex);
                    if (!caPublicKeyDataO.isPresent()) {
                        terminalVerificationResults.setCdaFailed(true);
                        tlvDb.updateOrAddKernel(TvrUtil.asTlv(terminalVerificationResults));
                    }
                }

                // S456.26
                if (isSdaPresentAndOnlyAip(tlvDb)) {
                    // S456.28
                    if (isEnoughSpaceInStaticDataToBeAuthenticated(
                            tlvDb.get(EmvTag.APPLICATION_INTERCHANGE_PROFILE).getValueBytes())) {

                        staticDataToBeAuthenticated.write(tlvDb.get(EmvTag.APPLICATION_INTERCHANGE_PROFILE).
                                getValueBytes());
                    } else {
                        terminalVerificationResults.setCdaFailed(true);
                        tlvDb.updateOrAddKernel(TvrUtil.asTlv(terminalVerificationResults));
                    }
                } else {
                    // S456.27.1, S456.27.2
                    MastercardErrorIndication ei = MastercardErrorIndication.
                            createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_ERROR,
                                    ERROR_OTHER_CARD);

                    return Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));
                }
            }


            byte cvmCapabilitiesByte;
            // S456.30
            if (transactionData.getAmountAuthorized() > readerLimits.readerCvmRequiredLimit) {

                // S456.31
                receiptRequired = true;

                // S456.32
                cvmCapabilitiesByte = tlvDb.get(EmvTag.CVM_CAPABILITY_CVM_REQUIRED).getValueBytes()[0];
                cvmCapabilities = TerminalCapabilities2Cvm.fromByte(cvmCapabilitiesByte);
            } else {
                // S456.33
                cvmCapabilitiesByte = tlvDb.get(EmvTag.CVM_CAPABILITY_NO_CVM_REQUIRED).getValueBytes()[0];
                cvmCapabilities = TerminalCapabilities2Cvm.fromByte(cvmCapabilitiesByte);
            }


            terminalCapabilitiesRaw[1] = cvmCapabilitiesByte;
            tlvDb.updateOrAddKernel(new Tlv(EmvTag.TERMINAL_CAPABILITIES, terminalCapabilitiesRaw.length, terminalCapabilitiesRaw));


            // S456.34
            // BR1.1
            if (applicationCapabilitiesInformation != null && applicationCapabilitiesInformation.isSupportBalanceReading()) {
                // BR1.2
                if (tlvDb.isTagPresent(EmvTag.BALANCE_READ_BEFORE_GEN_AC)) {
                    // BR1.3 & BR1.4
                    ApduResponsePackage resp = executeGetData(EmvTag.OFFLINE_ACCUMULATOR_BALANCE);
                    // S16.8
                    if (resp.isSuccess()) {
                        // S16.9
                        if (resp.getDataNoStatusBytes().length == 9) {
                            try {
                                Tlv tlvBalance = TlvUtils.getNextTlv(resp.getData());
                                if (tlvBalance.getTag() == EmvTag.OFFLINE_ACCUMULATOR_BALANCE &&
                                        tlvBalance.getValueBytes().length == 6) {

                                    tlvDb.updateOrAddKernel(new Tlv(EmvTag.BALANCE_READ_BEFORE_GEN_AC, 6, tlvBalance.getValueBytes()));
                                }
                            } catch (TlvException e) {
                                // do nothing
                            }
                        }
                    }
                    resp.purgeData();
                }
            }


            // S456.35
            try {
                processingRestrictions.process(terminalVerificationResults,
                        tlvDb,
                        transactionData,
                        ts,
                        countryCode);

            } catch (TlvException | EmvException e) {
                // this may happen if the card has returned invalid data. For example if Issuer Country Code cannot be
                // converted to int
                logger.warn("processingRestrictions", e);
                return parsingError();
            }


            // S456.36
            CvmSelectionResult cvmSelectionResult;
            try {
                cvmSelectionResult = cvmSelection.process(applicationInterchangeProfile,
                        tlvDb.getAsOptional(EmvTag.CVM_LIST),
                        transactionData,
                        tlvDb.getAsOptional(EmvTag.APPLICATION_CURRENCY_CODE),
                        cvmCapabilities,
                        terminalVerificationResults,
                        configuration.isDeviceCvmSupported(),
                        readerLimits.readerCvmRequiredLimit);
                tlvDb.updateOrAddKernel(TvrUtil.asTlv(terminalVerificationResults));
            } catch (EmvException e) {
                logger.warn("cvmSelectionResult", e);
                return cardDataError();
            }

            // dirty fix for receipt, otherwise we had to pollute return data all the way from RulesProcessor to here
            if (cvmSelectionResult.getCvm() == Outcome.Cvm.OBTAIN_SIGNATURE) {
                receiptRequired = true;
            }


            Tlv cvmResultsTlv = new Tlv(EmvTag.CVM_RESULTS, 3, cvmSelectionResult.getResults().getBytes());
            tlvDb.addKernel(cvmResultsTlv);


            // S456.37 - in our case, where the readerContactlessFloorLimit is always 0, this will be always true
            if (transactionData.getAmountAuthorized() > readerLimits.readerContactlessFloorLimit) {
                // S456.38
                terminalVerificationResults.setTransactionExceedsFloorLimit(true);
                tlvDb.updateOrAddKernel(TvrUtil.asTlv(terminalVerificationResults));
            }

            // S456.39
            TerminalType terminalType = TerminalType.fromCode(tlvDb.get(EmvTag.TERMINAL_TYPE).getValueBytes()[0]);
            ApplicationCryptogramType requestedApplicationCryptogramType = terminalActionAnalysis.process(tlvDb,
                    terminalVerificationResults,
                    configuration.getTerminalActionCodeDenial(),
                    configuration.getTerminalActionCodeOnline(),
                    configuration.getTerminalActionCodeDefault(),
                    terminalType);


            // S456.42
            if (!deTagsToWriteYetBeforeGenAc.isEmpty()) {
                if (putDataProcessor.processPutData(transceiver, deTagsToWriteYetBeforeGenAc)) {
                    // S12.12
                    tlvDb.updateOrAddKernel(new Tlv(EmvTag.PRE_GEN_AC_PUT_DATA_STATUS, 1, new byte[]{(byte) 0x80}));
                }
            }

            Tlv tlvTvr = new Tlv(EmvTag.TERMINAL_VERIFICATION_RESULTS, 5, terminalVerificationResults.toBytes());
            tlvDb.updateOrAddKernel(tlvTvr);


            CrlRid crlRid = new CrlRidImpl(rid, crl);

            // S456.43
            isAcStage = true;
            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.DRDOL) &&
                    tlvDb.get(EmvTag.MAX_NUMBER_TORN_TRANSACTION_LOG_REC).getValueBytes()[0] > 0) {

                byte[] panHash = AcStage.computePanHash(tlvDb.getPan().get(), tlvDb.getAsOptional(EmvTag.PAN_SEQUENCE_NUMBER));
                Optional<TornTransactionLogRecord> recO = tornTransactionLog.getIfExists(panHash);
                if (recO.isPresent()) {
                    if (!useLightLogging) {
                        logger.debug("Found torn transaction record: {}", ByteUtils.toHexString(recO.get().toTlv().getValueBytes()));
                    }

                    return acStage.recoverAcRoute(transceiver,
                            tlvDb,
                            terminalVerificationResults,
                            idsStatus,
                            isEmvMode,
                            requestedApplicationCryptogramType,
                            applicationCapabilitiesInformation,
                            rrpRez,
                            isOdaStatusCdaSet,
                            applicationInterchangeProfile,
                            applicationInterchangeProfile.isOnDeviceCvmSupported() && configuration.isDeviceCvmSupported(),
                            cdol1,
                            crlRid,
                            cvmSelectionResult.getCvm(),
                            receiptRequired,
                            caPublicKeyDb,
                            pdolData,
                            ts,
                            staticDataToBeAuthenticated.toByteArray(),
                            deTagsToWriteYetAfterGenAc,
                            messageHoldTime,
                            dsSummaryStatus,
                            recO.get(),
                            applicationCapabilitiesInformation != null && applicationCapabilitiesInformation.isSupportBalanceReading(),
                            idsStatus.isRead(),
                            applicationCapabilitiesInformation != null && applicationCapabilitiesInformation.isDataStorageVersion2(),
                            terminalCapabilities13
                    );

                } else {
                    logger.debug("No matching torn transaction record");
                    return acStage.generateAcRoute(transceiver,
                            tlvDb,
                            terminalVerificationResults,
                            idsStatus,
                            isEmvMode,
                            requestedApplicationCryptogramType,
                            applicationCapabilitiesInformation,
                            rrpRez,
                            isOdaStatusCdaSet,
                            applicationInterchangeProfile,
                            applicationInterchangeProfile.isOnDeviceCvmSupported() && configuration.isDeviceCvmSupported(),
                            cdol1,
                            crlRid,
                            cvmSelectionResult.getCvm(),
                            receiptRequired,
                            caPublicKeyDb,
                            pdolData,
                            ts,
                            staticDataToBeAuthenticated.toByteArray(),
                            deTagsToWriteYetAfterGenAc,
                            messageHoldTime,
                            dsSummaryStatus,
                            terminalCapabilities13
                    );
                }
            } else {
                return acStage.generateAcRoute(transceiver,
                        tlvDb, terminalVerificationResults, idsStatus, isEmvMode, requestedApplicationCryptogramType,
                        applicationCapabilitiesInformation,
                        rrpRez, isOdaStatusCdaSet, applicationInterchangeProfile,
                        applicationInterchangeProfile.isOnDeviceCvmSupported() && configuration.isDeviceCvmSupported(),
                        cdol1, crlRid, cvmSelectionResult.getCvm(), receiptRequired, caPublicKeyDb, pdolData, ts,
                        staticDataToBeAuthenticated.toByteArray(), deTagsToWriteYetAfterGenAc, messageHoldTime, dsSummaryStatus,
                        terminalCapabilities13
                );
            }
        } catch (NfcConnectionLostException e) {
            if (terminateOnNextRa) {
                return parsingError();
            } else {
                throw e;
            }
        }
    }


    private ApduResponsePackage executeReadRecord(McAflRecord rec) throws IOException {
        ApduCommandPackage cmd = new ApduCommandPackage(ApduCommand.READ_RECORD, (byte) rec.getIndex(),
                (byte) ((rec.getAfl().getSfi() << 3) | 4), null, 0);

        logger.debug("(nfc) READ RECORD AFL {}, index {}", rec.getAfl(), rec.getIndex());
        currentMcAflRecord = rec;
        // S4.3
        return transceiver.transceive(cmd);
    }


    private byte[] processReadRecord(ApduResponsePackage resp, McAflRecord rec) throws IOException, EmvException {
        // S4.9
        if (!resp.isSuccess()) {
            byte[] rawSw = Arrays.copyOfRange(resp.getData(), resp.getData().length - 2, resp.getData().length);
            resp.purgeData();
            if (resp.getStatusWord() == ApduResponseStatusWord.SW_UNKNOWN) {
                return rawSw;
            } else {
                return resp.getStatusWord().statusWord;
            }
        }

        // S4.11, S4.12, S4.13 - skip, we check if signed bellow

        // S4.14 - 23 - moved to the end of the method in order to avoid multithreading

        // S4.24
        byte[] dataNoSuccessCode = Arrays.copyOfRange(resp.getData(), 0, resp.getData().length - 2);
        if (rec.getAfl().getSfi() <= 10) {
            try {
                List<Tlv> tlvs = new ArrayList<>();
                try {
                    tlvs = TlvUtils.getTlvs(dataNoSuccessCode);
                } catch (TlvException e) {
                    logger.debug("S4.24 Error parsing READ RECORD response: {}", e.getMessage());
                    terminateOnNextRa = true;
                }

                if (!terminateOnNextRa) {
                    if (tlvs.size() > 1) {
                        logger.warn("Unexpected tags in RR response");
                        throw new EmvException("Unexpected tags in RR response");
                    }

                    // S4.24 "Record[1] = '70'"
                    if (resp.getData().length > 0 && resp.getData()[0] == EmvTag.RECORD_TEMPLATE.getTagBytes()[0]) {
                        // S4.25
                        List<Tlv> children = new ArrayList<>();
                        try {
                            children = TlvUtils.getChildTlvs(resp.getData(), EmvTag.RECORD_TEMPLATE);
                        } catch (TlvException e) {
                            logger.debug("S4.25 Error parsing READ RECORD response: {}", e.getMessage());
                            terminateOnNextRa = true;
                        }

                        if (!terminateOnNextRa) {
                            MastercardTags.checkInValidTemplate(children, EmvTag.RECORD_TEMPLATE);

                            for (Tlv tlv : children) {
                                // S4.28
                                if (tlv.getTag() == EmvTag.CDOL1) {
                                    List<TagAndLength> cdol1 = DolParser.parse(tlv.getValueBytes());
                                    logger.debug("Found CDOL1 {}", cdol1);
                                    // S4.29
                                    for (TagAndLength tl : cdol1) {
                                        if (tlvDb.isTagPresent(tl.getTag()) && tlvDb.get(tl.getTag()).getValueBytes().length == 0) {
                                            deDataNeeded.add(tl.getTag());
                                        }
                                    }
                                } else if (tlv.getTag() == EmvTag.CDOL2) {
                                    List<TagAndLength> cdol2 = DolParser.parse(tlv.getValueBytes());
                                    logger.debug("Found CDOL2 {}", cdol2);
                                } else if (tlv.getTag() == EmvTag.DSDOL) { // S4.30

                                    // S4.31
                                    if (idsStatus.isRead()) {
                                        // S4.32
                                        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.DS_SLOT_MANAGEMENT_CONTROL)) {
                                            DsSlotManagementControl tmp = DsSlotManagementControl.
                                                    fromByte(tlvDb.get(EmvTag.DS_SLOT_MANAGEMENT_CONTROL).getValueBytes()[0]);

                                            if (!tmp.isLockedSlot()) {
                                                List<TagAndLength> dsDolList = DolParser.parse(tlv.getValueBytes());
                                                // S4.33
                                                for (TagAndLength tl : dsDolList) {
                                                    if (tlvDb.isTagPresent(tl.getTag()) && tlvDb.get(tl.getTag()).getValueBytes().length == 0) {
                                                        deDataNeeded.add(tl.getTag());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                MastercardTags.checkInValidTemplate(children, EmvTag.RECORD_TEMPLATE);
                                tlvDb.updateOrAddRa(tlv);
                            }


                            // S4.34
                            if (rec.getAfl().getRecordsInvolvedInDataAuthentication() > 0 &&
                                    rec.getIndex() - (rec.getAfl().getFirstRecord() - 1) <=
                                            rec.getAfl().getRecordsInvolvedInDataAuthentication() && isOdaStatusCdaSet) {

                                if (isEnoughSpaceInStaticDataToBeAuthenticated(tlvs.get(0).getValueBytes())) {
                                    logger.debug("Adding to staticDataToBeAuthenticated");
                                    staticDataToBeAuthenticated.write(tlvs.get(0).getValueBytes());
                                } else {
                                    terminalVerificationResults.setCdaFailed(true);
                                    tlvDb.updateOrAddKernel(TvrUtil.asTlv(terminalVerificationResults));
                                }
                            }
                        }
                    } else {
                        logger.warn("S4.26, S4.27.1, S4.27.2");
                        terminateOnNextRa = true;
                    }
                }
            } catch (TlvException e) {
                logger.warn(e.getMessage());
                throw new EmvException(e.getMessage());
            }
        } else {
            logger.warn("SFI > 10");

            // S4.34
            if (rec.getAfl().getRecordsInvolvedInDataAuthentication() > 0 &&
                    rec.getIndex() - (rec.getAfl().getFirstRecord() - 1) <=
                            rec.getAfl().getRecordsInvolvedInDataAuthentication() && isOdaStatusCdaSet) {

                //S4.35
                if (dataNoSuccessCode[0] == EmvTag.RECORD_TEMPLATE.getTagBytes()[0]) {
                    if (isEnoughSpaceInStaticDataToBeAuthenticated(dataNoSuccessCode)) {
                        staticDataToBeAuthenticated.write(dataNoSuccessCode);
                    } else {
                        logger.warn("No more room in static data. Failing CDA");
                        terminalVerificationResults.setCdaFailed(true);
                        tlvDb.updateOrAddKernel(TvrUtil.asTlv(terminalVerificationResults));
                    }
                } else {
                    logger.warn("Template not 70");
                    terminalVerificationResults.setCdaFailed(true);
                    tlvDb.updateOrAddKernel(TvrUtil.asTlv(terminalVerificationResults));
                }
            }
        }


        // S4.14 - skip, we do it outside with aflRecordsQueue.get

        // S4.15
        getDataTag = deTagsToReadYet.getNextGetDataTag();
        if (getDataTag != null) {
            // S4.16
            nextCmd = NextCmd.GET_DATA;
            if (getDataResp != null) {
                getDataResp.purgeData();
            }
            getDataResp = executeGetData(getDataTag);
            // S4.17, 18 - outside in process processGetData
        } else {
            // S4.19
            if (aflRecordsQueue.size() > 0) {
                // S4.21, 22 - on next call to this method

                // S4.23
                nextCmd = NextCmd.READ_RECORD;

                readRecordResp = executeReadRecord(aflRecordsQueue.remove());

                // S456.2
                processTagsToReadYet(tlvDb, deTagsToReadYet, deDataToSend);

                if (!deDataToSend.isEmpty() && deTagsToReadYet.isEmpty()) {
                    logger.debug("S456.4 - RR1");
                    dekDet();
                }


            } else {
                // S4.20
                nextCmd = NextCmd.NONE;
            }
        }


        resp.purgeData();

        if (nextCmd == NextCmd.NONE && terminateOnNextRa) {
            throw new EmvException("Parsing error");
        }

        return null;
    }


    private ApduResponsePackage executeGetData(EmvTag tag) throws IOException {
        expectedGetDataResponseTag = tag;
        logger.debug("(gd) GET DATA for {} ({})", tag.getName(), ByteUtils.toHexString(tag.getTagBytes()));

        return GetDataUtil.executeGetData(transceiver, tag);
    }


    private void processGetData(ApduResponsePackage resp, EmvTag tag) throws IOException {

        Tlv empty = new Tlv(tag, 0, new byte[0]);

        // S5.19
        if (resp.isSuccess()) {
            // S5.20
            try {
                // S5.21
                Tlv tlv = TlvUtils.getNextTlv(resp.getData());

                if (tlv.getTag() == expectedGetDataResponseTag) {
                    try {
                        tlvDb.updateOrAddRa(tlv);
                        deDataToSend.add(tlv);
                    } catch (EmvException e) {
                        logger.warn("Cannot update tlvDb: {}", e.getMessage());
                        deDataToSend.add(empty);
                    }
                } else {
                    logger.warn("GET DATA reponse contains unexepcted tag {}, was expecting {}", tlv.getTag().getName(), tag.getName());
                    deDataToSend.add(empty);
                }
            } catch (TlvException e) {
                logger.warn("Cannot parse GET DATA result");
                deDataToSend.add(empty);
            }
        } else {
            logger.warn("GET DATA result not OK");
            deDataToSend.add(empty);
        }

        getDataTag = deTagsToReadYet.getNextGetDataTag();
        if (getDataTag != null) {
            nextCmd = NextCmd.GET_DATA;
            getDataResp = executeGetData(getDataTag);
        } else {
            if (aflRecordsQueue.size() > 0) {
                nextCmd = NextCmd.READ_RECORD;
                readRecordResp = executeReadRecord(aflRecordsQueue.remove());
            } else {
                nextCmd = NextCmd.NONE;
            }
        }

        if (nextCmd == NextCmd.READ_RECORD) {
            // S456.2
            processTagsToReadYet(tlvDb, deTagsToReadYet, deDataToSend);

            if (!deDataToSend.isEmpty() && deTagsToReadYet.isEmpty()) {
                logger.debug("S456.4 - RR2");
                dekDet();
            }
        }
    }


    private Outcome parsingError() {
        MastercardErrorIndication ei = MastercardErrorIndication.
                createL2Error(MastercardErrorIndication.L2Error.PARSING_ERROR, ERROR_OTHER_CARD);

        return Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));
    }


    private Outcome cardDataMissing() {
        MastercardErrorIndication ei = MastercardErrorIndication.
                createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_MISSING, ERROR_OTHER_CARD);
        return Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));
    }


    @ForUnitTestsOnly
    TerminalCapabilities2Cvm getCvmCapabilities() {
        return cvmCapabilities;
    }


    @ForUnitTestsOnly
    boolean isReceiptRequired() {
        return receiptRequired;
    }


    @ForUnitTestsOnly
    TerminalVerificationResults getTerminalVerificationResults() {
        return terminalVerificationResults;
    }


    private boolean checkAllCdaObjectsPresent(TlvMapReadOnly tlvDb) {
        //noinspection RedundantIfStatement
        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.CA_PUBLIC_KEY_INDEX_CARD) &&
                tlvDb.isTagPresentAndNonEmpty(EmvTag.ISSUER_PUBLIC_KEY_CERT) &&
                tlvDb.isTagPresentAndNonEmpty(EmvTag.ISSUER_PUBLIC_KEY_EXPONENT) &&
                tlvDb.isTagPresentAndNonEmpty(EmvTag.ICC_PUBLIC_KEY_CERT) &&
                tlvDb.isTagPresentAndNonEmpty(EmvTag.ICC_PUBLIC_KEY_EXPONENT) &&
                tlvDb.isTagPresentAndNonEmpty(EmvTag.STATIC_DATA_AUTHENTICATION_TAG_LIST)
        ) {

            return true;
        } else {
            return false;
        }
    }


    private Outcome cardDataError() {
        MastercardErrorIndication ei = MastercardErrorIndication.
                createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_ERROR, ERROR_OTHER_CARD);

        return Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));
    }


    private static class ReaderLimits {
        private final int contactlessReaderLimitOnDeviceCvm;
        private final int contactlessReaderLimitNoOnDeviceCvm;
        private final int readerCvmRequiredLimit;
        private final int readerContactlessFloorLimit;


        ReaderLimits(TlvMapReadOnly map) {
            try {
                contactlessReaderLimitOnDeviceCvm = map.get(EmvTag.READER_CONTACTLESS_TRANSACTION_LIMIT_OD_CVM).getValueAsBcdInt();
                contactlessReaderLimitNoOnDeviceCvm = map.get(EmvTag.READER_CONTACTLESS_TRANSACTION_LIMIT_NO_OD_CVM).getValueAsBcdInt();
                readerCvmRequiredLimit = map.get(EmvTag.READER_CVM_REQUIRED_LIMIT).getValueAsBcdInt();
                readerContactlessFloorLimit = map.get(EmvTag.READER_CONTACTLESS_FLOOR_LIMIT).getValueAsBcdInt();
            } catch (TlvException e) {
                throw new RuntimeException("Invalid configuration data", e);
            }
        }


        @Override
        public String toString() {
            return PhosMessageFormat.format("contactlessReaderLimitOnDeviceCvm: {}, contactlessReaderLimitNoOnDeviceCvm: {}, " +
                            "readerCvmRequiredLimit: {}, readerContactlessFloorLimit: {}", contactlessReaderLimitOnDeviceCvm,
                    contactlessReaderLimitNoOnDeviceCvm,
                    readerCvmRequiredLimit,
                    readerContactlessFloorLimit);
        }


    }


    private boolean isEnoughSpaceInStaticDataToBeAuthenticated(byte[] data) {
        return staticDataToBeAuthenticated.size() + data.length <= 2048;
    }


    private enum NextCmd {
        GET_DATA,
        READ_RECORD,
        NONE
    }


    public static void logTlv(Logger logger, Tlv tlv) {
        String value = "Value: ";
        switch (tlv.getTag().getTagValueType()) {
            case BINARY:
                value += ByteUtils.toHexString(tlv.getValueBytes(), true);
                break;
            case NUMERIC:
                try {
                    value += tlv.getValueAsBcdInt() + " (" + ByteUtils.toHexString(tlv.getValueBytes(), true) + ")";
                } catch (TlvException e) {
                    value += ByteUtils.toHexString(tlv.getValueBytes());
                }
                break;
            case TEXT:
                value += tlv.getValueAsString() + " (" + ByteUtils.toHexString(tlv.getValueBytes(), true) + ")";
                break;
            case MIXED:
                value += ByteUtils.toHexString(tlv.getValueBytes(), true);
                break;
            case DOL:
                value += ByteUtils.toHexString(tlv.getValueBytes(), true);
                break;
            case TEMPLATE:
                value += ByteUtils.toHexString(tlv.getValueBytes(), true);
                break;
            case COMPRESSED_NUMERIC:
                String str = ByteUtils.toHexString(tlv.getValueBytes());
                int pos = str.indexOf('F');
                if (pos < 0) {
                    value += str;
                } else {
                    value += str.substring(0, pos);
                }

                value += " (" + ByteUtils.toHexString(tlv.getValueBytes(), true) + ")";
                break;
        }
        logger.debug("(tlvs) Tag: {} ({}), {}", tlv.getTag().getName(), ByteUtils.toHexString(tlv.getTag().getTagBytes()), value);
    }


    // the purpose of this method is to give a change to process() to add fieldOffRequest to the Outcome
    private Outcome processActual(Transceiver transceiver,
                                  TlvMap commonDolData,
                                  CountryCode countryCode,
                                  TransactionData transactionData,
                                  SelectedApplication selectedApp,
                                  TransactionTimestamp ts
    ) throws IOException {
        if (!isInitialized) {
            throw new IllegalStateException("Not initialized. Did you forgot to call init()?");
        }

        if (!useLightLogging) {
            logger.debug("(vis) Kernel start +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            logger.debug("(vis) Kernel start ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            logger.debug("(vis) Kernel start +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            logger.debug("(vis) Kernel start ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
//            logger.debug("Transaction data: {}", transactionData);
        }


        this.transceiver = transceiver;

        if (transactionType21) {
            transactionData = new TransactionData(transactionData.getAmountAuthorized(),
                    transactionData.getAmountOther(),
                    transactionData.getCurrency(),
                    TransactionType.REFUND
            );
        }

        // KS.1
        prepareTlvDb(tlvDb,
                commonDolData,
                selectedApp.getCandidate().getPreprocessedApplication().getAppConfig().getTlvConfigData(),
                noAmountAuthorizedNumericInAct,
                zeroLengthAuthorizedNumericInAct,
                extendedRrpMaxGrace,
                emptyAmountOther,
                amountOther250,
                noTransactionType,
                transactionData.getType(),
                noTransactionCurrencyCodeAndAmountOther,
                transactionType21,
                emptyTransactionCategoryCode,
                noTransactionCategoryCode,
                emptyMerchantCustomData,
                useAmountOtherZero);

        if (!useLightLogging) {
            logger.debug("Initial TLV DB (after ACT data accepted):");

            for (Tlv tlv : tlvDb.asList()) {
                logger.debug("    {} ({}): {}", tlv.getTag().getName(), ByteUtils.toHexString(tlv.getTag().getTagBytes(), true),
                        ByteUtils.toHexString(tlv.getValueBytes(), true));
            }
        }

        tornTransactionLog.setMaxSize(tlvDb.get(EmvTag.MAX_NUMBER_TORN_TRANSACTION_LOG_REC).getValueAsHexInt());

        try {
            messageHoldTime = tlvDb.get(EmvTag.MESSAGE_HOLD_TIME).getValueAsBcdInt();
        } catch (TlvException e) {
            throw new RuntimeException("Invalid value for MESSAGE_HOLD_TIME");
        }

        configuration = extractConfiguration(tlvDb);

        // KS.2 - we avoid to have such global variables. Outcome is created on demand.
        mobileSupportIndicator = 1;

        // we use updateOrAdd bellow because test configs may set MOBILE_SUPPORT_INDICATOR
        tlvDb.updateOrAddKernel(new Tlv(EmvTag.MOBILE_SUPPORT_INDICATOR, 1, new byte[]{mobileSupportIndicator}));


        // S1.1 - kernel activated

        // S1.7 - we need this first in order to prepare selectedAppReprocessed
        try {
            selectedAppReprocessed = reprocessSelectedApp(selectedApp);
        } catch (ParsingException e) {
            logger.warn(e.getMessage());
            MastercardErrorIndication ei = MastercardErrorIndication.
                    createL2Error(MastercardErrorIndication.L2Error.PARSING_ERROR, NOT_AVAILABLE);

            return selectNext(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));
        } catch (CardDataMissingException e) {
            logger.warn(e.getMessage());
            MastercardErrorIndication ei = MastercardErrorIndication.
                    createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_MISSING, NOT_AVAILABLE);

            return selectNext(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));
        }


        ApplicationCapabilityInformation applicationCapabilitiesInformation = null;
        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.APPLICATION_CAPABILITIES_INFORMATION)) {
            applicationCapabilitiesInformation =
                    ApplicationCapabilityInformation.fromBytes(tlvDb.get(
                            EmvTag.APPLICATION_CAPABILITIES_INFORMATION).getValueBytes());

            if (applicationCapabilitiesInformation.isSupportForFieldOffDetection()) {
                if (tlvDb.isTagPresentAndNonEmpty(EmvTag.HOLD_TIME_VALUE)) {
                    fieldOffRequest = tlvDb.get(EmvTag.HOLD_TIME_VALUE).getValueAsHexInt();
                }
            }
        }

        // S1.9 - skip most, we initialize variables on demand
        byte[] terminalCapabilitiesRaw = new byte[]{
                tlvDb.get(EmvTag.CARD_DATA_INPUT_CAPABILITY).getValueBytes()[0],
                0,
                tlvDb.get(EmvTag.SECURITY_CAPABILITY).getValueBytes()[0]};

        terminalCapabilities13 = TerminalCapabilities13.fromBytes(terminalCapabilitiesRaw);
        tlvDb.addKernel(new Tlv(EmvTag.TERMINAL_CAPABILITIES, terminalCapabilitiesRaw.length, terminalCapabilitiesRaw));


        // S1.10
        deDataNeeded.initialize();
        deDataToSend.initialize();
        deTagsToReadYet.initialize();

        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.TAGS_TO_READ)) {
            try {
                List<EmvTag> tagsToRead = TlvUtils.extractTagsList(tlvDb.get(EmvTag.TAGS_TO_READ).getValueBytes());
                deTagsToReadYet.addAll(tagsToRead);
            } catch (TlvException e) {
                MastercardErrorIndication ei = MastercardErrorIndication.
                        createL2Error(MastercardErrorIndication.L2Error.PARSING_ERROR, NOT_AVAILABLE);

                return Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));
            }
        } else {
            if (tlvDb.isTagPresent(EmvTag.TAGS_TO_READ)) {
                deDataNeeded.add(EmvTag.TAGS_TO_READ);
            }
        }

        // S1.11
        boolean missingPdolData = false;

        // S1.12
        for (TagAndLength tal : selectedAppReprocessed.getPdol()) {
            Optional<MastercardTag> tagO = MastercardTags.get(tal.getTag());
            if (tagO.isPresent() &&
                    tagO.get().isDetUpdateAllowed() &&
                    tlvDb.isTagPresent(tagO.get().getEmvTag()) &&
                    !MastercardTags.isTestTag(tagO.get()) &&
                    tlvDb.get(tagO.get().getEmvTag()).getValueBytes().length == 0) {
                missingPdolData = true;
                deDataNeeded.add(tagO.get().getEmvTag());
            }
        }

        // S1.13 and S1.14 are moved bellow all the S1 items because we want to avoid async

        // S1.15
        processTagsToReadYet(tlvDb, deTagsToReadYet, deDataToSend);

        // S1.16
        idsStatus = new IdsStatus();
        tlvDb.updateOrAddKernel(idsStatus.toTlv());
        dsSummaryStatus = new DsSummaryStatus();
        tlvDb.updateOrAddKernel(dsSummaryStatus.toTlv());

        deTagsToWriteYetBeforeGenAc.initialize();
        deTagsToWriteYetAfterGenAc.initialize();
        tlvDb.updateOrAddKernel(new Tlv(EmvTag.POST_GEN_AC_PUT_DATA_STATUS, 1, new byte[]{(byte) 0x00}));
        tlvDb.updateOrAddKernel(new Tlv(EmvTag.PRE_GEN_AC_PUT_DATA_STATUS, 1, new byte[]{(byte) 0x00}));

        if (tlvDb.isTagPresent(EmvTag.TAGS_TO_WRITE_BEFORE_GEN_AC)) {
            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.TAGS_TO_WRITE_BEFORE_GEN_AC)) {
                try {
                    List<Tlv> tagsToWriteBeforeGenAc = TlvUtils.getTlvs(tlvDb.get(EmvTag.TAGS_TO_WRITE_BEFORE_GEN_AC).getValueBytes());
                    deTagsToWriteYetBeforeGenAc.addAll(tagsToWriteBeforeGenAc);
                } catch (TlvException e) {
                    MastercardErrorIndication ei = MastercardErrorIndication.
                            createL2Error(MastercardErrorIndication.L2Error.PARSING_ERROR, NOT_AVAILABLE);

                    return Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));
                }
            } else {
                deDataNeeded.add(EmvTag.TAGS_TO_WRITE_BEFORE_GEN_AC);
            }
        }


        if (tlvDb.isTagPresent(EmvTag.TAGS_TO_WRITE_AFTER_GEN_AC)) {
            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.TAGS_TO_WRITE_AFTER_GEN_AC)) {
                try {
                    List<Tlv> tagsToWriteAfterGenAc = TlvUtils.getTlvs(tlvDb.get(EmvTag.TAGS_TO_WRITE_AFTER_GEN_AC).getValueBytes());
                    deTagsToWriteYetAfterGenAc.addAll(tagsToWriteAfterGenAc);
                } catch (TlvException e) {
                    MastercardErrorIndication ei = MastercardErrorIndication.
                            createL2Error(MastercardErrorIndication.L2Error.PARSING_ERROR, NOT_AVAILABLE);

                    return Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));

                }
            } else {
                deDataNeeded.add(EmvTag.TAGS_TO_WRITE_AFTER_GEN_AC);
            }
        }


        // S1.17
        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.DSVN_TERM) && tlvDb.isTagPresent(EmvTag.DS_REQUESTED_OPERATOR_ID)) {
            // S1.18
            if (tlvDb.isTagPresent(EmvTag.DS_ID)) {
                deDataToSend.add(tlvDb.get(EmvTag.DS_ID));
            } else {
                deDataToSend.add(new Tlv(EmvTag.DS_ID, 0, new byte[0]));
            }

            if (tlvDb.isTagPresent(EmvTag.APPLICATION_CAPABILITIES_INFORMATION)) {
                deDataToSend.add(tlvDb.get(EmvTag.APPLICATION_CAPABILITIES_INFORMATION));
            } else {
                deDataToSend.add(new Tlv(EmvTag.APPLICATION_CAPABILITIES_INFORMATION, 0, new byte[0]));
            }

            // S1.19
            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.APPLICATION_CAPABILITIES_INFORMATION)) {
                //noinspection ConstantConditions
                if ((applicationCapabilitiesInformation.isDataStorageVersion1() ||
                        applicationCapabilitiesInformation.isDataStorageVersion2()) &&
                        tlvDb.isTagPresentAndNonEmpty(EmvTag.DS_ID)) {

                    // S1.20
                    idsStatus.setRead(true);
                    tlvDb.updateOrAddKernel(idsStatus.toTlv());
                }
            }
        }

        // S1.21, S1.22, S1.23
        if (missingPdolData || noAmountAuthorizedNumericInAct) {
            logger.debug("Missing PDOl data. Will execute DEK-DET");
            if (noAmountAuthorizedNumericInAct) {
                deDataNeeded.add(EmvTag.AMOUNT_AUTHORISED_NUMERIC);
            }
            logger.debug("S1.22");

            dekDet();
            missingPdolData = false;
            for (TagAndLength tal : selectedAppReprocessed.getPdol()) {
                Optional<MastercardTag> tagO = MastercardTags.get(tal.getTag());
                if (tagO.isPresent() &&
                        tagO.get().isDetUpdateAllowed() &&
                        !MastercardTags.isTestTag(tagO.get()) &&
                        tlvDb.isTagPresent(tagO.get().getEmvTag()) &&
                        tlvDb.get(tagO.get().getEmvTag()).getValueBytes().length == 0) {
                    missingPdolData = true;
                    break;
                }
            }

            if (missingPdolData) {
                logger.warn("Timeout during wait for missing PDOL data");

                MastercardErrorIndication ei = MastercardErrorIndication.
                        createL3Error(MastercardErrorIndication.L3Error.TIME_OUT, NOT_AVAILABLE);

                Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);
                b.discretionaryData(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));

                return b.build();
            }
        }


        // S1.13
        byte[] pdolData = MastercardDolPreparer.prepareDol(tlvDb, selectedAppReprocessed.getPdol());
        byte[] pdolPrepared = KernelUtils.preparePdol(pdolData);

        // 3M50-0111(A_02_Trx2-Prepare-Torn-Temp-Record) requires pdolPrepared to be used
        tlvDb.updateOrAddKernel(new Tlv(PDOL_RELATED_DATA, pdolPrepared.length, pdolPrepared));


        // S1.14
        GpoResult gpoResult = gpoExecutor.execute(transceiver, pdolPrepared,
                tlvDb.isTagPresentAndNonEmpty(EmvTag.APPLICATION_INTERCHANGE_PROFILE) |
                        tlvDb.isTagPresentAndNonEmpty(EmvTag.APPLICATION_FILE_LOCATOR)); // S3.1

        // S3.8
        if (!gpoResult.isOk()) {
            if (gpoResult.isTimeout()) {
                // S3.4, S3.5
                // for some retarded reason mastercard kernel uses custom approach when timeout occur when waiting for GPO
                Outcome.Builder b = new Outcome.Builder(Outcome.Type.TRY_AGAIN);
                b.start(Outcome.Start.B);
                b.discretionaryData(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, gpoResult.getErrorIndication()));
                b.fieldOffRequest(-1);
                return b.build();
            } else {
                // Outcome at this stage indicates some error in executing/processing GPO
                // S3.9.1, // S3.9.2
                MastercardErrorIndication ei = gpoResult.getErrorIndication();
                Outcome.Builder b;
                if (ei.getL2() == MastercardErrorIndication.L2Error.STATUS_BYTES) {
                    b = new Outcome.Builder(Outcome.Type.SELECT_NEXT);
                    b.start(Outcome.Start.C);
                    b.fieldOffRequest(-1);
                    b.discretionaryData(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));
                    return b.build();
                } else {
                    return Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(isEmvMode, tlvDb, ei));
                }
            }
        }

        // S3.10, S3.11
        for (Tlv tlv : gpoResult.getForTlvDb()) {
            try {
                tlvDb.updateOrAddRa(tlv);
            } catch (EmvException e) {
                logger.warn(e.getMessage());
                return parsingError();
            }
        }

        // S3.6
        if (isStopSignalReceived) {
            // S3.7
            return MastercardKernel.createStopOutcome();
        }


        ApplicationInterchangeProfile applicationInterchangeProfile = gpoResult.getApplicationInterchangeProfile();
        byte[] applicationFileLocator = gpoResult.getApplicationFileLocator();

        ReaderLimits readerLimits = new ReaderLimits(tlvDb);

        if (!useLightLogging) {
            logger.debug("Reader limits: {}", readerLimits);
        }

        try {
            // S3.15
            if (configuration.isEmvModeNotSupported()) {
                // S3.17
                if (configuration.isMagstripeModeNotSupported()) {
                    // S3.18
                    logger.warn("S3.18 (1)");
                    return magstripeNotSupported();
                } else {
                    // Mag-stripe mode

                    return magStripeMode(transceiver, applicationFileLocator, transactionData,
                            applicationInterchangeProfile, readerLimits);

                }
            } else {
                // S3.16
                if (applicationInterchangeProfile.isEmvModeSupported()) {
                    // EMV mode

                    return emvModeProcessing(transceiver, applicationFileLocator,
                            applicationInterchangeProfile, ts, countryCode, readerLimits,
                            selectedAppReprocessed.getCandidate().getPreprocessedApplication().getAppConfig().getApplicationId(),
                            pdolData, terminalCapabilitiesRaw, applicationCapabilitiesInformation);

                } else {
                    // S3.17
                    if (configuration.isMagstripeModeNotSupported()) {
                        // S3.18
                        logger.warn("S3.18 (2)");
                        return magstripeNotSupported();
                    } else {
                        // Mag-stripe mode

                        return magStripeMode(transceiver, applicationFileLocator, transactionData,
                                applicationInterchangeProfile, readerLimits);
                    }
                }
            }
        } catch (TlvException | EmvException e) {
            logger.warn("Exception: ", e);
            return parsingError();
        }
    }
}

