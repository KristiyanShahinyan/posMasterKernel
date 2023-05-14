package digital.paynetics.phos.kernel.mastercard.ccc;

import org.slf4j.LoggerFactory;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapReadOnly;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.ui.ContactlessTransactionStatus;
import digital.paynetics.phos.kernel.common.emv.ui.StandardMessages;
import digital.paynetics.phos.kernel.common.emv.ui.UserInterfaceRequest;
import digital.paynetics.phos.kernel.mastercard.MastercardKernel;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardErrorIndication;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardMagstripeFailedCounter;
import digital.paynetics.phos.kernel.mastercard.misc.MessageStoreMc;
import digital.paynetics.phos.kernel.mastercard.misc.PciiMessageTable;
import digital.paynetics.phos.kernel.mastercard.misc.PosCardHolderInteractionInformation;
import digital.paynetics.phos.kernel.mastercard.misc.TlvDb;

import static digital.paynetics.phos.kernel.mastercard.misc.MastercardMessageIdentifier.ERROR_OTHER_CARD;


public class Ccc2Impl implements Ccc2 {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());

    private final MessageStoreMc messageStore;


    @Inject
    public Ccc2Impl(MessageStoreMc messageStore) {
        this.messageStore = messageStore;
    }


    @Override
    public CccResult process(TlvDb tlvDb, MastercardMagstripeFailedCounter mastercardMagstripeFailedCounter,
                             int nUn, char[] random,
                             int amountAuthorized,
                             int readerCvmRequiredLimit,
                             Outcome.Cvm cvm,
                             int messageHoldTime) throws EmvException {

        logger.debug("CCC 2");
        // S14.12.1
        logger.debug("MSG: CARD_READ_OK");
        UserInterfaceRequest ui = new UserInterfaceRequest(StandardMessages.CLEAR_DISPLAY,
                ContactlessTransactionStatus.CARD_READ_SUCCESSFULLY,
                0, null, null, 0, null);

        messageStore.add(ui);

        if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.APP_TRANSACTION_COUNTER) ||
                !tlvDb.isTagPresentAndNonEmpty(EmvTag.POS_CARDHOLDER_INTERACTION_INFORMATION)) {

            return Ccc.cardDataMissing(mastercardMagstripeFailedCounter, tlvDb);
        }

        // S14.15
        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.CVC3_TRACK2)) {
            // S14.16
            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.TRACK1_DATA) && !
                    tlvDb.isTagPresentAndNonEmpty(EmvTag.CVC3_TRACK1)) {
                logger.warn("S14.16");
                return Ccc.cardDataMissing(mastercardMagstripeFailedCounter, tlvDb);
            }

            // S14.20
            int nUnFinal;
            if (PosCardHolderInteractionInformation.isOdCvmSuccessful(
                    tlvDb.get(EmvTag.POS_CARDHOLDER_INTERACTION_INFORMATION))) {

                // S14.24
                nUnFinal = (nUn + 5) % 10;
            } else {
                // S14.21
                if (amountAuthorized > readerCvmRequiredLimit) {
                    logger.warn("S14.21");

                    logger.debug("CCCtimer (sleep): {} ms", Math.pow(2, mastercardMagstripeFailedCounter.get()) * 300);
                    try {
                        Thread.sleep((long) (Math.pow(2, mastercardMagstripeFailedCounter.get()) * 300));
                    } catch (InterruptedException e) {
                        // ignored
                    }
                    mastercardMagstripeFailedCounter.increment();
                    // S14.21.1
                    return cardDataError(tlvDb);
                } else {
                    // S14.25
                    nUnFinal = nUn;
                }
            }


            // S14.25.1
            mastercardMagstripeFailedCounter.reset();


            // S14.26, S14.27, S14.28, S14.29, S14.30
            Ccc.updateTrackData(tlvDb, nUn, random, nUnFinal);

            // S14.32
            if (PosCardHolderInteractionInformation.isOdCvmSuccessful(
                    tlvDb.get(EmvTag.POS_CARDHOLDER_INTERACTION_INFORMATION))) {

                // S14.34
                Outcome.Builder b = new Outcome.Builder(Outcome.Type.ONLINE_REQUEST);
                b.cvm(Outcome.Cvm.CONFIRMATION_CODE_VERIFIED);
                b.dataRecord(MastercardKernel.buildDataRecordMagstripe(tlvDb.asUnencrypted()));

                if (amountAuthorized > readerCvmRequiredLimit) {
                    b.receiptPreference(Outcome.ReceiptPreference.YES);
                }

                b.discretionaryData(MastercardKernel.buildDiscretionaryData(false, tlvDb, null));
                return CccResult.createOkResult(b.build());
            } else {
                // S14.33
                Outcome.Builder b = new Outcome.Builder(Outcome.Type.ONLINE_REQUEST);
                b.cvm(Outcome.Cvm.NO_CVM);
                b.dataRecord(MastercardKernel.buildDataRecordMagstripe(tlvDb.asUnencrypted()));
                b.discretionaryData(MastercardKernel.buildDiscretionaryData(false, tlvDb, null));
                return CccResult.createOkResult(b.build());
            }
        } else {
            // S14.19.1
            if (PosCardHolderInteractionInformation.isSecondTapNeeded(tlvDb.get(EmvTag.POS_CARDHOLDER_INTERACTION_INFORMATION))) {
                // S14.22
                UserInterfaceRequest userInterfaceRequest = PciiMessageTable.getUir(
                        tlvDb.get(EmvTag.POS_CARDHOLDER_INTERACTION_INFORMATION));

                messageStore.add(userInterfaceRequest);
                // S14.22.1
                try {
                    logger.debug("CCCtimer (sleep): {} ms", Math.pow(2, mastercardMagstripeFailedCounter.get()) * 300);
                    Thread.sleep((long) (Math.pow(2, mastercardMagstripeFailedCounter.get()) * 300));
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                // S14.22.2
                mastercardMagstripeFailedCounter.increment();

                Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);
                b.start(Outcome.Start.B);
                b.cvm(cvm);
                b.dataRecord(MastercardKernel.buildDataRecordMagstripe(tlvDb.asUnencrypted()));

                userInterfaceRequest =
                        new UserInterfaceRequest(userInterfaceRequest.getMessage(),
                                ContactlessTransactionStatus.READY_TO_READ,
                                0,
                                null, null, 0, null
                        );

                b.uiRequestOnRestart(userInterfaceRequest);
                b.discretionaryData(MastercardKernel.buildDiscretionaryData(false, tlvDb, null));

                return CccResult.createOkResult(b.build());
            } else {
                // S14.19.2.1
                try {
                    logger.debug("CCCtimer (sleep): {} ms", Math.pow(2, mastercardMagstripeFailedCounter.get()) * 300);
                    Thread.sleep((long) (Math.pow(2, mastercardMagstripeFailedCounter.get()) * 300));
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }

                // S14.19.2.2
                mastercardMagstripeFailedCounter.increment();

                // S14.19.3
                UserInterfaceRequest userInterfaceRequest =
                        new UserInterfaceRequest(StandardMessages.NOT_AUTHORIZED,
                                ContactlessTransactionStatus.NOT_READY,
                                messageHoldTime,
                                null, null, 0, null
                        );
                Outcome.Builder b = new Outcome.Builder(Outcome.Type.DECLINED);
                b.uiRequestOnOutcome(userInterfaceRequest);
                b.dataRecord(MastercardKernel.buildDataRecordMagstripe(tlvDb.asUnencrypted()));
                b.discretionaryData(MastercardKernel.buildDiscretionaryData(false, tlvDb, null));

                return CccResult.createFailResult(b.build());
            }
        }
    }


    private CccResult cardDataError(TlvMapReadOnly tlvDb) {
        MastercardErrorIndication ei = MastercardErrorIndication.
                createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_ERROR, ERROR_OTHER_CARD);

        return CccResult.createFailResult(
                Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(false, tlvDb, ei)));
    }

}
