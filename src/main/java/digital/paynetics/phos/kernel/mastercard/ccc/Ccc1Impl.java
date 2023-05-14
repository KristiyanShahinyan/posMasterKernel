package digital.paynetics.phos.kernel.mastercard.ccc;

import org.slf4j.LoggerFactory;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.ui.ContactlessTransactionStatus;
import digital.paynetics.phos.kernel.common.emv.ui.StandardMessages;
import digital.paynetics.phos.kernel.common.emv.ui.UserInterfaceRequest;
import digital.paynetics.phos.kernel.mastercard.MastercardKernel;
import digital.paynetics.phos.kernel.mastercard.misc.MagstripeCvmCapability;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardMagstripeFailedCounter;
import digital.paynetics.phos.kernel.mastercard.misc.MessageStoreMc;
import digital.paynetics.phos.kernel.mastercard.misc.PciiMessageTable;
import digital.paynetics.phos.kernel.mastercard.misc.PosCardHolderInteractionInformation;
import digital.paynetics.phos.kernel.mastercard.misc.TlvDb;


public class Ccc1Impl implements Ccc1 {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());


    private final MessageStoreMc messageStore;


    @Inject
    public Ccc1Impl(MessageStoreMc messageStore) {
        this.messageStore = messageStore;
    }


    @Override
    public CccResult process(TlvDb tlvDb,
                             MastercardMagstripeFailedCounter mastercardMagstripeFailedCounter,
                             int nUn,
                             char[] random,
                             int amountAuthorized,
                             int readerCvmRequiredLimit,
                             int messageHoldTime) throws EmvException {

        logger.debug("CCC 1");

        // S13.12.1
        logger.debug("MSG: CARD_READ_OK");
        UserInterfaceRequest ui = new UserInterfaceRequest(StandardMessages.CLEAR_DISPLAY,
                ContactlessTransactionStatus.CARD_READ_SUCCESSFULLY,
                0, null, null, 0, null);

        messageStore.add(ui);


        // S13.14.1
        if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.APP_TRANSACTION_COUNTER)) {
            return Ccc.cardDataMissing(mastercardMagstripeFailedCounter, tlvDb);
        }

        // S13.14.2
        if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.CVC3_TRACK2)) {
            // S13.14.3
            if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.POS_CARDHOLDER_INTERACTION_INFORMATION)) {
                return Ccc.cardDataMissing(mastercardMagstripeFailedCounter, tlvDb);
            } else {
                // S13.41
                if (PosCardHolderInteractionInformation.
                        isSecondTapNeeded(tlvDb.get(EmvTag.POS_CARDHOLDER_INTERACTION_INFORMATION))) {

                    UserInterfaceRequest userInterfaceRequest = PciiMessageTable.getUir(
                            tlvDb.get(EmvTag.POS_CARDHOLDER_INTERACTION_INFORMATION));

                    messageStore.add(userInterfaceRequest);
                    // S13.44.1
                    try {
                        logger.debug("CCCtimer (sleep): {} ms", Math.pow(2, mastercardMagstripeFailedCounter.get()) * 300);
                        Thread.sleep((long) (Math.pow(2, mastercardMagstripeFailedCounter.get()) * 300));
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    }

                    // S13.44.2
                    mastercardMagstripeFailedCounter.increment();

                    // S13.45
                    userInterfaceRequest =
                            new UserInterfaceRequest(userInterfaceRequest.getMessage(),
                                    ContactlessTransactionStatus.READY_TO_READ,
                                    0,
                                    null, null, 0, null
                            );

                    Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);
                    b.start(Outcome.Start.B);
                    b.dataRecord(MastercardKernel.buildDataRecordMagstripe(tlvDb.asUnencrypted()));
                    b.uiRequestOnRestart(userInterfaceRequest);
                    b.discretionaryData(MastercardKernel.buildDiscretionaryData(false, tlvDb, null));

                    return CccResult.createOkResult(b.build());
                } else {
                    // S13.42.1
                    try {
                        logger.debug("CCCtimer (sleep): {} ms", Math.pow(2, mastercardMagstripeFailedCounter.get()) * 300);
                        Thread.sleep((long) (Math.pow(2, mastercardMagstripeFailedCounter.get()) * 300));
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    }

                    // S13.42.2
                    mastercardMagstripeFailedCounter.increment();

                    // S13.43
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
        } else {
            int nUnFinal;
            // S13.14.5
            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.POS_CARDHOLDER_INTERACTION_INFORMATION)) {
                if (PosCardHolderInteractionInformation.isOdCvmSuccessful(
                        tlvDb.get(EmvTag.POS_CARDHOLDER_INTERACTION_INFORMATION))) {
                    nUnFinal = (nUn + 5) % 10;
                } else {
                    nUnFinal = nUn;
                }
            } else {
                nUnFinal = nUn;
            }


            // S13.15
            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.TRACK1_DATA) &&
                    !tlvDb.isTagPresentAndNonEmpty(EmvTag.CVC3_TRACK1)) {

                // S13.16
                logger.warn("S13.16 card data missing");
                return Ccc.cardDataMissing(mastercardMagstripeFailedCounter, tlvDb);
            }


            // S13.17
            mastercardMagstripeFailedCounter.reset();

            // S13.18, S13.19, S13.20, S13.21, S13.22
            Ccc.updateTrackData(tlvDb, nUn, random, nUnFinal);

            MagstripeCvmCapability cvm;
            // S13.24
            if (amountAuthorized > readerCvmRequiredLimit) {
                Outcome.Builder b = new Outcome.Builder(Outcome.Type.ONLINE_REQUEST);

                cvm = MagstripeCvmCapability.fromByte(tlvDb.get(EmvTag.MAG_STRIPE_CVM_CAPABILITY_CVM_REQUIRED).getValueBytes()[0]);
                b.cvm(MagstripeCvmCapability.toOutcomeCvm(cvm));
                b.receiptPreference(Outcome.ReceiptPreference.YES);
                b.dataRecord(MastercardKernel.buildDataRecordMagstripe(tlvDb.asUnencrypted()));
                b.discretionaryData(MastercardKernel.buildDiscretionaryData(false, tlvDb, null));

                return CccResult.createOkResult(b.build());
            } else {
                Outcome.Builder b = new Outcome.Builder(Outcome.Type.ONLINE_REQUEST);
                cvm = MagstripeCvmCapability.fromByte(tlvDb.get(EmvTag.MAG_STRIPE_CVM_CAPABILITY_NO_CVM_REQUIRED).getValueBytes()[0]);
                b.cvm(MagstripeCvmCapability.toOutcomeCvm(cvm));

                // dirty fix for receipt, otherwise we had to pollute return data all the way from RulesProcessor to here
                if (MagstripeCvmCapability.toOutcomeCvm(cvm) == Outcome.Cvm.OBTAIN_SIGNATURE) {
                    b.receiptPreference(Outcome.ReceiptPreference.YES);
                }

                b.dataRecord(MastercardKernel.buildDataRecordMagstripe(tlvDb.asUnencrypted()));
                b.discretionaryData(MastercardKernel.buildDiscretionaryData(false, tlvDb, null));

                return CccResult.createOkResult(b.build());
            }
        }
    }
}
