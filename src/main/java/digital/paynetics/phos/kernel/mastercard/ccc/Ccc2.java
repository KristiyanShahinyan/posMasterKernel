package digital.paynetics.phos.kernel.mastercard.ccc;


import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardMagstripeFailedCounter;
import digital.paynetics.phos.kernel.mastercard.misc.TlvDb;


public interface Ccc2 {
    CccResult process(TlvDb tlvDb,
                      MastercardMagstripeFailedCounter mastercardMagstripeFailedCounter,
                      int nUn,
                      char[] random,
                      int amountAuthorized,
                      int readerCvmRequiredLimit, Outcome.Cvm cvm,
                      int messageHoldTime) throws EmvException;
}
