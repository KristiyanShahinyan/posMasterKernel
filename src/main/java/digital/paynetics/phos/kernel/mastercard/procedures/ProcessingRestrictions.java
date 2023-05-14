package digital.paynetics.phos.kernel.mastercard.procedures;

import digital.paynetics.phos.kernel.common.emv.TerminalVerificationResults;
import digital.paynetics.phos.kernel.common.emv.entry_point.misc.TransactionData;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;
import digital.paynetics.phos.kernel.common.misc.CountryCode;
import digital.paynetics.phos.kernel.common.misc.TransactionTimestamp;
import digital.paynetics.phos.kernel.mastercard.misc.TlvDb;


/**
 * Reflects Book C-2, Procedure 7.7 Processing Restrictions
 */
public interface ProcessingRestrictions {
    /**
     * @param terminalVerificationResults Results of the processing raises flags in this object
     * @param tlvDb
     * @param transactionData
     * @param ts
     * @param terminalCountryCode
     * @throws TlvException
     */
    void process(TerminalVerificationResults terminalVerificationResults,
                 TlvDb tlvDb,
                 TransactionData transactionData,
                 TransactionTimestamp ts,
                 CountryCode terminalCountryCode) throws TlvException, EmvException;

}
