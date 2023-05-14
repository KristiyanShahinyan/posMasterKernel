package digital.paynetics.phos.kernel.mastercard.procedures.cvm_selection;

import digital.paynetics.phos.kernel.common.emv.TerminalVerificationResults;
import digital.paynetics.phos.kernel.common.emv.entry_point.misc.TransactionData;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationInterchangeProfile;
import digital.paynetics.phos.kernel.common.emv.kernel.common.CvmSelectionResult;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.misc.TerminalCapabilities2Cvm;
import java8.util.Optional;


/**
 * CVM selection procedure as described in Book C-2, 7.5 Procedure – CVM Selection
 */
public interface CvmSelection {
    CvmSelectionResult process(ApplicationInterchangeProfile aip,
                               Optional<Tlv> cvmListRawO,
                               TransactionData transactionData,
                               Optional<Tlv> applicationCurrencyO,
                               TerminalCapabilities2Cvm cvmCapabilities,
                               TerminalVerificationResults terminalVerificationResults,
                               boolean kernelConfigOndeviceCvmSupported,
                               int readerCvmRequiredLimit) throws EmvException;

}
