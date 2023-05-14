package digital.paynetics.phos.kernel.mastercard.procedures;

import digital.paynetics.phos.kernel.common.emv.TerminalVerificationResults;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationCryptogramType;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapReadOnly;
import digital.paynetics.phos.kernel.common.misc.TerminalType;


/**
 * Reflects Book C-2, 7.8 Procedure - Terminal Action Analysis
 */
public interface TerminalActionAnalysis {
    ApplicationCryptogramType process(TlvMapReadOnly tlvDb,
                                      TerminalVerificationResults terminalVerificationResults,
                                      byte[] terminalActionCodeDenial,
                                      byte[] terminalActionCodeOnline,
                                      byte[] terminalActionCodeDefault,
                                      TerminalType terminalType);
}
