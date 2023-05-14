package digital.paynetics.phos.kernel.mastercard.procedures.cvm_selection;

import java.util.List;

import digital.paynetics.phos.kernel.common.emv.TerminalVerificationResults;
import digital.paynetics.phos.kernel.common.emv.entry_point.misc.TransactionData;
import digital.paynetics.phos.kernel.common.emv.kernel.common.CvmListRule;
import digital.paynetics.phos.kernel.common.emv.kernel.common.CvmSelectionResult;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.misc.TerminalCapabilities2Cvm;
import java8.util.Optional;


public interface RulesProcessor {
    ProcessingRuleResult processRules(List<CvmListRule> rules, TransactionData transactionData,
                                      Optional<Tlv> applicationCurrencyO,
                                      TerminalCapabilities2Cvm cvmCapabilities,
                                      TerminalVerificationResults terminalVerificationResults,
                                      long x, long y) throws EmvException;


    class ProcessingRuleResult {
        private final CvmSelectionResult cvmSelectionResult;
        private final CvmListRule lastRule;


        public ProcessingRuleResult(CvmSelectionResult cvmSelectionResult, CvmListRule lastRule) {
            this.cvmSelectionResult = cvmSelectionResult;
            this.lastRule = lastRule;
        }


        public CvmSelectionResult getCvmSelectionResult() {
            return cvmSelectionResult;
        }


        public CvmListRule getLastRule() {
            return lastRule;
        }
    }
}
