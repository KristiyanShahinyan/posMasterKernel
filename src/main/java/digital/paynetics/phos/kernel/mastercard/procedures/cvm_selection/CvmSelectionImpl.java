package digital.paynetics.phos.kernel.mastercard.procedures.cvm_selection;

import org.slf4j.LoggerFactory;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.TerminalVerificationResults;
import digital.paynetics.phos.kernel.common.emv.entry_point.misc.TransactionData;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationInterchangeProfile;
import digital.paynetics.phos.kernel.common.emv.kernel.common.CvmList;
import digital.paynetics.phos.kernel.common.emv.kernel.common.CvmListRule;
import digital.paynetics.phos.kernel.common.emv.kernel.common.CvmResults;
import digital.paynetics.phos.kernel.common.emv.kernel.common.CvmSelectionResult;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import digital.paynetics.phos.kernel.common.misc.TerminalCapabilities2Cvm;
import java8.util.Optional;


public final class CvmSelectionImpl implements CvmSelection {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(CvmSelection.class);


    private final RulesProcessor rulesProcessor;


    @Inject
    public CvmSelectionImpl(RulesProcessor rulesProcessor) {
        this.rulesProcessor = rulesProcessor;
    }


    @Override
    public CvmSelectionResult process(ApplicationInterchangeProfile aip,
                                      Optional<Tlv> cvmListRawO,
                                      TransactionData transactionData,
                                      Optional<Tlv> applicationCurrencyO,
                                      TerminalCapabilities2Cvm cvmCapabilities,
                                      TerminalVerificationResults terminalVerificationResults,
                                      boolean kernelConfigOnDeviceCvmSupported,
                                      int readerCvmRequiredLimit) throws EmvException {


        // CVM.1
        if (aip.isOnDeviceCvmSupported() && kernelConfigOnDeviceCvmSupported) {
            // CVM.2
            if (transactionData.getAmountAuthorized() > readerCvmRequiredLimit) {
                // CVM.4
                return new CvmSelectionResult(Outcome.Cvm.CONFIRMATION_CODE_VERIFIED,
                        CvmResults.createCvmPerformed((byte) 1,
                                CvmListRule.CvmCode.PLAINTEXT,
                                CvmListRule.ConditionCode.ALWAYS,
                                CvmResults.Result.SUCCESSFUL));
            } else {
                // CVM.3
                // this is kind of hack in order to provide necessary value. Probably
                // createCvmNotPerformed(false) should use SUCCESSFUL instead of UNKNOWN?
                return new CvmSelectionResult(Outcome.Cvm.NO_CVM,
                        CvmResults.createCvmPerformed((byte) 0x3f,
                                CvmListRule.CvmCode.FAIL,
                                CvmListRule.ConditionCode.ALWAYS,
                                CvmResults.Result.SUCCESSFUL));
            }
        } else {

            // CVM.5
            if (!aip.isCvmSupported()) {
                // CVM.6
                return new CvmSelectionResult(Outcome.Cvm.NO_CVM, CvmResults.createCvmNotPerformed(false));
            }

            // CVM.7
            if (!cvmListRawO.isPresent()) {
                // CVM.8
                terminalVerificationResults.setIccDataMissing(true);
                return new CvmSelectionResult(Outcome.Cvm.NO_CVM, CvmResults.createCvmNotPerformed(false));
            }

            if (cvmListRawO.get().getTag() != EmvTag.CVM_LIST) {
                throw new IllegalArgumentException("cvmListRawO must contain CVM_LIST");
            }

            logger.debug("CVM List: {}", ByteUtils.toHexString(cvmListRawO.get().getValueBytes(), true));
            Tlv cvmListRaw = cvmListRawO.get();
            byte[] data = cvmListRaw.getValueBytes();
            if (data.length == 0) {
                // CVM.8
                terminalVerificationResults.setIccDataMissing(true);
                return new CvmSelectionResult(Outcome.Cvm.NO_CVM, CvmResults.createCvmNotPerformed(false));
            }

            if (!CvmList.isValidDataLength(data)) {
                throw new EmvException("Invalid CVM list length: " + data.length);
            }

            CvmList cvmList = new CvmList(data);

            RulesProcessor.ProcessingRuleResult pr = rulesProcessor.processRules(cvmList.getRules(), transactionData,
                    applicationCurrencyO, cvmCapabilities, terminalVerificationResults, cvmList.getX(), cvmList.getY());


            return pr.getCvmSelectionResult();
        }
    }
}
