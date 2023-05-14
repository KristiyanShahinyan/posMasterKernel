package digital.paynetics.phos.kernel.mastercard.procedures.cvm_selection;


import org.slf4j.LoggerFactory;

import java.util.List;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.TerminalVerificationResults;
import digital.paynetics.phos.kernel.common.emv.entry_point.misc.TransactionData;
import digital.paynetics.phos.kernel.common.emv.kernel.common.CvmListRule;
import digital.paynetics.phos.kernel.common.emv.kernel.common.CvmResults;
import digital.paynetics.phos.kernel.common.emv.kernel.common.CvmSelectionResult;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import digital.paynetics.phos.kernel.common.misc.Currency;
import digital.paynetics.phos.kernel.common.misc.TerminalCapabilities2Cvm;
import digital.paynetics.phos.kernel.common.misc.TransactionType;
import java8.util.Optional;

import static digital.paynetics.phos.kernel.common.emv.kernel.common.CvmListRule.CvmCode.FAIL;
import static digital.paynetics.phos.kernel.common.misc.PhosMessageFormat.format;


public class RulesProcessorImpl implements RulesProcessor {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(RulesProcessorImpl.class);


    @Inject
    public RulesProcessorImpl() {
    }


    static boolean checkCvmListRule(CvmListRule rule,
                                    TransactionData transactionData,
                                    Optional<Tlv> applicationCurrencyO,
                                    long x, long y, TerminalCapabilities2Cvm cvmCapabilities)
            throws EmvException, CvmMissingDataException {

        switch (rule.getConditionCode()) {
            case ALWAYS:
                return true;
            case UNATTENDED_CASH:
                // this is probably incorrect but EMV does not support
                return transactionData.getType() == TransactionType.CASH_ADVANCE;
            case NOT_ALL_CASH_NOT_CASHBACK:
                return transactionData.getType() != TransactionType.CASH_ADVANCE &&
                        transactionData.getType() != TransactionType.CASHBACK;
            case IF_TERMINAL_SUPPORTS:
                return isCvmCodeSupportedTermSupport(rule, cvmCapabilities);
            case MANUAL_CASH:
                return transactionData.getType() == TransactionType.CASH_DISBURSEMENT;
            case PURCHASE_WITH_CASHBACK:
                return transactionData.getType() == TransactionType.CASHBACK;
            case APP_CURRENCY_UNDER_X:
                return checkXyCondition(applicationCurrencyO, transactionData, x, false);
            case APP_CURRENCY_OVER_X:
                return checkXyCondition(applicationCurrencyO, transactionData, x, true);
            case APP_CURRENCY_UNDER_Y:
                return checkXyCondition(applicationCurrencyO, transactionData, y, false);
            case APP_CURRENCY_OVER_Y:
                return checkXyCondition(applicationCurrencyO, transactionData, y, true);
            case UNKNOWN:
                // we must not reach here. Should be checked outside this method before calling it
                throw new AssertionError("UNKNOWN must be unreachable");
        }

        // this return is not really necessary but we have to put it in order to satisfy the compiler
        return false;
    }


    static boolean checkXyCondition(Optional<Tlv> applicationCurrencyO,
                                    TransactionData transactionData,
                                    long conditionAmount,
                                    boolean isOverAmount) throws EmvException, CvmMissingDataException {

        if (!applicationCurrencyO.isPresent()) { // CVM.11
            throw new CvmMissingDataException();
        }

        Tlv acTlv = applicationCurrencyO.get();
        if (acTlv.getTag() != EmvTag.APPLICATION_CURRENCY_CODE) {
            throw new IllegalArgumentException("applicationCurrencyO must be APPLICATION_CURRENCY_CODE");
        }

        try {
            Optional<Currency> acO = Currency.find(acTlv.getValueAsBcdInt());
            if (acO.isPresent()) {
                if (acO.get() == transactionData.getCurrency()) {
                    if (isOverAmount) {
                        return transactionData.getAmountAuthorized() > conditionAmount;
                    } else {
                        return transactionData.getAmountAuthorized() < conditionAmount;
                    }
                } else {
                    return false;
                }
            } else {
                logger.error("Cannot find Currency for code {}", acTlv.getValueAsBcdInt());
                throw new EmvException(format("Cannot find Currency for code {}", acTlv.getValueAsBcdInt()));
            }
        } catch (TlvException e) {
            logger.error("Invalid value for {}: {}", EmvTag.APPLICATION_CURRENCY_CODE,
                    ByteUtils.toHexString(acTlv.getValueBytes()));
            throw new EmvException(format("Invalid value for {}: {}", EmvTag.APPLICATION_CURRENCY_CODE,
                    ByteUtils.toHexString(acTlv.getValueBytes())));
        }
    }


    private static boolean isCvmCodeSupportedTermSupport(CvmListRule rule, TerminalCapabilities2Cvm cvmCapabilities) {

        switch (rule.getCvmCode()) {
            case FAIL:
                return true;
            case PLAINTEXT:
                return cvmCapabilities.isPlaintextPinForIccVerification();
            case ENCIPHERED_ONLINE:
                return cvmCapabilities.isEncipheredPinForOnline();
            case PLAINTEXT_AND_SIGNATURE:
                return cvmCapabilities.isPlaintextPinForIccVerification() && cvmCapabilities.isSignatureSupported();
            case ENCIPHERED_BY_CARD:
                return cvmCapabilities.isEncipheredPinForOffline();
            case ENCIPHERED_BY_CARD_AND_SIGNATURE:
                return cvmCapabilities.isEncipheredPinForOffline() && cvmCapabilities.isSignatureSupported();
            case SIGNATURE:
                return cvmCapabilities.isSignatureSupported();
            case NO_CVM_REQUIRED:
                return cvmCapabilities.isNoCvmRequired();
            default:
                return false;
        }
    }


    private static boolean isCvmCodeSupportedAndNotFail(CvmListRule rule, TerminalCapabilities2Cvm cvmCapabilities)
            throws UnrecognizedCvmCodeException {

        switch (rule.getCvmCode()) {
            case FAIL:
                // CVM.17: "Fail CVM processing ('00' or '40') must always be supported"
                return false;
            case PLAINTEXT:
                return cvmCapabilities.isPlaintextPinForIccVerification();
            case ENCIPHERED_ONLINE:
                return cvmCapabilities.isEncipheredPinForOnline();
            case PLAINTEXT_AND_SIGNATURE:
                return cvmCapabilities.isPlaintextPinForIccVerification() && cvmCapabilities.isSignatureSupported();
            case ENCIPHERED_BY_CARD:
                return cvmCapabilities.isEncipheredPinForOffline();
            case ENCIPHERED_BY_CARD_AND_SIGNATURE:
                return cvmCapabilities.isEncipheredPinForOffline() && cvmCapabilities.isSignatureSupported();
            case SIGNATURE:
                return cvmCapabilities.isSignatureSupported();
            case NO_CVM_REQUIRED:
                return cvmCapabilities.isNoCvmRequired();
            case RFU:
                throw new UnrecognizedCvmCodeException();
            default:
                throw new AssertionError("Cannot reach here");
        }
    }


    public ProcessingRuleResult processRules(List<CvmListRule> rules,
                                             TransactionData transactionData,
                                             Optional<Tlv> applicationCurrencyO,
                                             TerminalCapabilities2Cvm cvmCapabilities,
                                             TerminalVerificationResults terminalVerificationResults,
                                             long x, long y) throws EmvException {
        CvmListRule currentRule = null;

        boolean unrecognizedConditionCodeFoundLast = false;
        boolean missingDataLast = false;
        boolean lastRuleNotSatisfied = false;
        boolean unrecognizedCvmCodeFoundLast = false;
        boolean cvmCodeNotSupportedOrFail = false;

        for (CvmListRule rule : rules) { // CVM.9

            unrecognizedConditionCodeFoundLast = false;
            missingDataLast = false;
            lastRuleNotSatisfied = false;
            unrecognizedCvmCodeFoundLast = false;
            cvmCodeNotSupportedOrFail = false;

            // CVM.10
            if (rule.getConditionCode() == CvmListRule.ConditionCode.UNKNOWN) {
                unrecognizedConditionCodeFoundLast = true;
                continue;
            }

            // CVM.21
            currentRule = rule;


            try { // CVM.11
                if (checkCvmListRule(rule, transactionData, applicationCurrencyO, x, y, cvmCapabilities)) { // CVM.12
                    if (isCvmCodeSupportedAndNotFail(rule, cvmCapabilities)) {
                        if ((rule.getCvmCode().getCode() & 0x3f) == 2) {
                            terminalVerificationResults.setOnlinePinEntered(true);
                            CvmResults rez = CvmResults.createCvmPerformed(rule.getCvmCodeRaw(), rule.getCvmCode(),
                                    rule.getConditionCode(),
                                    CvmResults.Result.UNKNOWN);

                            return new ProcessingRuleResult(new CvmSelectionResult(Outcome.Cvm.ONLINE_PIN, rez),
                                    currentRule);
                        } else if ((rule.getCvmCode().getCode() & 0x3f) == 0x1e) {
                            CvmResults rez = CvmResults.createCvmPerformed(rule.getCvmCodeRaw(), rule.getCvmCode(),
                                    rule.getConditionCode(),
                                    CvmResults.Result.UNKNOWN);

                            return new ProcessingRuleResult(new CvmSelectionResult(Outcome.Cvm.OBTAIN_SIGNATURE, rez),
                                    currentRule);
                        } else if ((rule.getCvmCode().getCode() & 0x3f) == 0x1f) {
                            CvmResults rez = CvmResults.createCvmPerformed(rule.getCvmCodeRaw(), rule.getCvmCode(),
                                    rule.getConditionCode(),
                                    CvmResults.Result.SUCCESSFUL);

                            return new ProcessingRuleResult(new CvmSelectionResult(Outcome.Cvm.NO_CVM, rez),
                                    currentRule);
                        }
                    } else {
                        cvmCodeNotSupportedOrFail = true;
                        if (rule.isFailCvmIfUnsuccessful()) { // CVM.19
                            return return22(rule, terminalVerificationResults);
                        }
                    }
                } else {
                    lastRuleNotSatisfied = true;
                }
            } catch (UnrecognizedCvmCodeException e) { // CVM.15
                terminalVerificationResults.setUnrecognizedCvm(true); // CVM.16
                unrecognizedCvmCodeFoundLast = true;
                if (rule.isFailCvmIfUnsuccessful()) { // CVM.19
                    return return22(rule, terminalVerificationResults);
                }
            } catch (CvmMissingDataException e) {
                // CVM.11 - no
                missingDataLast = true;
                continue;
            }
        }

        if (unrecognizedConditionCodeFoundLast || missingDataLast || lastRuleNotSatisfied) { // CVM.13
            // CVM.14
            terminalVerificationResults.setCvmNotSuccessful(true);
            CvmResults rez = CvmResults.createCvmNotPerformed(true);

            return new ProcessingRuleResult(new CvmSelectionResult(Outcome.Cvm.NO_CVM, rez), null);
        }

        if (unrecognizedCvmCodeFoundLast || cvmCodeNotSupportedOrFail) {
            return return22(currentRule, terminalVerificationResults);
        }

        throw new AssertionError("Must not reach here");
    }


    private ProcessingRuleResult return22(CvmListRule rule, TerminalVerificationResults terminalVerificationResults) {
        CvmResults rez;

        terminalVerificationResults.setCvmNotSuccessful(true);

        if (rule.getCvmCode() == FAIL) {
            rez = CvmResults.createCvmPerformed(rule.getCvmCodeRaw(), rule.getCvmCode(),
                    rule.getConditionCode(),
                    CvmResults.Result.FAILED);
        } else {
            rez = CvmResults.createCvmNotPerformed(true);

            return new ProcessingRuleResult(new CvmSelectionResult(Outcome.Cvm.NO_CVM, rez), null);
        }

        return new ProcessingRuleResult(new CvmSelectionResult(Outcome.Cvm.NO_CVM, rez), null);
    }

}
