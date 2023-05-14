package digital.paynetics.phos.kernel.mastercard.procedures;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.TerminalVerificationResults;
import digital.paynetics.phos.kernel.common.emv.entry_point.misc.TransactionData;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationUsageControl;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import digital.paynetics.phos.kernel.common.misc.CountryCode;
import digital.paynetics.phos.kernel.common.misc.TerminalType;
import digital.paynetics.phos.kernel.common.misc.TransactionTimestamp;
import digital.paynetics.phos.kernel.common.misc.TransactionType;
import digital.paynetics.phos.kernel.mastercard.misc.TlvDb;
import digital.paynetics.phos.kernel.mastercard.misc.TvrUtil;
import hirondelle.date4j.DateTime;


public final class ProcessingRestrictionsImpl implements ProcessingRestrictions {
    @Inject
    public ProcessingRestrictionsImpl() {
    }


    static void processAuc(ApplicationUsageControl auc,
                           TerminalVerificationResults terminalVerificationResults,
                           TlvDb tlvDb,
                           TransactionData transactionData,
                           CountryCode terminalCountryCode) throws TlvException {

        Tlv atc = tlvDb.get(EmvTag.ADDITIONAL_TERMINAL_CAPABILITIES);
        boolean cash = ((atc.getValueBytes()[0] & 0b10000000) == 0b10000000);

        // PRE.10
        TerminalType terminalType = TerminalType.fromCode(tlvDb.get(EmvTag.TERMINAL_TYPE).getValueBytes()[0]);
        if ((terminalType == TerminalType.UNATTENDED_FINANCIAL_INSTITUTION_OFFLINE_ONLY ||
                terminalType == TerminalType.UNATTENDED_FINANCIAL_INSTITUTION_OFFLINE_WITH_ONLINE ||
                terminalType == TerminalType.UNATTENDED_FINANCIAL_INSTITUTION_ONLINE_ONLY) &&
                cash) {

            // PRE.12
            if (!auc.isValidAtAtms()) {
                // PRE.13
                terminalVerificationResults.setRequestedServiceNotAllowed(true);
                return;
            }
        } else {
            // PRE.11
            if (!auc.isValidAtOtherThanAtms()) {
                // PRE.13
                terminalVerificationResults.setRequestedServiceNotAllowed(true);
                return;
            }
        }


        // PRE.14
        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.ISSUER_COUNTRY_CODE)) {
            int issuerCountryCode = tlvDb.get(EmvTag.ISSUER_COUNTRY_CODE).getValueAsBcdInt();

            // PRE.15
            if (transactionData.getType() == TransactionType.CASH_ADVANCE ||
                    transactionData.getType() == TransactionType.CASH_DISBURSEMENT) {
                // PRE.16
                if (terminalCountryCode.getNumeric() == issuerCountryCode) {
                    // PRE.17
                    if (!auc.isValidForDomesticCash()) {
                        // PRE.19
                        terminalVerificationResults.setRequestedServiceNotAllowed(true);
                    }
                } else {
                    // PRE.18
                    if (!auc.isValidForInternationalCash()) {
                        // PRE.19
                        terminalVerificationResults.setRequestedServiceNotAllowed(true);
                    }
                }
            } else if (transactionData.getType() == TransactionType.PURCHASE ||
                    transactionData.getType() == TransactionType.CASHBACK) { // PRE.20

                // PRE.21
                if (terminalCountryCode.getNumeric() == issuerCountryCode) {
                    // PRE.22
                    if (!(auc.isValidForDomesticGoods() || auc.isValidForDomesticServices())) {
                        // PRE.24
                        terminalVerificationResults.setRequestedServiceNotAllowed(true);
                    }
                } else {
                    // PRE.23
                    if (!(auc.isValidForInternationalGoods() || auc.isValidForInternationalServices())) {
                        // PRE.24
                        terminalVerificationResults.setRequestedServiceNotAllowed(true);
                    }
                }
            }


            // PRE.25 - we use the transaction type instead of the cashback amount because we will not receive
            // amount in other types
            if (transactionData.getType() == TransactionType.CASHBACK) {
                // PRE.26
                if (terminalCountryCode.getNumeric() == issuerCountryCode) {
                    // PRE.27
                    if (!auc.isDomesticCashbackAllowed()) {
                        // PRE.29
                        terminalVerificationResults.setRequestedServiceNotAllowed(true);
                    }
                } else {
                    // PRE.27
                    if (!auc.isInternationalCashbackAllowed()) {
                        // PRE.29
                        terminalVerificationResults.setRequestedServiceNotAllowed(true);
                    }
                }
            }
        }

        tlvDb.updateOrAddKernel(TvrUtil.asTlv(terminalVerificationResults));
    }


    public static DateTime getValueAsDate(byte[] data) {
        if (data.length != 3) {
            throw new IllegalArgumentException("Data length must be 3");
        } else {
            String tmp = ByteUtils.toHexString(data);
            String y2str = tmp.substring(0, 2);
            int y2 = Integer.parseInt(y2str);
            String finalDt;
            if (y2 > 49) {
                finalDt = "19" + y2str + "-" + tmp.substring(2, 4) + "-" + tmp.substring(4);
            } else {
                finalDt = "20" + y2str + "-" + tmp.substring(2, 4) + "-" + tmp.substring(4);
            }

            return new DateTime(finalDt);
        }
    }


    @Override
    public void process(TerminalVerificationResults terminalVerificationResults,
                        TlvDb tlvDb,
                        TransactionData transactionData,
                        TransactionTimestamp ts,
                        CountryCode terminalCountryCode) throws TlvException, EmvException {

        // PRE.1
        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.APP_VERSION_NUMBER_CARD)) {
            int cardAppVersion = tlvDb.get(EmvTag.APP_VERSION_NUMBER_CARD).getValueAsHexInt();
            int kernelAppVersion = tlvDb.get(EmvTag.APP_VERSION_NUMBER_TERMINAL).getValueAsHexInt();
            // PRE.2
            if (cardAppVersion != kernelAppVersion) {
                // PRE.3
                terminalVerificationResults.setIccAndTerminalAppDifferentVersions(true);
            }
        }


        // PRE.4
        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.APP_EFFECTIVE_DATE)) {
            DateTime cardEffectiveDate = tlvDb.get(EmvTag.APP_EFFECTIVE_DATE).getValueAsDate();
            // PRE.5
            if (ts.getTs().lt(cardEffectiveDate)) {
                // PRE.6
                terminalVerificationResults.setApplicationNotYetEffective(true);
            }
        }

        // kernel must have checked that APP_EXPIRATION_DATE is present according to C-2
        if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.APP_EXPIRATION_DATE)) {
            throw new EmvException("Missing TLV for APP_EXPIRATION_DATE");
        }
        DateTime cardExpirationDate = getValueAsDate(tlvDb.get(EmvTag.APP_EXPIRATION_DATE).getValueBytes());
        DateTime compare = DateTime.forDateOnly(ts.getTs().getYear(), ts.getTs().getMonth(), ts.getTs().getDay());

        // PRE.7
        if (cardExpirationDate.lt(compare)) {
            // PRE.8
            terminalVerificationResults.setExpiredApplication(true);
        }


        // PRE.9
        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.APP_USAGE_CONTROL)) {
            ApplicationUsageControl auc = new ApplicationUsageControl(tlvDb.get(EmvTag.APP_USAGE_CONTROL).
                    getValueBytes());

            processAuc(auc, terminalVerificationResults, tlvDb, transactionData, terminalCountryCode);
        }

        tlvDb.updateOrAddKernel(TvrUtil.asTlv(terminalVerificationResults));
    }
}
