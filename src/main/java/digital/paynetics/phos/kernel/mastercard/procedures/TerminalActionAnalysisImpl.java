package digital.paynetics.phos.kernel.mastercard.procedures;

import org.slf4j.LoggerFactory;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.TerminalVerificationResults;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationCryptogramType;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapReadOnly;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import digital.paynetics.phos.kernel.common.misc.TerminalType;

import static digital.paynetics.phos.kernel.common.misc.ByteUtils.byteArrayAnd;
import static digital.paynetics.phos.kernel.common.misc.ByteUtils.isByteArrayZeros;


public final class TerminalActionAnalysisImpl implements TerminalActionAnalysis {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());


    @Inject
    public TerminalActionAnalysisImpl() {
    }


    private static boolean isOnlineOnlyTerminal(TerminalType tt) {
        byte ttb = tt.getCode();

        return ttb == 0x11 || ttb == 0x21 || ttb == 0x14 || ttb == 0x24 || ttb == 0x34;
    }


    private static boolean isOfflineOnlyTerminal(TerminalType tt) {
        byte ttb = tt.getCode();

        return ttb == 0x23 || ttb == 0x26 || ttb == 0x36 || ttb == 0x13;
    }


    @Override
    public ApplicationCryptogramType process(TlvMapReadOnly tlvDb,
                                             TerminalVerificationResults terminalVerificationResults,
                                             byte[] terminalActionCodeDenial,
                                             byte[] terminalActionCodeOnline,
                                             byte[] terminalActionCodeDefault,
                                             TerminalType terminalType) {

        // actionCodeDenial combines the cases when ISSUER_ACTION_CODE_DENIAL is present and when it is not
        // it is just temporary variable
        byte[] actionCodeDenial;

        // TAA.1
        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.ISSUER_ACTION_CODE_DENIAL)) {
            Tlv iacd = tlvDb.get(EmvTag.ISSUER_ACTION_CODE_DENIAL);

            // TAA.3
            byte[] iacdBytes = iacd.getValueBytes();

            actionCodeDenial = ByteUtils.byteArrayOr(iacdBytes, terminalActionCodeDenial);
        } else {
            // TAA.2
            actionCodeDenial = terminalActionCodeDenial;
        }

        logger.debug("IAC Denial: {}", ByteUtils.toHexString(actionCodeDenial));
        byte[] tvr = terminalVerificationResults.toBytes();
        logger.debug("TVR: {}", ByteUtils.toHexString(tvr));

        // TAA.4 & TAA.2
        boolean zeroResult = isByteArrayZeros(byteArrayAnd(tvr, actionCodeDenial));

        if (zeroResult) {
            // TAA.4.1
            if (isOnlineOnlyTerminal(terminalType)) {
                // TAA.4.2
                return ApplicationCryptogramType.ARQC;
            } else {
                // TAA.6
                if (!isOfflineOnlyTerminal(terminalType)) {
                    // TAA.7
                    if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.ISSUER_ACTION_CODE_ONLINE)) {
                        // TAA.8
                        if (isByteArrayZeros(tvr)) {
                            // TAA.9
                            return ApplicationCryptogramType.TC;
                        } else {
                            // TAA.11
                            return ApplicationCryptogramType.ARQC;
                        }
                    } else {
                        // TAA.10
                        if (isByteArrayZeros(byteArrayAnd(tvr,
                                ByteUtils.byteArrayOr(tlvDb.get(EmvTag.ISSUER_ACTION_CODE_ONLINE).getValueBytes(),
                                        terminalActionCodeOnline)))) {

                            // TAA.12
                            return ApplicationCryptogramType.TC;
                        } else {
                            // TAA.11
                            return ApplicationCryptogramType.ARQC;
                        }
                    }
                } else {
                    // TAA.13
                    if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.ISSUER_ACTION_CODE_DEFAULT)) {
                        // TAA.14
                        if (isByteArrayZeros(tvr)) {
                            // TAA.15
                            return ApplicationCryptogramType.TC;
                        } else {
                            // TAA.17
                            return ApplicationCryptogramType.AAC;
                        }

                    } else {
                        if (isByteArrayZeros(byteArrayAnd(tvr,
                                ByteUtils.byteArrayOr(tlvDb.get(EmvTag.ISSUER_ACTION_CODE_DEFAULT).getValueBytes(),
                                        terminalActionCodeOnline)))) {

                            // TAA.18
                            return ApplicationCryptogramType.TC;
                        } else {
                            // TAA.17
                            return ApplicationCryptogramType.AAC;
                        }
                    }
                }
            }
        } else {
            // TAA.3 & // TAA.5
            return ApplicationCryptogramType.AAC;
        }
    }

}
