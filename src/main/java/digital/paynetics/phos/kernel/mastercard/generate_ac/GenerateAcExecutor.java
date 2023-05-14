package digital.paynetics.phos.kernel.mastercard.generate_ac;


import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.TerminalVerificationResults;
import digital.paynetics.phos.kernel.common.emv.cert.CaPublicKeyDb;
import digital.paynetics.phos.kernel.common.emv.cert.CrlRid;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationCryptogramType;
import digital.paynetics.phos.kernel.common.misc.McTlvList;
import digital.paynetics.phos.kernel.common.misc.TerminalCapabilities13;
import digital.paynetics.phos.kernel.common.misc.TransactionTimestamp;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;
import digital.paynetics.phos.kernel.mastercard.misc.DsSummaryStatus;
import digital.paynetics.phos.kernel.mastercard.misc.IdsStatus;
import digital.paynetics.phos.kernel.mastercard.misc.TlvDb;
import java8.util.Optional;


public interface GenerateAcExecutor {
    Outcome execute(Transceiver transceiver,
                    byte[] cdol1Prepared,
                    byte[] dsDolPrepared,
                    byte applicationReferenceParameter,
                    ApplicationCryptogramType requestedApplicationCryptogramType,
                    Outcome.Cvm cvm,
                    boolean receiptRequired,
                    TlvDb tlvDb,
                    Optional<CaPublicKeyDb> caPublicKeyDbO,
                    CrlRid crlRid,
                    byte[] pdolData,
                    TransactionTimestamp ts,
                    String pan8,
                    byte[] staticDataToBeAuthenticated,
                    boolean haveIds,
                    boolean idsVersion2,
                    int rrpMeasuredProcessingTime,
                    int rrpCounter,
                    McTlvList deTagsToWriteYetAfterGenAc,
                    int messageHoldTime,
                    IdsStatus idsStatus,
                    DsSummaryStatus dsSummaryStatus,
                    boolean isSupportingBalanceReading,
                    TerminalVerificationResults terminalVerificationResults,
                    TerminalCapabilities13 terminalCapabilities13);
}
