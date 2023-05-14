package digital.paynetics.phos.kernel.mastercard.generate_ac;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.TerminalVerificationResults;
import digital.paynetics.phos.kernel.common.emv.cert.CaPublicKeyDb;
import digital.paynetics.phos.kernel.common.emv.cert.CrlRid;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationCryptogramType;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationInterchangeProfile;
import digital.paynetics.phos.kernel.common.emv.tag.TagAndLength;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import digital.paynetics.phos.kernel.common.misc.McTlvList;
import digital.paynetics.phos.kernel.common.misc.TerminalCapabilities13;
import digital.paynetics.phos.kernel.common.misc.TransactionTimestamp;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;
import digital.paynetics.phos.kernel.mastercard.misc.ApplicationCapabilityInformation;
import digital.paynetics.phos.kernel.mastercard.misc.DsSummaryStatus;
import digital.paynetics.phos.kernel.mastercard.misc.IdsStatus;
import digital.paynetics.phos.kernel.mastercard.misc.SensitiveData;
import digital.paynetics.phos.kernel.mastercard.misc.TlvDb;
import digital.paynetics.phos.kernel.mastercard.rrp.Rrp;
import digital.paynetics.phos.kernel.mastercard.torn.TornTransactionLogRecord;
import java8.util.Optional;


public interface AcStage {
    Outcome generateAcRoute(Transceiver transceiver,
                            TlvDb tlvDb,
                            TerminalVerificationResults terminalVerificationResults,
                            IdsStatus idsStatus,
                            boolean isEmvMode,
                            ApplicationCryptogramType requestedApplicationCryptogramType,
                            ApplicationCapabilityInformation applicationCapabilitiesInformation,
                            Rrp.RrpResult rrpRez,
                            boolean isOdaStatusCdaSet,
                            ApplicationInterchangeProfile applicationInterchangeProfile,
                            boolean isDeviceCvmSupported,
                            List<TagAndLength> cdol1,
                            CrlRid crlRid,
                            Outcome.Cvm cvm,
                            boolean receiptRequired,
                            Optional<CaPublicKeyDb> caPublicKeyDb,
                            byte[] pdolData,
                            TransactionTimestamp ts,
                            byte[] staticDataToBeAuthenticated,
                            McTlvList deTagsToWriteYetAfterGenAc,
                            int messageHoldTime,
                            DsSummaryStatus dsSummaryStatus,
                            TerminalCapabilities13 terminalCapabilities13
    );

    static byte[] computePanHash(SensitiveData panSd, Optional<Tlv> panSeqO) {
        byte[] data;
        if (panSeqO.isPresent()) {
            data = new byte[panSd.getData().length + 1];
            System.arraycopy(panSd.getData(), 0, data, 0, panSd.getData().length);
            data[panSd.getData().length] = panSeqO.get().getValueBytes()[0];
        } else {
            data = panSd.getData();
        }


        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        byte[] hash = digest.digest(data);

        ByteUtils.purge(data);


        return hash;
    }

    Outcome recoverAcRoute(Transceiver transceiver,
                           TlvDb tlvDb,
                           TerminalVerificationResults terminalVerificationResults,
                           IdsStatus idsStatus,
                           boolean isEmvMode,
                           ApplicationCryptogramType requestedApplicationCryptogramType,
                           ApplicationCapabilityInformation applicationCapabilitiesInformation,
                           Rrp.RrpResult rrpRez,
                           boolean isOdaStatusCdaSet,
                           ApplicationInterchangeProfile applicationInterchangeProfile,
                           boolean isDeviceCvmSupported,
                           List<TagAndLength> cdol1,
                           CrlRid crlRid,
                           Outcome.Cvm cvm,
                           boolean receiptRequired,
                           Optional<CaPublicKeyDb> caPublicKeyDb,
                           byte[] pdolData,
                           TransactionTimestamp ts,
                           byte[] staticDataToBeAuthenticated,
                           McTlvList deTagsToWriteYetAfterGenAc,
                           int messageHoldTime,
                           DsSummaryStatus dsSummaryStatus,
                           TornTransactionLogRecord tornTransactionLogRecord,
                           boolean isSupportingBalanceReading,
                           boolean haveIds,
                           boolean isIdsVersion2,
                           TerminalCapabilities13 terminalCapabilities13) throws IOException;


}
