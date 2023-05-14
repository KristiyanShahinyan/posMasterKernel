package digital.paynetics.phos.kernel.mastercard.afl;

import java.util.List;

import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;


/**
 * Encapsulates result of processing an AFL
 * Use the static factory methods to create instances (constructor is private for safety reasons)
 */
public final class McAflProcessorResult {
    private final boolean isOk;
    private final Outcome outcome;
    private final List<Tlv> forTlvDb;
    private final List<Tlv> forTlvDbKernel;
    private final byte[] dataAuthenticationData;
    private final boolean cdaFailed;


    private McAflProcessorResult(boolean isOk,
                                 Outcome outcome,
                                 List<Tlv> forTlvDb,
                                 List<Tlv> forTlvDbKernel,
                                 byte[] dataAuthenticationData,
                                 boolean cdaFailed) {

        this.isOk = isOk;
        this.outcome = outcome;
        this.forTlvDb = forTlvDb;
        this.forTlvDbKernel = forTlvDbKernel;
        this.dataAuthenticationData = dataAuthenticationData;
        this.cdaFailed = cdaFailed;
    }


    public static McAflProcessorResult createOkResult(List<Tlv> fortlvDb,
                                                      List<Tlv> forTlvDbKernel,
                                                      byte[] dataAuthenticationData,
                                                      boolean cdaFailed) {

        return new McAflProcessorResult(true, null, fortlvDb, forTlvDbKernel, dataAuthenticationData, cdaFailed);
    }


    public static McAflProcessorResult createFailResult(Outcome outcome, boolean cdaFailed) {

        return new McAflProcessorResult(false, outcome, null, null, null, cdaFailed);
    }


    public boolean isOk() {
        return isOk;
    }


    /**
     * @return Outcome if {@link #isOk} returns false, null otherwise
     */
    public Outcome getOutcome() {
        return outcome;
    }


    public List<Tlv> getForTlvDb() {
        return forTlvDb;
    }

    public byte[] getDataAuthenticationData() {
        return dataAuthenticationData;
    }


    public List<Tlv> getForTlvDbKernel() {
        return forTlvDbKernel;
    }


    public boolean isCdaFailed() {
        return cdaFailed;
    }
}
