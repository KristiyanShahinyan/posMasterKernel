package digital.paynetics.phos.kernel.mastercard.gpo;

import java.util.List;

import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationInterchangeProfile;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardErrorIndication;


/**
 * Encapsulates the result of the execution of GET PROCESSING OPTIONS
 * If {@link #isOk} returns false then outcome is present and discretionaryData is optionally present
 * If {@link #isOk} returns true then applicationInterchangeProfile, applicationFileLocator and forTlvDb are
 * present for sure.
 * <p>
 * Use the static factory methods to create instance (constructor is private for safety reasons).
 */
public final class GpoResult {
    private final boolean isOk;
    private final boolean isTimeout;
    private final ApplicationInterchangeProfile applicationInterchangeProfile;
    private final byte[] applicationFileLocator;
    private final List<Tlv> forTlvDb;
    private final MastercardErrorIndication errorIndication;


    private GpoResult(boolean isOk,
                      boolean isTimeout, ApplicationInterchangeProfile applicationInterchangeProfile,
                      byte[] applicationFileLocator,
                      List<Tlv> forTlvDb,
                      MastercardErrorIndication errorIndication
    ) {

        this.isOk = isOk;
        this.isTimeout = isTimeout;
        this.applicationInterchangeProfile = applicationInterchangeProfile;
        this.applicationFileLocator = applicationFileLocator;
        this.forTlvDb = forTlvDb;
        this.errorIndication = errorIndication;
    }


    public static GpoResult createOkResult(ApplicationInterchangeProfile applicationInterchangeProfile,
                                           byte[] applicationFileLocator,
                                           List<Tlv> fortlvDb) {

        return new GpoResult(true, false, applicationInterchangeProfile, applicationFileLocator, fortlvDb, null);
    }


    public static GpoResult createFailResult(MastercardErrorIndication errorIndication, boolean isTimeout) {
        return new GpoResult(false, isTimeout, null, null, null, errorIndication);
    }


    /**
     * Indicated success of the GPO execution
     *
     * @return true if GPO execution and processing was successful, false otherwise
     */
    public boolean isOk() {
        return isOk;
    }


    public boolean isTimeout() {
        return isTimeout;
    }


    public ApplicationInterchangeProfile getApplicationInterchangeProfile() {
        return applicationInterchangeProfile;
    }


    public byte[] getApplicationFileLocator() {
        return applicationFileLocator;
    }


    /**
     * Returns list of TLVs that have to be added to the 'data record'
     *
     * @return List ot TLVs
     */
    public List<Tlv> getForTlvDb() {
        return forTlvDb;
    }


    public MastercardErrorIndication getErrorIndication() {
        return errorIndication;
    }
}
