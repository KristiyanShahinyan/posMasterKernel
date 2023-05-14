package digital.paynetics.phos.kernel.mastercard.gpo;

import java.io.IOException;

import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;


public interface GpoExecutor {
    GpoResult execute(Transceiver transceiver, byte[] pdolPrepared, boolean aipOrAflPresentAndNonEmpty) throws IOException;
}
