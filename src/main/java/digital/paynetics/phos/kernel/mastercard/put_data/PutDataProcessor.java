package digital.paynetics.phos.kernel.mastercard.put_data;

import java.io.IOException;

import digital.paynetics.phos.kernel.common.misc.McTlvList;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;


public interface PutDataProcessor {
    boolean processPutData(Transceiver transceiver, McTlvList deTagsToWriteYetBeforeGenAc) throws IOException;
}
