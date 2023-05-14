package digital.paynetics.phos.kernel.mastercard.get_data;

import java.io.IOException;
import java.util.List;

import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;


public interface GetDataProcessor {
    Result process(Transceiver transceiver, List<EmvTag> tags) throws IOException;

    class Result {
        private final List<Tlv> forTlvDb;
        private final List<Tlv> forDataToSend;
        private final List<EmvTag> processedTags;


        public Result(List<Tlv> forTlvDb, List<Tlv> forDataToSend, List<EmvTag> processedTags) {
            this.forTlvDb = forTlvDb;
            this.forDataToSend = forDataToSend;
            this.processedTags = processedTags;
        }


        public List<Tlv> getForTlvDb() {
            return forTlvDb;
        }


        public List<Tlv> getForDataToSend() {
            return forDataToSend;
        }


        public List<EmvTag> getProcessedTags() {
            return processedTags;
        }
    }
}
