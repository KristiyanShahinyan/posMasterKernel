package digital.paynetics.phos.kernel.mastercard.dek_det;

import java.util.List;

import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;


public interface DekDetProcessor {
    Result process(List<EmvTag> dataNeededIn, List<Tlv> dataToSendIn, boolean noDataNeeded) throws TlvException;

    class Result {
        private final List<Tlv> data;
        private final boolean dekFound;
        private final boolean allEmpty;


        public Result(List<Tlv> data, boolean dekFound, boolean allEmpty) {
            this.data = data;
            this.dekFound = dekFound;
            this.allEmpty = allEmpty;
        }


        public List<Tlv> getData() {
            return data;
        }


        public boolean isDekFound() {
            return dekFound;
        }


        public boolean isAllDetEmpty() {
            return allEmpty;
        }
    }
}
