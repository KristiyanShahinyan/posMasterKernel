package digital.paynetics.phos.kernel.mastercard.generate_ac;

import java.util.List;

import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;


public interface Template1Handler {
    List<Tlv> handle(byte[] data) throws EmvException;
}
