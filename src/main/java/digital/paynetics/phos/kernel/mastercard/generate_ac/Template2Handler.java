package digital.paynetics.phos.kernel.mastercard.generate_ac;

import java.util.List;

import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;


public interface Template2Handler {
    List<Tlv> handle(byte[] data) throws TlvException;
}
