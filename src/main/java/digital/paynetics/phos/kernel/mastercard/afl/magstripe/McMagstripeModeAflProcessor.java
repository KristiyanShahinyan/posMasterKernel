package digital.paynetics.phos.kernel.mastercard.afl.magstripe;

import java.io.IOException;

import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapReadOnly;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;
import digital.paynetics.phos.kernel.mastercard.afl.McAflProcessor;
import digital.paynetics.phos.kernel.mastercard.afl.McAflProcessorResult;


public interface McMagstripeModeAflProcessor extends McAflProcessor {
    McAflProcessorResult process(Transceiver transceiver, byte[] applicationFileLocator,
                                 TlvMapReadOnly tlvDb)
            throws IOException;
}
