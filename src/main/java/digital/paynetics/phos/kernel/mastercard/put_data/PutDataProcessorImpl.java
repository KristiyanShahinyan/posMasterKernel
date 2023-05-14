package digital.paynetics.phos.kernel.mastercard.put_data;

import org.slf4j.LoggerFactory;

import java.io.IOException;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.misc.McTlvList;
import digital.paynetics.phos.kernel.common.nfc.ApduCommand;
import digital.paynetics.phos.kernel.common.nfc.ApduCommandPackage;
import digital.paynetics.phos.kernel.common.nfc.ApduResponsePackage;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;


public class PutDataProcessorImpl implements PutDataProcessor {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());


    @Inject
    public PutDataProcessorImpl() {
    }


    @Override
    public boolean processPutData(Transceiver transceiver, McTlvList deTagsToWriteYetBeforeGenAc) throws IOException {
        for (Tlv tlv : deTagsToWriteYetBeforeGenAc.asList()) {
            if (!processOne(transceiver, tlv)) {
                logger.warn("PUT DATA not returned 90 00");
                return false;
            }
        }

        return true;
    }


    private boolean processOne(Transceiver transceiver, Tlv tlv) throws IOException {
        EmvTag tag = tlv.getTag();
        logger.debug("(nfc) Will do PUT DATA for {} ({} bytes)", tag.getName(), tlv.getValueBytes().length);

        byte p1, p2;
        if (tag.getTagBytes().length == 1) {
            p1 = 0;
            p2 = tag.getTagBytes()[0];
        } else {
            p1 = tag.getTagBytes()[0];
            p2 = tag.getTagBytes()[1];
        }
        ApduCommandPackage cmd = new ApduCommandPackage(ApduCommand.PUT_DATA, p1, p2, tlv.getValueBytes(), -1);

        ApduResponsePackage resp = transceiver.transceive(cmd);
        resp.purgeData();
        return resp.isSuccess();
    }
}
