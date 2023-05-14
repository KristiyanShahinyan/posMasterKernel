package digital.paynetics.phos.kernel.mastercard.get_data;

import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;
import digital.paynetics.phos.kernel.common.emv.tag.TlvUtils;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import digital.paynetics.phos.kernel.common.nfc.ApduCommand;
import digital.paynetics.phos.kernel.common.nfc.ApduCommandPackage;
import digital.paynetics.phos.kernel.common.nfc.ApduResponsePackage;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;
import digital.paynetics.phos.kernel.mastercard.misc.GetDataTags;


public class GetDataProcessorImpl implements GetDataProcessor {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());


    @Inject
    public GetDataProcessorImpl() {
    }


    @Override
    public Result process(Transceiver transceiver, List<EmvTag> tags) throws IOException {
        List<Tlv> forTlvDb = new ArrayList<>();
        List<Tlv> forDataToSend = new ArrayList<>();
        List<EmvTag> processedTags = new ArrayList<>();

        if (GetDataTags.containsGetDataTags(tags)) {
            for (EmvTag tag : tags) {
                if (GetDataTags.isGetDataTag(tag)) {
                    Tlv tlv = processTag(transceiver, tag);
                    processedTags.add(tag);
                    if (tlv != null) {
                        forTlvDb.add(tlv);
                        forDataToSend.add(tlv);
                    } else {
                        forDataToSend.add(new Tlv(tag, 0, new byte[0]));
                    }
                }
            }
        }


        return new Result(forTlvDb, forDataToSend, processedTags);
    }


    private Tlv processTag(Transceiver transceiver, EmvTag tag) throws IOException {
        logger.debug("Will do GET DATA for {} ({})", tag.getName(), ByteUtils.toHexString(tag.getTagBytes()));
        // S3R1.2, S5.11
        byte p1, p2;
        if (tag.getTagBytes().length == 1) {
            p1 = 0;
            p2 = tag.getTagBytes()[0];
        } else {
            p1 = tag.getTagBytes()[0];
            p2 = tag.getTagBytes()[1];
        }
        ApduCommandPackage cmd = new ApduCommandPackage(ApduCommand.GET_DATA, p1, p2, null, 0);

        // S3R1.3, S5.12
        ApduResponsePackage resp = transceiver.transceive(cmd);

        // S5.19
        if (resp.isSuccess()) {
            // S5.20
            try {
                // S5.21
                Tlv tlv = TlvUtils.getNextTlv(resp.getData());
                resp.purgeData();
                // S5.22
                if (tlv.getTag() == tag) {
                    return tlv;
                } else {
                    return null;
                }
            } catch (TlvException e) {
                return null;
            }
        } else {
            resp.purgeData();
            // do nothing, we will not send anything to terminal
            return null;
        }
    }
}
