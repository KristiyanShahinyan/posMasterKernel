package digital.paynetics.phos.kernel.mastercard.misc;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.TagAndLength;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import java8.util.Optional;


public class MastercardDolPreparer {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(MastercardDolPreparer.class);


    private MastercardDolPreparer() {
        throw new AssertionError("Non-instantiable utility class");
    }


    public static byte[] prepareDol(TlvDb tlvDb, List<TagAndLength> dolList) {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            for (TagAndLength tal : dolList) {
                if (tlvDb.isTagPresentAndNonEmpty(tal.getTag())) {
                    Tlv tlv;
                    if (tal.getTag() != EmvTag.PAN && tal.getTag() != EmvTag.TRACK_2_EQV_DATA) {
                        tlv = tlvDb.get(tal.getTag());
                    } else {
                        if (tal.getTag() == EmvTag.PAN) {
                            // this is needed because of retarded test case that require PAN
                            Optional<SensitiveData> panSdO = tlvDb.getPan();
                            byte[] pan = ByteUtils.stripPanPadding(panSdO.get().getData());
                            tlv = new Tlv(EmvTag.PAN, pan.length, pan);

                            panSdO.get().purge();
                            ByteUtils.purge(pan);
                        } else {
                            // this is needed because of retarded test case that require TRACK_2_EQV_DATA
                            Optional<SensitiveData> sdO = tlvDb.getTrack2Eqv();
                            byte[] data = sdO.get().getData();
                            tlv = new Tlv(EmvTag.TRACK_2_EQV_DATA, data.length, data);

                            sdO.get().purge();
                            ByteUtils.purge(data);
                        }
                    }

                    // we need this because: (1) Test case requires the PAN to be sent back to the card as if it is demented and
                    // forgets its PAN. (2) PAN tag has wrong TagValueTypeEnum, i.e. it is not COMPRESSED_NUMERIC AND fitDolData
                    // does not support it
                    if (tal.getTag() != EmvTag.PAN) {
                        out.write(ByteUtils.fitDolData(tal, tlv.getValueBytes()));
                    } else {
                        if (tal.getLength() > tlv.getValueBytes().length) {
                            String pan = ByteUtils.toHexString(tlv.getValueBytes());
                            pan = StringUtils.rightPad(pan, tal.getLength() * 2, 'F');
                            out.write(ByteUtils.fromString(pan));
                        } else {
                            out.write(ByteUtils.fitDolData(tal, tlv.getValueBytes()));
                        }
                    }

//                    logger.debug("Preparing DOL, added: {} {}", tal.getTag().getName(), ByteUtils.toHexString(tlv.getValueBytes()));
                } else {
                    logger.warn("Preparing DOL, missing or empty tag: {} ({})", tal.getTag().getName(),
                            ByteUtils.toHexString(tal.getTag().getTagBytes()));
                    out.write(new byte[tal.getLength()]);
                }
            }

            return out.toByteArray();
        } catch (IOException e) {
            // cannot happen
            throw new RuntimeException(e);
        }
    }

}
