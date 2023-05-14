package digital.paynetics.phos.kernel.mastercard.dek_det;

import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;
import digital.paynetics.phos.kernel.common.emv.tag.TlvUtils;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import java8.util.Optional;


public class DekDetProcessorImpl implements DekDetProcessor {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());

    private final Optional<PhosDekDetFile> dekDetFileOptional;


    @Inject
    public DekDetProcessorImpl(PhosDekDetFile dekDetFileOptional) {
        this.dekDetFileOptional = Optional.ofNullable(dekDetFileOptional);
    }


    @Override
    public Result process(List<EmvTag> dataNeededIn, List<Tlv> dataToSendIn, boolean noDataNeeded) throws TlvException {
        if (!dekDetFileOptional.isPresent()) {
            throw new IllegalStateException("dekDet called but dekDetFileOptional is empty");
        }

        ByteArrayOutputStream dekDataBos = new ByteArrayOutputStream();

        try {
            ByteArrayOutputStream dataToSendBos = new ByteArrayOutputStream();
            for (Tlv tlv : dataToSendIn) {
                dataToSendBos.write(tlv.toByteArray());
            }

            byte[] dataToSendArr = dataToSendBos.toByteArray();
            Tlv dataToSendTlv = new Tlv(EmvTag.DATA_TO_SEND, dataToSendArr.length, dataToSendArr);

            ByteArrayOutputStream dataNeededBos = new ByteArrayOutputStream();
            for (EmvTag tag : dataNeededIn) {
                dataNeededBos.write(tag.getTagBytes());
            }

            byte[] dataNeededArr = dataNeededBos.toByteArray();
            Tlv dataNeededTlv = new Tlv(EmvTag.DATA_NEEDED, dataNeededArr.length, dataNeededArr);

            dekDataBos.write(dataToSendTlv.toByteArray());

            if (!noDataNeeded) {
                dekDataBos.write(dataNeededTlv.toByteArray());
            }
        } catch (IOException e) {
            throw new AssertionError("Cannot happen");
        }

        byte[] dekData = dekDataBos.toByteArray();

        // replacing unpredictable number with FFs as required ITF_DE03 (Mastercard Contactless Testing Environment)
        String dekDataStr = ByteUtils.toHexString(dekData);
        int unpredictableIndex = dekDataStr.indexOf("9F3704");
        if (unpredictableIndex > 0) {
            dekDataStr = dekDataStr.substring(0, unpredictableIndex + 6) + "FFFFFFFF" +
                    dekDataStr.substring(unpredictableIndex + 14);
        }

        dekData = ByteUtils.fromString(dekDataStr);

        if (dekData.length == 0) {
            logger.warn("dekData.length == 0");
            return null;
        }
        logger.debug("(dd) DEK: {}", ByteUtils.toHexString(dekData));

        boolean dekFound = false;

        List<byte[]> detDataList = new ArrayList<>();
        if (dekDetFileOptional.get().getItems() != null) {
            for (DekDetExchange x : dekDetFileOptional.get().getItems()) {
                if (Arrays.equals(x.getDek(), dekData)) {
                    detDataList = x.getDet();
                    dekFound = true;
                    break;
                }
            }
        }

        if (detDataList.size() == 0) {
            logger.warn("(dd) Unexpected DEK");
        }

        logger.debug("detDataList size: {}", detDataList.size());
        boolean allDetAreEmpty = true;

        int i = 1;
        for (byte[] d : detDataList) {
            logger.debug("(dd) DET {}: {}", i, ByteUtils.toHexString(d));
            i++;
            if (d.length != 0) {
                allDetAreEmpty = false;
            }
        }

        List<Tlv> ret = new ArrayList<>();

        for (byte[] detData : detDataList) {
            ret.addAll(TlvUtils.getTlvs(detData, true));
        }

        if (detDataList.size() > 0 && allDetAreEmpty) {
            logger.warn("All DETs are empty");
        }
        return new Result(ret, dekFound, allDetAreEmpty);
    }
}
