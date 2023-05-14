package digital.paynetics.phos.kernel.mastercard.get_data;

import java.io.IOException;

import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.nfc.ApduCommand;
import digital.paynetics.phos.kernel.common.nfc.ApduCommandPackage;
import digital.paynetics.phos.kernel.common.nfc.ApduResponsePackage;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;


public class GetDataUtil {
    private GetDataUtil() {
        throw new AssertionError("Non-instantiable utility class");
    }


    public static ApduResponsePackage executeGetData(Transceiver transceiver, EmvTag tag) throws IOException {
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
        return transceiver.transceive(cmd);
    }
}
