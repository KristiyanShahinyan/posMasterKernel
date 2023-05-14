package digital.paynetics.phos.kernel.mastercard.misc;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;

import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.TagAndLength;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;
import digital.paynetics.phos.kernel.common.emv.tag.TlvUtils;


public class DolParser {
    private DolParser() {
        throw new AssertionError("Non-instantiable utility class");
    }


    public static List<TagAndLength> parse(byte[] data) throws TlvException {
        final List<TagAndLength> tagAndLengthList = new ArrayList<>();
        if (data != null) {
            final ByteArrayInputStream stream = new ByteArrayInputStream(data);

            while (stream.available() > 0) {
                if (stream.available() < 2) {
                    throw new TlvException("Data length < 2 : " + stream.available());
                }

                final EmvTag tag = EmvTag.resolveById(TlvUtils.readTagIdBytes(stream));
                final int tagValueLength = stream.read();

                tagAndLengthList.add(new TagAndLength(tag, tagValueLength));
            }
        }
        return tagAndLengthList;
    }
}
