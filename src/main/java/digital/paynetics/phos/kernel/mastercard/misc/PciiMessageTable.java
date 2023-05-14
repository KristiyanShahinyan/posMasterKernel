package digital.paynetics.phos.kernel.mastercard.misc;

import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.emv.ui.ContactlessTransactionStatus;
import digital.paynetics.phos.kernel.common.emv.ui.StandardMessages;
import digital.paynetics.phos.kernel.common.emv.ui.UserInterfaceRequest;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;


public final class PciiMessageTable {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(PciiMessageTable.class);


    private PciiMessageTable() {
        throw new AssertionError("Non-instantiable utility class");
    }


    private static List<Entry> entries = new ArrayList<>();

    static {
        UserInterfaceRequest seePhone =
                new UserInterfaceRequest(StandardMessages.SEE_PHONE_FOR_INSTRUCTIONS,
                        ContactlessTransactionStatus.NOT_READY,
                        13,
                        null, null, 0, null
                );

        entries.add(new Entry(ByteUtils.fromString("000001"),
                ByteUtils.fromString("000001"),
                seePhone
        ));
        entries.add(new Entry(ByteUtils.fromString("000800"),
                ByteUtils.fromString("000800"),
                seePhone
        ));
        entries.add(new Entry(ByteUtils.fromString("000400"),
                ByteUtils.fromString("000400"),
                seePhone
        ));
        entries.add(new Entry(ByteUtils.fromString("000100"),
                ByteUtils.fromString("000100"),
                seePhone
        ));
        entries.add(new Entry(ByteUtils.fromString("000200"),
                ByteUtils.fromString("000200"),
                seePhone
        ));
        entries.add(new Entry(ByteUtils.fromString("000000"),
                ByteUtils.fromString("000000"),
                new UserInterfaceRequest(StandardMessages.NOT_AUTHORIZED,
                        ContactlessTransactionStatus.NOT_READY,
                        13,
                        null, null, 0, null
                )
        ));
    }


    public static UserInterfaceRequest getUir(Tlv tlv) {
        String pciiStr = ByteUtils.toHexString(tlv.getValueBytes());
        logger.debug("second tap needed. PCII: {}", pciiStr);

        for (Entry e : entries) {
            if (Arrays.equals(ByteUtils.byteArrayAnd(e.getMask(), tlv.getValueBytes()), e.getValue())) {
                return e.getUir();
            }
        }

        // we cannot reach here because 000000 will match everything but we need to keep the compiler happy
        return new UserInterfaceRequest(StandardMessages.NOT_AUTHORIZED,
                ContactlessTransactionStatus.NOT_READY,
                0,
                null, null, 0, null
        );
    }


    private static class Entry {
        private final byte[] mask;
        private final byte[] value;
        private final UserInterfaceRequest uir;


        public Entry(byte[] mask, byte[] value, UserInterfaceRequest uir) {
            this.mask = mask;
            this.value = value;
            this.uir = uir;
        }


        public byte[] getMask() {
            return mask;
        }


        public byte[] getValue() {
            return value;
        }


        public UserInterfaceRequest getUir() {
            return uir;
        }
    }
}
