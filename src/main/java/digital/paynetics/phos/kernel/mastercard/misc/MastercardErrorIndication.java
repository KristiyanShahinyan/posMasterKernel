package digital.paynetics.phos.kernel.mastercard.misc;


import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;

import static digital.paynetics.phos.kernel.common.misc.PhosMessageFormat.format;
import static digital.paynetics.phos.kernel.mastercard.misc.MastercardMessageIdentifier.NOT_AVAILABLE;


public class MastercardErrorIndication {
    private final L1Error l1;
    private final L2Error l2;
    private final L3Error l3;
    private final Type type;
    @SuppressWarnings({"unused", "FieldCanBeLocal"})
    private final byte[] sw12;
    @SuppressWarnings({"unused", "FieldCanBeLocal"})
    private final MastercardMessageIdentifier messageIdentifier;


    private MastercardErrorIndication(L1Error l1, L2Error l2, L3Error l3, Type type, byte[] sw12,
                                      MastercardMessageIdentifier messageIdentifier) {
        this.l1 = l1;
        this.l2 = l2;
        this.l3 = l3;
        this.type = type;
        this.sw12 = sw12;
        if (messageIdentifier != null) {
            this.messageIdentifier = messageIdentifier;
        } else {
            this.messageIdentifier = NOT_AVAILABLE;
        }
    }


    public static MastercardErrorIndication createL1Error(L1Error error, byte[] sw) {
        return new MastercardErrorIndication(error, L2Error.OK, L3Error.OK, Type.L1, sw, null);
    }


    public static MastercardErrorIndication createL1Error(L1Error error, MastercardMessageIdentifier mi) {
        return new MastercardErrorIndication(error, L2Error.OK, L3Error.OK, Type.L1, null, mi);
    }


    public static MastercardErrorIndication createL2Error(L2Error error, MastercardMessageIdentifier mi) {
        if (error == L2Error.STATUS_BYTES) {
            throw new IllegalArgumentException("use createL2StatusBytesError()");
        }
        return new MastercardErrorIndication(L1Error.OK, error, L3Error.OK, Type.L2, null, mi);
    }


    public static MastercardErrorIndication createL2StatusBytesError(byte[] sw, MastercardMessageIdentifier mi) {
        return new MastercardErrorIndication(L1Error.OK, L2Error.STATUS_BYTES, L3Error.OK, Type.L2, sw, mi);
    }


    public static MastercardErrorIndication createL3Error(L3Error error, MastercardMessageIdentifier mi) {
        return new MastercardErrorIndication(L1Error.OK, L2Error.OK, error, Type.L3, null, mi);
    }


    public static MastercardErrorIndication createNoError() {
        return new MastercardErrorIndication(null, null, null, Type.NO_ERROR, null, MastercardMessageIdentifier.NO_MESSAGE);
    }

    public boolean hasError() {
        return l1 != L1Error.OK || l2 != L2Error.OK || l3 != L3Error.OK;
    }


    public Type getType() {
        return type;
    }


    public byte[] getSw12() {
        return sw12;
    }


    public L1Error getL1() {
        return l1;
    }


    public L2Error getL2() {
        return l2;
    }


    public L3Error getL3() {
        return l3;
    }


    public MastercardMessageIdentifier getMessageIdentifier() {
        return messageIdentifier;
    }


    @Override
    public String toString() {
        switch (type) {
            case L1:
                return format("L1 Error: {}, SW12 {}", l1, sw12 != null ? ByteUtils.toHexString(sw12) : "n/a");
            case L2:
                return format("L2 Error: {}, message: {}, SW12: {}", l2, messageIdentifier, sw12 != null ? ByteUtils.toHexString(sw12) : "n/a");
            case L3:
                return format("L3 Error: {}", l3);
            default:
                throw new AssertionError("Cannot happen");
        }
    }


    public static MastercardErrorIndication fromBytes(byte[] data) {
        if (data.length != 6) {
            throw new IllegalArgumentException("length != 6");
        }

        L1Error l1 = L1Error.fromByte(data[0]);
        L2Error l2 = L2Error.fromByte(data[1]);
        L3Error l3 = L3Error.fromByte(data[2]);

        Type type;
        if (l1 != L1Error.OK) {
            type = Type.L1;
        } else if (l2 != L2Error.OK) {
            type = Type.L2;
        } else if (l3 != L3Error.OK) {
            type = Type.L3;
        } else {
            type = Type.NO_ERROR;
        }

        byte[] sw12 = new byte[2];
        sw12[0] = data[3];
        sw12[1] = data[4];

        MastercardMessageIdentifier mi = MastercardMessageIdentifier.fromByte(data[5]);
        return new MastercardErrorIndication(l1, l2, l3, type, sw12, mi);
    }


    public enum L1Error {
        OK((byte) 0),
        TIME_OUT((byte) 0b00000001),
        TRANSMISSION_ERROR((byte) 0b00000010),
        PROTOCOL_ERROR((byte) 0b00000011);

        private final byte value;


        L1Error(byte value) {
            this.value = value;
        }


        public byte getValue() {
            return value;
        }


        public static L1Error fromByte(byte b) {
            switch (b) {
                case 0:
                    return OK;
                case 0b00000001:
                    return TIME_OUT;
                case 0b00000010:
                    return TRANSMISSION_ERROR;
                case 0b00000011:
                    return PROTOCOL_ERROR;
                default:
                    throw new IllegalArgumentException("Invalid L1 byte: " + ByteUtils.toHexString(new byte[]{b}));
            }
        }


    }


    public enum L2Error {
        OK((byte) 0),
        CARD_DATA_MISSING((byte) 0b00000001),
        CAM_FAILED((byte) 0b00000010),
        STATUS_BYTES((byte) 0b00000011),
        PARSING_ERROR((byte) 0b00000100),
        MAX_LIMIT_EXCEEDED((byte) 0b00000101),
        CARD_DATA_ERROR((byte) 0b00000110),
        MAGSTRIPE_NOT_SUPPORTED((byte) 0b00000111),
        NO_PPSE((byte) 0b00001000),
        PPSE_FAULT((byte) 0b00001001),
        EMPTY_CANDIDATE_LIST((byte) 0b00001010),
        IDS_READ_ERROR((byte) 0b00001011),
        IDS_WRITE_ERROR((byte) 0b00001100),
        IDS_DATA_ERROR((byte) 0b00001101),
        IDS_NO_MATCHING_AC((byte) 0b00001110),
        TERMINAL_DATA_ERROR((byte) 0b00001111);

        private final byte value;


        L2Error(byte value) {
            this.value = value;
        }


        public byte getValue() {
            return value;
        }


        public static L2Error fromByte(byte b) {
            switch (b) {
                case 0:
                    return OK;
                case 0b00000001:
                    return CARD_DATA_MISSING;
                case 0b00000010:
                    return CAM_FAILED;
                case 0b00000011:
                    return STATUS_BYTES;
                case 0b00000100:
                    return PARSING_ERROR;
                case 0b00000101:
                    return MAX_LIMIT_EXCEEDED;
                case 0b00000110:
                    return CARD_DATA_ERROR;
                case 0b00000111:
                    return MAGSTRIPE_NOT_SUPPORTED;
                case 0b00001000:
                    return NO_PPSE;
                case 0b00001001:
                    return PPSE_FAULT;
                case 0b00001010:
                    return EMPTY_CANDIDATE_LIST;
                case 0b00001011:
                    return IDS_READ_ERROR;
                case 0b00001100:
                    return IDS_WRITE_ERROR;
                case 0b00001101:
                    return IDS_DATA_ERROR;
                case 0b00001110:
                    return IDS_NO_MATCHING_AC;
                case 0b00001111:
                    return TERMINAL_DATA_ERROR;
                default:
                    throw new IllegalArgumentException("Invalid L2 byte: " + ByteUtils.toHexString(new byte[]{b}));
            }
        }
    }


    public enum L3Error {
        OK((byte) 0),
        TIME_OUT((byte) 0b00000001),
        STOP((byte) 0b00000010),
        AMOUNT_NOT_PRESENT((byte) 0b00000011);

        private final byte value;


        L3Error(byte value) {
            this.value = value;
        }


        public byte getValue() {
            return value;
        }


        public static L3Error fromByte(byte b) {
            switch (b) {
                case 0:
                    return OK;
                case 0b00000001:
                    return TIME_OUT;
                case 0b00000010:
                    return STOP;
                case 0b00000011:
                    return AMOUNT_NOT_PRESENT;
                default:
                    throw new IllegalArgumentException("Invalid L3 byte: " + ByteUtils.toHexString(new byte[]{b}));

            }
        }
    }


    public Tlv asErrorIndicationTlv() {
        if (type != Type.NO_ERROR) {
            byte[] data = new byte[]{l1.getValue(), l2.getValue(), l3.getValue(),
                    sw12 != null ? sw12[0] : 0,
                    sw12 != null ? sw12[1] : 0,
                    messageIdentifier != null ? messageIdentifier.getMessage().getCode() : (byte) 0
            };

            return new Tlv(EmvTag.ERROR_INDICATION, 6, data);
        } else {
            return new Tlv(EmvTag.ERROR_INDICATION, 6, new byte[]{0, 0, 0, 0, 0, (byte) 0xff});
        }


    }


    public enum Type {
        L1, L2, L3, NO_ERROR
    }
}
