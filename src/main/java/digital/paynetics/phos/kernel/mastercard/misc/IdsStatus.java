package digital.paynetics.phos.kernel.mastercard.misc;

import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;


public class IdsStatus {
    private boolean read;
    private boolean write;


    public boolean isRead() {
        return read;
    }


    public void setRead(boolean read) {
        this.read = read;
    }


    public boolean isWrite() {
        return write;
    }


    public void setWrite(boolean write) {
        this.write = write;
    }


    public Tlv toTlv() {
        byte b = 0;
        if (read) {
            b |= 0b10000000;
        }

        if (write) {
            b |= 0b01000000;
        }

        byte[] data = new byte[]{b};
        return new Tlv(EmvTag.IDS_STATUS, data.length, data);
    }


    public static IdsStatus fromByte(byte b) {
        IdsStatus ret = new IdsStatus();
        if ((b & 0b10000000) == 0b10000000) {
            ret.setRead(true);
        }

        if ((b & 0b01000000) == 0b01000000) {
            ret.setWrite(true);
        }

        return ret;
    }
}
