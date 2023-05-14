package digital.paynetics.phos.kernel.mastercard.misc;

import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;


public class DsSummaryStatus {
    private boolean successfulRead;
    private boolean successfulWrite;


    public boolean isSuccessfulRead() {
        return successfulRead;
    }


    public void setSuccessfulRead(boolean successfulRead) {
        this.successfulRead = successfulRead;
    }


    public boolean isSuccessfulWrite() {
        return successfulWrite;
    }


    public void setSuccessfulWrite(boolean successfulWrite) {
        this.successfulWrite = successfulWrite;
    }


    public byte[] toBytes() {
        byte b = 0;
        if (successfulRead) {
            b |= 0b10000000;
        }

        if (successfulWrite) {
            b |= 0b01000000;
        }

        return new byte[]{b};
    }


    public Tlv toTlv() {
        return new Tlv(EmvTag.DS_SUMMARY_STATUS, 1, toBytes());
    }

}
