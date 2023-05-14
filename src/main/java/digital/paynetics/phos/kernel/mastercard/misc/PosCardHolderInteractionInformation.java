package digital.paynetics.phos.kernel.mastercard.misc;

import java.math.BigInteger;

import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;


public final class PosCardHolderInteractionInformation {
    private PosCardHolderInteractionInformation() {
        throw new AssertionError("Non-instantiable utility class");
    }


    public static boolean isOdCvmSuccessful(Tlv tlv) throws EmvException {
        if (tlv.getTag() != EmvTag.POS_CARDHOLDER_INTERACTION_INFORMATION) {
            throw new IllegalArgumentException("Unexpected TLV, not POS_CARDHOLDER_INTERACTION_INFORMATION");
        }

        byte[] data = tlv.getValueBytes();
        if (data.length != 3) {
            throw new EmvException("Invalid POS_CARDHOLDER_INTERACTION_INFORMATION data length");
        }

        BigInteger bi = BigInteger.valueOf(data[1]);

        return bi.testBit(5 - 1);
    }


    public static boolean isSecondTapNeeded(Tlv tlv) {
        if (tlv.getTag() != EmvTag.POS_CARDHOLDER_INTERACTION_INFORMATION) {
            throw new IllegalArgumentException("Unexpected TLV, not POS_CARDHOLDER_INTERACTION_INFORMATION");
        }

        byte[] pcii = tlv.getValueBytes();
        byte[] test = {0x00, 0x03, (byte) 0x0f};

        return !ByteUtils.isByteArrayZeros(ByteUtils.byteArrayAnd(pcii, test));
    }
}
