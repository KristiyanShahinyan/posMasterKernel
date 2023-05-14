package digital.paynetics.phos.kernel.mastercard.torn;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.mastercard.misc.SensitiveData;
import digital.paynetics.phos.kernel.mastercard.misc.TlvDb;
import java8.util.Optional;


public class TornTransactionLogRecord {
    private final byte[] panHash;
    private final List<Tlv> tlvs = new ArrayList<>();
    private final long ts;


    public TornTransactionLogRecord(TlvDb tlvDb, byte[] panHash, long ts) {
        this.panHash = panHash;
        this.ts = ts;
        for (EmvTag tag : getTornRecordTags()) {
            addIfPresentAndNonEmpty(tlvDb, tag);
        }
    }


    private void addIfPresentAndNonEmpty(TlvDb tlvDb, EmvTag tag) {
        if (tlvDb.isTagPresentAndNonEmpty(tag)) {
            if (tag == EmvTag.PAN) {
                Optional<SensitiveData> sdO = tlvDb.getPan();
                tlvs.add(new Tlv(EmvTag.PAN, sdO.get().getData().length, sdO.get().getData()));
            } else {
                tlvs.add(tlvDb.get(tag));
            }
        }
    }


    public static List<EmvTag> getTornRecordTags() {
        List<EmvTag> ret = new ArrayList<>();

        ret.add(EmvTag.AMOUNT_AUTHORISED_NUMERIC);
        ret.add(EmvTag.AMOUNT_OTHER_NUMERIC);
        ret.add(EmvTag.PAN);
        ret.add(EmvTag.PAN_SEQUENCE_NUMBER);
        ret.add(EmvTag.BALANCE_READ_BEFORE_GEN_AC);
        ret.add(EmvTag.CDOL1_RELATED_DATA);
        ret.add(EmvTag.CVM_RESULTS);
        ret.add(EmvTag.DRDOL_RELATED_DATA);
        ret.add(EmvTag.DS_SUMMARY_1);
        ret.add(EmvTag.IDS_STATUS);
        ret.add(EmvTag.INTERFACE_DEVICE_SERIAL_NUMBER);
        ret.add(EmvTag.PDOL_RELATED_DATA);
        ret.add(EmvTag.REFERENCE_CONTROL_PARAMETER);
        ret.add(EmvTag.TERMINAL_CAPABILITIES);
        ret.add(EmvTag.TERMINAL_COUNTRY_CODE);
        ret.add(EmvTag.TERMINAL_TYPE);
        ret.add(EmvTag.TERMINAL_VERIFICATION_RESULTS);
        ret.add(EmvTag.TRANSACTION_CATEGORY_CODE);
        ret.add(EmvTag.TRANSACTION_CURRENCY_CODE);
        ret.add(EmvTag.TRANSACTION_DATE);
        ret.add(EmvTag.TRANSACTION_TIME);
        ret.add(EmvTag.TRANSACTION_TYPE);
        ret.add(EmvTag.UNPREDICTABLE_NUMBER);
        ret.add(EmvTag.TERMINAL_RELAY_RESISTANCE_ENTROPY);
        ret.add(EmvTag.DEVICE_RELAY_RESISTANCE_ENTROPY);
        ret.add(EmvTag.MIN_TIME_FOR_PROCESSING_RELAY_RESISTANCE_APDU);
        ret.add(EmvTag.MAX_TIME_FOR_PROCESSING_RELAY_RESISTANCE_APDU);
        ret.add(EmvTag.DEVICE_ESTIMATED_TRANSMISSION_TIME_FOR_RELAY_RESISTANCE_RAPDU);
        ret.add(EmvTag.MEASURED_RELAY_RESISTANCE_PROCESSING_TIME);
        ret.add(EmvTag.RRP_COUNTER);

        return ret;
    }


    public byte[] getPanHash() {
        return panHash;
    }


    public Tlv toTlv() {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            for (Tlv tlv : tlvs) {
                baos.write(tlv.toByteArray());
            }
            byte[] data = baos.toByteArray();
            return new Tlv(EmvTag.TORN_RECORD, data.length, data);
        } catch (IOException e) {
            throw new AssertionError("Cannot happen");
        }
    }


    public List<Tlv> getTlvs() {
        return tlvs;
    }


    public long getTs() {
        return ts;
    }
}
