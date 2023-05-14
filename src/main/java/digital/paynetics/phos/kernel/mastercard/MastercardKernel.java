package digital.paynetics.phos.kernel.mastercard;

import java.io.IOException;
import java.util.List;

import digital.paynetics.phos.kernel.common.crypto.EncDec;
import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.cert.CaRidDbReadOnly;
import digital.paynetics.phos.kernel.common.emv.cert.CertificateRevocationListReadOnly;
import digital.paynetics.phos.kernel.common.emv.entry_point.misc.TransactionData;
import digital.paynetics.phos.kernel.common.emv.entry_point.selection.SelectedApplication;
import digital.paynetics.phos.kernel.common.emv.kernel.common.Kernel;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMap;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapImpl;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapReadOnly;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import digital.paynetics.phos.kernel.common.misc.CountryCode;
import digital.paynetics.phos.kernel.common.misc.TransactionTimestamp;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardErrorIndication;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardMagstripeFailedCounter;
import digital.paynetics.phos.kernel.mastercard.misc.TlvDb;

import static digital.paynetics.phos.kernel.mastercard.misc.MastercardMessageIdentifier.NOT_AVAILABLE;


public interface MastercardKernel extends Kernel {
    static List<Tlv> buildDataRecordEmv(TlvMapReadOnly tlvDb) {
        TlvMap dataRecord = new TlvMapImpl();

        dataRecord.add(tlvDb.getAsOptional(EmvTag.AMOUNT_AUTHORISED_NUMERIC));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.AMOUNT_OTHER_NUMERIC));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.APP_CRYPTOGRAM));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.APP_EXPIRATION_DATE));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.APPLICATION_INTERCHANGE_PROFILE));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.APPLICATION_LABEL));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.PAN));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.PAN_SEQUENCE_NUMBER));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.APP_PREFERRED_NAME));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.APP_TRANSACTION_COUNTER));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.APP_USAGE_CONTROL));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.APP_VERSION_NUMBER_TERMINAL));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.CRYPTOGRAM_INFORMATION_DATA));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.CVM_RESULTS));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.DEDICATED_FILE_NAME));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.INTERFACE_DEVICE_SERIAL_NUMBER));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.ISSUER_APPLICATION_DATA));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.ISSUER_CODE_TABLE_INDEX));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.PAYMENT_ACCOUNT_REFFERENCE));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.TERMINAL_CAPABILITIES));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.TERMINAL_COUNTRY_CODE));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.TERMINAL_TYPE));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.TERMINAL_VERIFICATION_RESULTS));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.VISA_FORM_FACTOR_INDICATOR__MS_THIRD_PARTY_DATA));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.TRACK_2_EQV_DATA));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.TRANSACTION_CATEGORY_CODE));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.TRANSACTION_CURRENCY_CODE));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.TRANSACTION_DATE));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.TRANSACTION_TYPE));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.UNPREDICTABLE_NUMBER));


        return dataRecord.asList();
    }

    static List<Tlv> buildDiscretionaryDataEmv(TlvMapReadOnly tlvDb, MastercardErrorIndication ei) {
        TlvMap dataRecord = new TlvMapImpl();

        dataRecord.add(tlvDb.getAsOptional(EmvTag.APPLICATION_CAPABILITIES_INFORMATION));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.APPLICATION_CURRENCY_CODE));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.BALANCE_READ_BEFORE_GEN_AC));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.BALANCE_READ_AFTER_GEN_AC));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.DS_SUMMARY_3));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.DS_SUMMARY_STATUS));
        dataRecord.add(ei != null ? ei.asErrorIndicationTlv() : new Tlv(EmvTag.ERROR_INDICATION, 6, new byte[6]));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.POST_GEN_AC_PUT_DATA_STATUS));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.PRE_GEN_AC_PUT_DATA_STATUS));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.VISA_FORM_FACTOR_INDICATOR__MS_THIRD_PARTY_DATA));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.TORN_RECORD));

        return dataRecord.asList();
    }

    static List<Tlv> buildDataRecordMagstripe(TlvMapReadOnly tlvDb) {
        TlvMap dataRecord = new TlvMapImpl();

        dataRecord.add(tlvDb.getAsOptional(EmvTag.APPLICATION_LABEL));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.APP_PREFERRED_NAME));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.DEDICATED_FILE_NAME));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.ISSUER_CODE_TABLE_INDEX));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.MAG_STRIPE_APP_VERSION_NUMBER_READER));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.PAYMENT_ACCOUNT_REFFERENCE));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.TRACK1_DATA));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.TRACK2_DATA));


        return dataRecord.asList();
    }

    static TlvMapReadOnly createDefaultKernelTlvs() {
        TlvMap ret = new TlvMapImpl();

        // ACCOUNT_TYPE is not required in C2, but some test need it to be empty
        Tlv tlv = new Tlv(EmvTag.ACCOUNT_TYPE, 0, new byte[0]);
        ret.add(tlv);


        byte[] data = new byte[5];
        tlv = new Tlv(EmvTag.ADDITIONAL_TERMINAL_CAPABILITIES, data.length, data);
        ret.add(tlv);

        data = new byte[]{0, 2};
        tlv = new Tlv(EmvTag.APP_VERSION_NUMBER_TERMINAL, data.length, data);
        ret.add(tlv);

        data = new byte[1];
        tlv = new Tlv(EmvTag.CARD_DATA_INPUT_CAPABILITY, data.length, data);
        ret.add(tlv);

        data = new byte[1];
        tlv = new Tlv(EmvTag.CVM_CAPABILITY_CVM_REQUIRED, data.length, data);
        ret.add(tlv);

        data = new byte[1];
        tlv = new Tlv(EmvTag.CVM_CAPABILITY_NO_CVM_REQUIRED, data.length, data);
        ret.add(tlv);

        data = ByteUtils.fromString("9F6A04");
        tlv = new Tlv(EmvTag.DEFAULT_UDOL, data.length, data);
        ret.add(tlv);

        data = new byte[]{0xd};
        tlv = new Tlv(EmvTag.HOLD_TIME_VALUE, data.length, data);
        ret.add(tlv);

        data = new byte[1];
        tlv = new Tlv(EmvTag.KERNEL_CONFIGURATION, data.length, data);
        ret.add(tlv);

        data = new byte[]{0x2};
        tlv = new Tlv(EmvTag.KERNEL_ID, data.length, data);
        ret.add(tlv);

        data = new byte[]{0x0, 0x1};
        tlv = new Tlv(EmvTag.MAG_STRIPE_APP_VERSION_NUMBER_READER, data.length, data);
        ret.add(tlv);

        data = new byte[]{(byte) 0xF0};
        tlv = new Tlv(EmvTag.MAG_STRIPE_CVM_CAPABILITY_CVM_REQUIRED, data.length, data);
        ret.add(tlv);

        data = new byte[]{(byte) 0xF0};
        tlv = new Tlv(EmvTag.MAG_STRIPE_CVM_CAPABILITY_NO_CVM_REQUIRED, data.length, data);
        ret.add(tlv);

        data = new byte[]{0x0, 0x1};
        tlv = new Tlv(EmvTag.MAX_LIFETIME_TORN_TRANSACTION_LOG_REC, data.length, data);
        ret.add(tlv);

        data = new byte[]{(byte) 0x00};
        tlv = new Tlv(EmvTag.MAX_NUMBER_TORN_TRANSACTION_LOG_REC, data.length, data);
        ret.add(tlv);

        data = new byte[]{0x0, 0x0, 0x13};
        tlv = new Tlv(EmvTag.MESSAGE_HOLD_TIME, data.length, data);
        ret.add(tlv);

        data = new byte[]{0x0, 0x32};
        tlv = new Tlv(EmvTag.MAXIMUM_RELAY_RESISTANCE_GRACE_PERIOD, data.length, data);
        ret.add(tlv);

        data = new byte[]{0x0, 0x14};
        tlv = new Tlv(EmvTag.MINIMUM_RELAY_RESISTANCE_GRACE_PERIOD, data.length, data);
        ret.add(tlv);

        data = new byte[6];
        tlv = new Tlv(EmvTag.READER_CONTACTLESS_FLOOR_LIMIT, data.length, data);
        ret.add(tlv);

        data = new byte[6];
        tlv = new Tlv(EmvTag.READER_CONTACTLESS_TRANSACTION_LIMIT_OD_CVM, data.length, data);
        ret.add(tlv);

        data = new byte[6];
        tlv = new Tlv(EmvTag.READER_CONTACTLESS_TRANSACTION_LIMIT_NO_OD_CVM, data.length, data);
        ret.add(tlv);

        data = new byte[6];
        tlv = new Tlv(EmvTag.READER_CVM_REQUIRED_LIMIT, data.length, data);
        ret.add(tlv);

        data = new byte[]{0x1, 0x2c};
        tlv = new Tlv(EmvTag.RELAY_RESISTANCE_ACCURACY_THRESHOLD, data.length, data);
        ret.add(tlv);

        data = new byte[]{(byte) 0x32};
        tlv = new Tlv(EmvTag.RELAY_RESISTANCE_TRANSMISSION_TIME_MISMATCH_THRESHOLD, data.length, data);
        ret.add(tlv);

        data = new byte[]{(byte) 0x0};
        tlv = new Tlv(EmvTag.SECURITY_CAPABILITY, data.length, data);
        ret.add(tlv);

        data = ByteUtils.fromString("840000000C");
        tlv = new Tlv(EmvTag.TERMINAL_ACTION_CODE_DEFAULT, data.length, data);
        ret.add(tlv);

        data = ByteUtils.fromString("840000000C");
        tlv = new Tlv(EmvTag.TERMINAL_ACTION_CODE_DENIAL, data.length, data);
        ret.add(tlv);

        data = ByteUtils.fromString("840000000C");
        tlv = new Tlv(EmvTag.TERMINAL_ACTION_CODE_ONLINE, data.length, data);
        ret.add(tlv);

        data = new byte[2];
        tlv = new Tlv(EmvTag.TERMINAL_COUNTRY_CODE, data.length, data);
        ret.add(tlv);

        data = new byte[]{0x0, 0x12};
        tlv = new Tlv(EmvTag.TERMINAL_EXPECTED_TRANSMISSION_TIME_C_APDU, data.length, data);
        ret.add(tlv);

        data = new byte[]{0x0, 0x18};
        tlv = new Tlv(EmvTag.TERMINAL_EXPECTED_TRANSMISSION_TIME_R_APDU, data.length, data);
        ret.add(tlv);

        data = new byte[]{(byte) 0x0};
        tlv = new Tlv(EmvTag.TERMINAL_TYPE, data.length, data);
        ret.add(tlv);

        data = new byte[]{0x01, (byte) 0xf4};
        tlv = new Tlv(EmvTag.TIME_OUT_VALUE, data.length, data);
        ret.add(tlv);

        return ret;
    }

    static List<Tlv> buildDiscretionaryDataMagstripe(TlvMapReadOnly tlvDb, MastercardErrorIndication ei) {
        TlvMap dataRecord = new TlvMapImpl();

        dataRecord.add(tlvDb.getAsOptional(EmvTag.APPLICATION_CAPABILITIES_INFORMATION));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.DD_CARD_TRACK1));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.DD_CARD_TRACK2));
        dataRecord.add(ei != null ? ei.asErrorIndicationTlv() : new Tlv(EmvTag.ERROR_INDICATION, 6, new byte[6]));
        dataRecord.add(tlvDb.getAsOptional(EmvTag.VISA_FORM_FACTOR_INDICATOR__MS_THIRD_PARTY_DATA));

        //TODO add DS Summary Status

        return dataRecord.asList();
    }

    static List<Tlv> buildDiscretionaryData(boolean isEmvMode, TlvMapReadOnly tlvDb, MastercardErrorIndication ei) {
        if (ei == null) {
            ei = MastercardErrorIndication.createNoError();
        }

        if (isEmvMode) {
            return buildDiscretionaryDataEmv(tlvDb, ei);
        } else {
            return buildDiscretionaryDataMagstripe(tlvDb, ei);
        }
    }

    Outcome process(Transceiver transceiver,
                    TlvMap commonDolData,
                    CountryCode countryCode,
                    TransactionData transactionData,
                    SelectedApplication selectedApp,
                    TransactionTimestamp ts
    ) throws IOException;


    static Outcome createStopOutcome() {
        Outcome.Builder b = new Outcome.Builder(Outcome.Type.END_APPLICATION);

        MastercardErrorIndication ei = MastercardErrorIndication.createL3Error(MastercardErrorIndication.L3Error.STOP, NOT_AVAILABLE);
        TlvMap dd = new TlvMapImpl();
        dd.add(ei.asErrorIndicationTlv());

        b.discretionaryData(dd.asList());
        b.start(Outcome.Start.NOT_APPLICABLE);

        return b.build();
    }


    void init(MastercardMagstripeFailedCounter mastercardMagstripeFailedCounter,
              CaRidDbReadOnly caRidDb,
              CertificateRevocationListReadOnly crl,
              EncDec encDec);

    Outcome clean(int ttl);

    TlvDb getTlvDb();

    boolean isEmvMode();
}
