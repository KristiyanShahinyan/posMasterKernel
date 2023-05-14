package digital.paynetics.phos.kernel.mastercard;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import java8.util.Optional;

import static digital.paynetics.phos.kernel.common.misc.PhosMessageFormat.format;


public final class MastercardTags {
    private static final Map<EmvTag, MastercardTag> tags = new HashMap<>();

    static {
        add(new MastercardTag(EmvTag.ACCOUNT_TYPE, true, true, false, true, 1, 1));
        add(new MastercardTag(EmvTag.ACQUIRER_IDENTIFIER, false, true, false, false, 6, 6));
        add(new MastercardTag(EmvTag.ADDITIONAL_TERMINAL_CAPABILITIES, false, true, false, false, 5, 5));
        add(new MastercardTag(EmvTag.AMOUNT_AUTHORISED_NUMERIC, true, true, false, true, 6, 6));
        add(new MastercardTag(EmvTag.AMOUNT_OTHER_NUMERIC, true, true, false, true, 6, 6));
        add(new MastercardTag(EmvTag.APPLICATION_CAPABILITIES_INFORMATION, false, true, true, false, 3, 3,
                EmvTag.FCI_ISSUER_DISCRETIONARY_DATA));
        add(new MastercardTag(EmvTag.APP_CRYPTOGRAM, false, true, true, false, 8, 8, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.APPLICATION_CURRENCY_CODE, false, true, true, false, 2, 2, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.APP_CURRENCY_EXPONENT, false, true, true, false, 1, 1, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.APP_EFFECTIVE_DATE, false, true, true, false, 3, 3, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.APP_EXPIRATION_DATE, false, true, true, false, 3, 3, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.APPLICATION_FILE_LOCATOR, false, true, true, false, 4, 248, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.APPLICATION_INTERCHANGE_PROFILE, false, true, true, false, 2, 2, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.APPLICATION_LABEL, false, true, true, false, 0, 16, EmvTag.FCI_PROPRIETARY_TEMPLATE));
        add(new MastercardTag(EmvTag.APP_PREFERRED_NAME, false, true, true, false, 0, 16, EmvTag.FCI_PROPRIETARY_TEMPLATE));
        add(new MastercardTag(EmvTag.PAN, false, true, true, false, 0, 10, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.PAN_SEQUENCE_NUMBER, false, true, true, false, 1, 1, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.APPLICATION_PRIORITY_INDICATOR, false, true, true, false, 1, 1, EmvTag.FCI_PROPRIETARY_TEMPLATE));
        add(new MastercardTag(EmvTag.APP_TRANSACTION_COUNTER, false, true, true, false, 2, 2, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.APP_USAGE_CONTROL, false, true, true, false, 2, 2, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.APP_VERSION_NUMBER_CARD, false, true, true, false, 2, 2, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.APP_VERSION_NUMBER_TERMINAL, false, true, true, false, 2, 2));
        add(new MastercardTag(EmvTag.BALANCE_READ_BEFORE_GEN_AC, true, true, false, true, 6, 6));
        add(new MastercardTag(EmvTag.BALANCE_READ_AFTER_GEN_AC, true, true, false, true, 6, 6));
        add(new MastercardTag(EmvTag.CA_PUBLIC_KEY_INDEX_CARD, false, true, true, false, 1, 1, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.CARD_DATA_INPUT_CAPABILITY, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.CDOL1, false, true, true, false, 0, 250, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.CDOL1_RELATED_DATA, false, true, false, false, 0, 1000));
        add(new MastercardTag(EmvTag.CRYPTOGRAM_INFORMATION_DATA, false, true, true, false, 1, 1, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.CVC3_TRACK1, false, true, true, false, 2, 2, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.CVC3_TRACK2, false, true, true, false, 2, 2, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.CVM_CAPABILITY_CVM_REQUIRED, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.CVM_CAPABILITY_NO_CVM_REQUIRED, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.CVM_LIST, false, true, true, false, 10, 250, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.CVM_RESULTS, false, true, false, false, 3, 3));
        add(new MastercardTag(EmvTag.DATA_NEEDED, false, true, false, false, 0, 1000));
        add(new MastercardTag(EmvTag.DATA_RECORD, false, true, false, false, 0, 1000));
        add(new MastercardTag(EmvTag.DATA_TO_SEND, false, true, false, false, 0, 1000));
        add(new MastercardTag(EmvTag.DD_CARD_TRACK1, false, true, false, false, 0, 56));
        add(new MastercardTag(EmvTag.DD_CARD_TRACK2, false, true, false, false, 0, 11));
        add(new MastercardTag(EmvTag.DEFAULT_UDOL, false, true, false, false, 3, 3));
        add(new MastercardTag(EmvTag.DEVICE_ESTIMATED_TRANSMISSION_TIME_FOR_RELAY_RESISTANCE_RAPDU, false, true, true, false, 2, 2));
        add(new MastercardTag(EmvTag.DEVICE_RELAY_RESISTANCE_ENTROPY, false, true, true, false, 4, 4));
        add(new MastercardTag(EmvTag.DEDICATED_FILE_NAME, false, true, true, false, 5, 16, EmvTag.FCI_TEMPLATE));
        add(new MastercardTag(EmvTag.DISCRETIONARY_DATA, false, true, false, false, 0, 1000));
        add(new MastercardTag(EmvTag.DRDOL, false, true, true, false, 0, 250, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.DRDOL_RELATED_DATA, false, true, false, false, 0, 1000));
        add(new MastercardTag(EmvTag.DS_AC_TYPE, true, true, false, true, 1, 1));
        add(new MastercardTag(EmvTag.DS_DIGEST_H, false, true, false, false, 8, 8));
        add(new MastercardTag(EmvTag.DSDOL, false, true, true, false, 0, 250, EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.DS_ID, false, true, true, false, 8, 11, EmvTag.FCI_ISSUER_DISCRETIONARY_DATA));
        add(new MastercardTag(EmvTag.VISA_LOG_ENTRY__MS_DS_INPUT, true, true, false, true, 8, 8));
        add(new MastercardTag(EmvTag.DS_INPUT_TERM, true, true, false, true, 8, 8));
        add(new MastercardTag(EmvTag.DS_ODS_CARD, false, true, true, false, 0, 160, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.DS_ODS_INFO, true, true, false, true, 1, 1));
        add(new MastercardTag(EmvTag.DS_ODS_INFO_FOR_READER, true, true, false, true, 1, 1));
        add(new MastercardTag(EmvTag.DS_ODS_TERM, true, true, false, true, 0, 160));
        add(new MastercardTag(EmvTag.DS_REQUESTED_OPERATOR_ID, true, true, false, true, 8, 8));
        add(new MastercardTag(EmvTag.DS_SLOT_AVAILABILITY, false, true, true, false, 1, 1, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.DS_SLOT_MANAGEMENT_CONTROL, false, true, true, false, 1, 1, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.DS_SUMMARY_1, false, true, true, false, 8, 18, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.DS_SUMMARY_2, false, true, true, false, 8, 16));
        add(new MastercardTag(EmvTag.DS_SUMMARY_3, false, true, true, false, 8, 16));
        add(new MastercardTag(EmvTag.DS_SUMMARY_STATUS, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.DS_UNPREDICTABLE_NUMBER, false, true, true, false, 4, 4, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.DSVN_TERM, false, true, false, false, 0, 1000));
        add(new MastercardTag(EmvTag.ERROR_INDICATION, false, true, false, false, 6, 6));
        add(new MastercardTag(EmvTag.FCI_ISSUER_DISCRETIONARY_DATA, false, true, true, false, 0, 220, EmvTag.FCI_PROPRIETARY_TEMPLATE));
        add(new MastercardTag(EmvTag.FCI_PROPRIETARY_TEMPLATE, false, true, true, false, 0, 240, EmvTag.FCI_TEMPLATE));
        add(new MastercardTag(EmvTag.FCI_TEMPLATE, false, true, true, false, 0, 250));
        add(new MastercardTag(EmvTag.HOLD_TIME_VALUE, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.ICC_DYNAMIC_NUMBER, false, true, true, false, 2, 8));
        add(new MastercardTag(EmvTag.ICC_PUBLIC_KEY_CERT, false, true, true, false, 0, 248, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.ICC_PUBLIC_KEY_EXPONENT, false, true, true, false, 1, 3, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.ICC_PUBLIC_KEY_REMAINDER, false, true, true, false, 0, 1000, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.IDS_STATUS, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.INTERFACE_DEVICE_SERIAL_NUMBER, false, true, false, false, 8, 8));
        add(new MastercardTag(EmvTag.ISSUER_ACTION_CODE_DEFAULT, false, true, true, false, 5, 5, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.ISSUER_ACTION_CODE_DENIAL, false, true, true, false, 5, 5, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.ISSUER_ACTION_CODE_ONLINE, false, true, true, false, 5, 5, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.ISSUER_APPLICATION_DATA, false, true, true, false, 0, 32, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.ISSUER_CODE_TABLE_INDEX, false, true, true, false, 1, 1, EmvTag.FCI_PROPRIETARY_TEMPLATE));
        add(new MastercardTag(EmvTag.ISSUER_COUNTRY_CODE, false, true, true, false, 2, 2, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.ISSUER_PUBLIC_KEY_CERT, false, true, true, false, 0, 248, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.ISSUER_PUBLIC_KEY_EXPONENT, false, true, true, false, 1, 3, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.ISSUER_PUBLIC_KEY_REMAINDER, false, true, true, false, 0, 1000, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2,
                EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.KERNEL_CONFIGURATION, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.KERNEL_ID, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.LANGUAGE_PREFERENCE, false, true, true, false, 2, 8, EmvTag.FCI_PROPRIETARY_TEMPLATE));
        add(new MastercardTag(EmvTag.LOG_ENTRY, false, true, true, false, 2, 2, EmvTag.FCI_ISSUER_DISCRETIONARY_DATA));
        add(new MastercardTag(EmvTag.MAG_STRIPE_APP_VERSION_NUMBER_READER, false, true, false, false, 2, 2));
        add(new MastercardTag(EmvTag.MAG_STRIPE_CVM_CAPABILITY_CVM_REQUIRED, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.MAG_STRIPE_CVM_CAPABILITY_NO_CVM_REQUIRED, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.MAXIMUM_RELAY_RESISTANCE_GRACE_PERIOD, false, true, false, false, 2, 2));
        add(new MastercardTag(EmvTag.MAX_TIME_FOR_PROCESSING_RELAY_RESISTANCE_APDU, false, true, true, false, 2, 2));
        add(new MastercardTag(EmvTag.MAX_LIFETIME_TORN_TRANSACTION_LOG_REC, false, true, false, false, 2, 2));
        add(new MastercardTag(EmvTag.MAX_NUMBER_TORN_TRANSACTION_LOG_REC, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.MEASURED_RELAY_RESISTANCE_PROCESSING_TIME, false, true, false, false, 2, 2));
        add(new MastercardTag(EmvTag.MERCHANT_CATEGORY_CODE, false, true, false, false, 2, 2));
        add(new MastercardTag(EmvTag.MERCHANT_CUSTOM_DATA, true, true, false, true, 20, 20));
        add(new MastercardTag(EmvTag.MERCHANT_IDENTIFIER, false, true, false, false, 15, 15));
        add(new MastercardTag(EmvTag.MERCHANT_NAME_AND_LOCATION, false, true, false, false, 0, 1000));
        add(new MastercardTag(EmvTag.MESSAGE_HOLD_TIME, false, true, false, false, 3, 3));
        add(new MastercardTag(EmvTag.MINIMUM_RELAY_RESISTANCE_GRACE_PERIOD, false, true, false, false, 2, 2));
        add(new MastercardTag(EmvTag.MIN_TIME_FOR_PROCESSING_RELAY_RESISTANCE_APDU, false, true, true, false, 2, 2));
        add(new MastercardTag(EmvTag.MOBILE_SUPPORT_INDICATOR, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.NATC_TRACK1, false, true, true, false, 1, 1, EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.NATC_TRACK2, false, true, true, false, 1, 1, EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.OFFLINE_ACCUMULATOR_BALANCE, false, true, true, false, 6, 6));
        add(new MastercardTag(EmvTag.OUTCOME_PARAMETER_SET, false, true, false, false, 8, 8));
        add(new MastercardTag(EmvTag.PAYMENT_ACCOUNT_REFFERENCE, false, true, true, false, 29, 29, EmvTag.RECORD_TEMPLATE,
                EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.PCVC3_TRACK1, false, true, true, false, 6, 6, EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.PCVC3_TRACK2, false, true, true, false, 2, 2, EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.PDOL, false, true, true, false, 0, 240, EmvTag.FCI_PROPRIETARY_TEMPLATE));
        add(new MastercardTag(EmvTag.PDOL_RELATED_DATA, false, true, false, false, 0, 1000));
        add(new MastercardTag(EmvTag.PHONE_MESSAGE_TABLE, false, true, false, false, 0, 1000));
        add(new MastercardTag(EmvTag.POS_CARDHOLDER_INTERACTION_INFORMATION, false, true, true, false, 3, 3,
                EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.POST_GEN_AC_PUT_DATA_STATUS, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.PRE_GEN_AC_PUT_DATA_STATUS, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.PROCEED_TO_FIRST_WRITE_FLAG, true, true, false, true, 1, 1));
        add(new MastercardTag(EmvTag.PROTECTED_DATA_ENVELOPE_1, true, true, true, true, 0, 192));
        add(new MastercardTag(EmvTag.PROTECTED_DATA_ENVELOPE_2, true, true, true, true, 0, 192));
        add(new MastercardTag(EmvTag.PROTECTED_DATA_ENVELOPE_3, true, true, true, true, 0, 192));
        add(new MastercardTag(EmvTag.PROTECTED_DATA_ENVELOPE_4, true, true, true, true, 0, 192));
        add(new MastercardTag(EmvTag.PROTECTED_DATA_ENVELOPE_5, true, true, true, true, 0, 192));
        add(new MastercardTag(EmvTag.PUNATC_TRACK1, false, true, true, false, 6, 6, EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.TERMINAL_TRANSACTION_QUALIFIERS__PUNATC_TRACK2, false, true, true, false, 2, 2, EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.READER_CONTACTLESS_FLOOR_LIMIT, false, true, false, false, 6, 6));
        add(new MastercardTag(EmvTag.READER_CONTACTLESS_TRANSACTION_LIMIT_NO_OD_CVM, false, true, false, false, 6, 6));
        add(new MastercardTag(EmvTag.READER_CONTACTLESS_TRANSACTION_LIMIT_OD_CVM, false, true, false, false, 6, 6));
        add(new MastercardTag(EmvTag.READER_CVM_REQUIRED_LIMIT, false, true, false, false, 6, 6));
        add(new MastercardTag(EmvTag.READ_RECORD_RESPONSE_MESSAGE_TEMPLATE, false, true, true, false, 0, 253));
        add(new MastercardTag(EmvTag.REFERENCE_CONTROL_PARAMETER, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.RELAY_RESISTANCE_ACCURACY_THRESHOLD, false, true, false, false, 2, 2));
        add(new MastercardTag(EmvTag.RELAY_RESISTANCE_TRANSMISSION_TIME_MISMATCH_THRESHOLD, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.RESPONSE_MESSAGE_TEMPLATE_1, false, true, true, false, 0, 253));
        add(new MastercardTag(EmvTag.RESPONSE_MESSAGE_TEMPLATE_2, false, true, true, false, 0, 253));
        add(new MastercardTag(EmvTag.RRP_COUNTER, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.SECURITY_CAPABILITY, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.SERVICE_CODE, false, true, true, false, 2, 2, EmvTag.RECORD_TEMPLATE,
                EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.SIGNED_DYNAMIC_APPLICATION_DATA, false, true, true, false, 0, 1000,
                EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.STATIC_DATA_AUTHENTICATION_TAG_LIST, false, true, true, false, 0, 250, EmvTag.RECORD_TEMPLATE,
                EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.TAGS_TO_READ, true, true, false, true, 0, 1000));
        add(new MastercardTag(EmvTag.TAGS_TO_WRITE_AFTER_GEN_AC, true, true, false, true, 0, 1000));
        add(new MastercardTag(EmvTag.TAGS_TO_WRITE_BEFORE_GEN_AC, true, true, false, true, 0, 1000));
        add(new MastercardTag(EmvTag.TERMINAL_ACTION_CODE_DEFAULT, false, true, false, false, 5, 5));
        add(new MastercardTag(EmvTag.TERMINAL_ACTION_CODE_DENIAL, false, true, false, false, 5, 5));
        add(new MastercardTag(EmvTag.TERMINAL_ACTION_CODE_ONLINE, false, true, false, false, 5, 5));
        add(new MastercardTag(EmvTag.TERMINAL_CAPABILITIES, false, true, false, false, 3, 3));
        add(new MastercardTag(EmvTag.TERMINAL_COUNTRY_CODE, false, true, false, false, 2, 2));
        add(new MastercardTag(EmvTag.TERMINAL_EXPECTED_TRANSMISSION_TIME_C_APDU, false, true, false, false, 2, 2));
        add(new MastercardTag(EmvTag.TERMINAL_EXPECTED_TRANSMISSION_TIME_R_APDU, false, true, false, false, 2, 2));
        add(new MastercardTag(EmvTag.TERMINAL_IDENTIFICATION, false, true, false, false, 8, 8));
        add(new MastercardTag(EmvTag.TERMINAL_RELAY_RESISTANCE_ENTROPY, false, true, false, false, 4, 4));
        add(new MastercardTag(EmvTag.TERMINAL_RISK_MANAGEMENT_DATA, false, true, false, false, 8, 8));
        add(new MastercardTag(EmvTag.TERMINAL_TYPE, false, true, false, false, 1, 1));
        add(new MastercardTag(EmvTag.TERMINAL_VERIFICATION_RESULTS, false, true, false, false, 5, 5));
        add(new MastercardTag(EmvTag.VISA_FORM_FACTOR_INDICATOR__MS_THIRD_PARTY_DATA, false, true, true, false, 5, 32,
                EmvTag.FCI_ISSUER_DISCRETIONARY_DATA, EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.TIME_OUT_VALUE, false, true, false, false, 2, 2));
        add(new MastercardTag(EmvTag.TORN_RECORD, false, true, false, false, 0, 1000));
        add(new MastercardTag(EmvTag.TRACK1_DATA, false, true, true, false, 0, 76, EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.TRACK1_DISCRETIONARY_DATA, false, true, true, false, 0, 54, EmvTag.RECORD_TEMPLATE,
                EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.TRACK2_DATA, false, true, true, false, 0, 19, EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.TRACK2_DISCRETIONARY_DATA, false, true, true, false, 0, 16, EmvTag.RECORD_TEMPLATE,
                EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.TRACK_2_EQV_DATA, false, true, true, false, 0, 19, EmvTag.RECORD_TEMPLATE,
                EmvTag.RESPONSE_MESSAGE_TEMPLATE_2));
        add(new MastercardTag(EmvTag.TRANSACTION_CATEGORY_CODE, true, true, false, true, 1, 1));
        add(new MastercardTag(EmvTag.TRANSACTION_CURRENCY_CODE, true, true, false, true, 2, 2));
        add(new MastercardTag(EmvTag.TRANSACTION_CURRENCY_EXP, true, true, false, true, 1, 1));
        add(new MastercardTag(EmvTag.TRANSACTION_DATE, true, true, false, true, 3, 3));
        add(new MastercardTag(EmvTag.TRANSACTION_TIME, true, true, false, true, 3, 3));
        add(new MastercardTag(EmvTag.TRANSACTION_TYPE, true, true, false, true, 1, 1));
        add(new MastercardTag(EmvTag.VISA_CARD_AUTHENTICATION_RELATED_DATA__MASTERCARD_UDOL, false, true, true, false, 0, 250, EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.UNPREDICTABLE_NUMBER, false, true, false, false, 4, 4));
        add(new MastercardTag(EmvTag.UNPREDICTABLE_NUMBER_NUMERIC, false, true, false, false, 4, 4));
        add(new MastercardTag(EmvTag.UNPROTECTED_DATA_ENVELOPE_1, true, true, true, true, 0, 192));
        add(new MastercardTag(EmvTag.UNPROTECTED_DATA_ENVELOPE_2, true, true, true, true, 0, 192));
        add(new MastercardTag(EmvTag.UNPROTECTED_DATA_ENVELOPE_3, true, true, true, true, 0, 192));
        add(new MastercardTag(EmvTag.UNPROTECTED_DATA_ENVELOPE_4, true, true, true, true, 0, 192));
        add(new MastercardTag(EmvTag.UNPROTECTED_DATA_ENVELOPE_5, true, true, true, true, 0, 192));
        add(new MastercardTag(EmvTag.USER_INTERFACE_REQUEST_DATA, false, true, false, false, 22, 22));

        add(new MastercardTag(EmvTag.MASTERCARD_PROPRIETARY_TEST_TAG_C1, false, true, true, true, 0, 248, EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.MASTERCARD_PROPRIETARY_TEST_TAG_C2, false, true, true, true, 0, 248, EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.MASTERCARD_PROPRIETARY_TEST_TAG_C3, false, true, true, true, 0, 248, EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.MASTERCARD_PROPRIETARY_TEST_TAG_C4, false, true, true, true, 0, 248, EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.MASTERCARD_PROPRIETARY_TEST_TAG_C5, false, true, true, true, 0, 248, EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.MASTERCARD_PROPRIETARY_TEST_TAG_C6, false, true, true, true, 0, 248, EmvTag.RECORD_TEMPLATE));
        add(new MastercardTag(EmvTag.MASTERCARD_PROPRIETARY_TEST_TAG_C7, false, true, true, true, 0, 248, EmvTag.RECORD_TEMPLATE));
    }


    public static boolean isKnown(EmvTag emvTag) {
        return tags.containsKey(emvTag);
    }


    public static Optional<MastercardTag> get(EmvTag tag) {
        return Optional.ofNullable(tags.get(tag));
    }


    private static void add(MastercardTag mt) {
        if (!tags.containsKey(mt.getEmvTag())) {
            tags.put(mt.getEmvTag(), mt);
        } else {
            throw new IllegalArgumentException();
        }
    }


    public static void checkInValidTemplate(List<Tlv> tlvs, EmvTag foundInTemplate) throws EmvException {
        for (Tlv tlv : tlvs) {
            Optional<MastercardTag> mtO = get(tlv.getTag());
            if (!(mtO.isPresent() && tlv.getTag().isPrivateClass() && !mtO.get().isRaUpdateAllowed())) {
                if (mtO.isPresent() && !isTestTag(mtO.get())) {
                    if (!checkInValidTemplate(mtO.get(), foundInTemplate)) {
                        throw new EmvException(format("Tag {} found in template {} but not allowed there", tlv.getTag().getName(),
                                foundInTemplate.getName()));
                    }
                }
            }
        }
    }


    public static boolean checkInValidTemplate(MastercardTag mt, EmvTag foundInTemplate) {
        EmvTag[] templates = mt.getTemplates();
        if (templates != null) {
            for (EmvTag template : templates) {
                if (template == foundInTemplate) {
                    return true;
                }
            }

        }

        return false;
    }


    public static boolean isTestTag(MastercardTag mastercardTag) {
        EmvTag tag = mastercardTag.getEmvTag();

        return tag == EmvTag.MASTERCARD_PROPRIETARY_TEST_TAG_C1 ||
                tag == EmvTag.MASTERCARD_PROPRIETARY_TEST_TAG_C2 ||
                tag == EmvTag.MASTERCARD_PROPRIETARY_TEST_TAG_C3 ||
                tag == EmvTag.MASTERCARD_PROPRIETARY_TEST_TAG_C4 ||
                tag == EmvTag.MASTERCARD_PROPRIETARY_TEST_TAG_C5 ||
                tag == EmvTag.MASTERCARD_PROPRIETARY_TEST_TAG_C6 ||
                tag == EmvTag.MASTERCARD_PROPRIETARY_TEST_TAG_C7;
    }


    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    public static boolean isValidSize(Tlv tlv, MastercardTag mt) {
        return tlv.getValueBytes().length >= mt.getLengthFrom() && tlv.getValueBytes().length <= mt.getLengthTo();
    }


    /**
     * @param tlvs
     * @param isStrict If true will throw EmvException if the tag is not a Mastercard card, if false will just proceed silently
     * @return
     * @throws EmvException
     */
    public static boolean checkValidSizes(List<Tlv> tlvs, boolean isStrict) throws EmvException {
        for (Tlv tlv : tlvs) {
            Optional<MastercardTag> mtO = get(tlv.getTag());
            if (mtO.isPresent()) {
                if (!isValidSize(tlv, mtO.get())) {
                    return false;
                }
            } else {
                if (isStrict) {
                    throw new EmvException(format("Tag {} not a Mastercard tag", tlv.getTag()));
                }
            }
        }

        return true;
    }


    public static boolean checkValidSizes(List<Tlv> tlvs) throws EmvException {
        return checkValidSizes(tlvs, true);
    }
}
