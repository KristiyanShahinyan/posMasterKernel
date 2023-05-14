package digital.paynetics.phos.kernel.mastercard.misc;

import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.ui.UserInterfaceRequest;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import digital.paynetics.phos.kernel.common.misc.PhosMessageFormat;

import static digital.paynetics.phos.kernel.common.misc.PhosMessageFormat.format;


public final class OutcomePresenter {
    private OutcomePresenter() {
        throw new AssertionError("Non-instantiable utility class");
    }


    public static String present(Outcome outcome) {
        String statusStr;
        switch (outcome.getType()) {
            case SELECT_NEXT:
                statusStr = " (5)";
                break;
            case TRY_AGAIN:
                statusStr = " (7)";
                break;
            case APPROVED:
                statusStr = " (1)";
                break;
            case DECLINED:
                statusStr = " (2)";
                break;
            case ONLINE_REQUEST:
                statusStr = " (3)";
                break;
            case TRY_ANOTHER_INTERFACE:
                statusStr = " (6)";
                break;
            case END_APPLICATION:
                statusStr = " (4)";
                break;
            default:
                statusStr = " (f)";
        }

        String startStr;
        switch (outcome.getStart()) {
            case B:
                startStr = " (1)";
                break;
            case C:
                startStr = " (2)";
                break;
            case D:
                startStr = " (3)";
                break;
            case NOT_APPLICABLE:
                startStr = " (f)";
                break;
            default:
                startStr = " (f)";
        }

        String cvmStr;
        switch (outcome.getCvm()) {
            case ONLINE_PIN:
                cvmStr = " (2)";
                break;
            case CONFIRMATION_CODE_VERIFIED:
                cvmStr = " (3)";
                break;
            case OBTAIN_SIGNATURE:
                cvmStr = " (1)";
                break;
            case NO_CVM:
                cvmStr = " (0)";
                break;
            case NOT_APPLICABLE:
                cvmStr = " (f)";
                break;
            default:
                cvmStr = " (f)";
        }

        String receiptPref;
        switch (outcome.getReceiptPreference()) {
            case YES:
                receiptPref = "Yes (1)";
                break;
            case DO_NOT_CARE:
                receiptPref = "Not care (ff)";
                break;
            case NOT_APPLICABLE:
                receiptPref = "N/A (0)";
                break;
            default:
                receiptPref = "N/A (0)";
        }

        return "+++ OUTCOME +++" +
                "\n    Status: " + outcome.getType() + statusStr +
                "\n    Start: " + outcome.getStart() + startStr +
                "\n    CVM: " + outcome.getCvm() + cvmStr +
                "\n    UI Request On Outcome present: " + (outcome.getUiRequestOnOutcome().isPresent() ? "yes" : "no") +
                "\n    UI Request On Restart present: " + (outcome.getUiRequestOnRestart().isPresent() ? "yes" : "no") +
                "\n    Data Record Present: " + (outcome.isDataRecordPresent() ? "yes" : "no") +
                "\n    Discretionary Data Present: " + (outcome.getDiscretionaryData() != null ? "yes" : "no") +
                "\n    Field Off Request: " + (outcome.getFieldOffRequest() > 0 ? outcome.getFieldOffRequest() +
                " (" + Integer.toHexString(outcome.getFieldOffRequest()) + ")" : "n/a (ff)") +
                "\n    Removal timeout: 0" +
                "\n    Receipt: " + receiptPref +
                "\n    Alternate Interface Preference n/a (f0)" +
                "\n    Online response data: n/a (f0)";
    }


    public static String present(UserInterfaceRequest uir) {
        String valQ = "NONE";
        if (uir.getValueQualifier().isPresent()) {
            if (uir.getValueQualifier().get() == UserInterfaceRequest.ValueQualifier.AMOUNT) {
                valQ = uir.getValueQualifier().get() + " (" + 1 + ")";
            } else {
                valQ = uir.getValueQualifier().get() + " (" + 2 + ")";
            }
        }

        int statusCode;
        switch (uir.getStatus()) {
            case NOT_READY:
                statusCode = 0;
                break;
            case IDLE:
                statusCode = 1;
                break;
            case READY_TO_READ:
                statusCode = 2;
                break;
            case PROCESSING:
                statusCode = 3;
                break;
            case CARD_READ_SUCCESSFULLY:
                statusCode = 4;
                break;
            case PROCESSING_ERROR:
                statusCode = 5;
                break;
            default:
                statusCode = -1;
        }

        MastercardMessageIdentifier mmi = MastercardMessageIdentifier.fromByte(uir.getMessage().getCode());
        if (mmi == null) {
            mmi = MastercardMessageIdentifier.NO_MESSAGE;
        }

        return PhosMessageFormat.format("*** UI Request ***" +
                        "\n    Message identifier: {} ({})" +
                        "\n    Status: {} ({})" +
                        "\n    Hold time: {}" +
                        "\n    Lang. pref: {}" +
                        "\n    Value qualifier: {}" +
                        "\n    Value: {}" +
                        "\n    Currency code: {}",
                mmi, mmi.getMessage().getCode() != -1 ? Integer.toHexString(uir.getMessage().getCode()) : "FF",
                uir.getStatus(), statusCode,
                uir.getHoldTime(),
                uir.getLanguagePreference().isPresent() ? uir.getLanguagePreference().get() : "0000000000000000",
                valQ,
                uir.getValue(),
                uir.getCurrency().isPresent() ? uir.getCurrency().get() + " (" + uir.getCurrency().get().getISOCodeNumeric() + ")" : "n/a (00 00)"
        );
    }


    public static String present(MastercardErrorIndication ei, byte[] raw) {
        String msg;
        if (ei.getMessageIdentifier() != MastercardMessageIdentifier.NOT_AVAILABLE) {
            msg = ei.getMessageIdentifier() + " (" + ei.getMessageIdentifier().getMessage().getCode() + ")";
        } else {
            msg = ei.getMessageIdentifier() + " (ff)";
        }

        switch (ei.getType()) {
            case L1:
                return format("Raw bytes: {}\nL1: {} ({})\nL2: OK\nL3: OK\nSW12 {}\nMsg On Error: {}",
                        ByteUtils.toHexString(raw, true),
                        ei.getL1(),
                        ei.getL1().getValue(),
                        ei.getSw12() != null ? ByteUtils.toHexString(ei.getSw12(), true) : "N/A",
                        msg
                );
            case L2:
                return format("Raw bytes: {}\nL1: OK\nL2: {}\nL3: OK\nSW12: {}\nMsg On Error: {}",
                        ByteUtils.toHexString(raw, true),
                        ei.getL2(),
                        ei.getSw12() != null ? ByteUtils.toHexString(ei.getSw12(), true) : "N/A",
                        msg
                );
            case L3:
                return format("Raw bytes:  {}\nL1: OK\nL2: OK\nL3: {} ({})\nSW12: {}\nMsg On Error: {}",
                        ByteUtils.toHexString(raw, true),
                        ei.getL3(),
                        ei.getL3().getValue(),
                        ei.getSw12() != null ? ByteUtils.toHexString(ei.getSw12(), true) : "N/A",
                        msg
                );
            default:
                return format("Raw bytes: {}\nL1: OK\nL2: OK\nL3: OK\nSW12: 00 00\nMessage on Error: {}",
                        ByteUtils.toHexString(raw, true), msg);
        }
    }
}
