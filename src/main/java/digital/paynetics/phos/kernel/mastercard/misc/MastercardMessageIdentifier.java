package digital.paynetics.phos.kernel.mastercard.misc;


import digital.paynetics.phos.kernel.common.emv.ui.StandardMessages;


public enum MastercardMessageIdentifier {
    CARD_READ_OK(StandardMessages.CARD_READ_OK_REMOVE_CARD),
    TRY_AGAIN(StandardMessages.PRESENT_CARD_AGAIN),
    APPROVED(StandardMessages.APPROVED),
    APPROVED_SIGN(StandardMessages.APPROVED_SIGN),
    DECLINED(StandardMessages.NOT_AUTHORIZED),
    ERROR_OTHER_CARD(StandardMessages.TRY_ANOTHER_CARD),
    INSERT_CARD(StandardMessages.INSERT_CARD),
    SEE_PHONE(StandardMessages.SEE_PHONE_FOR_INSTRUCTIONS),
    AUTHORIZING_PLEASE_WAIT(StandardMessages.AUTHORIZING),
    CLEAR_DISPLAY(StandardMessages.CLEAR_DISPLAY),
    NO_MESSAGE(StandardMessages.NO_MESSAGE),
    NOT_AVAILABLE(StandardMessages.NO_MESSAGE);

    private final StandardMessages msg;


    MastercardMessageIdentifier(StandardMessages msg) {
        this.msg = msg;
    }


    public StandardMessages getMessage() {
        return msg;
    }


    public static MastercardMessageIdentifier fromByte(byte b) {
        if (b == CARD_READ_OK.msg.getCode()) {
            return CARD_READ_OK;
        } else if (b == TRY_AGAIN.msg.getCode()) {
            return TRY_AGAIN;
        } else if (b == APPROVED.msg.getCode()) {
            return APPROVED;
        } else if (b == APPROVED_SIGN.msg.getCode()) {
            return APPROVED_SIGN;
        } else if (b == DECLINED.msg.getCode()) {
            return DECLINED;
        } else if (b == ERROR_OTHER_CARD.msg.getCode()) {
            return ERROR_OTHER_CARD;
        } else if (b == INSERT_CARD.msg.getCode()) {
            return INSERT_CARD;
        } else if (b == SEE_PHONE.msg.getCode()) {
            return SEE_PHONE;
        } else if (b == AUTHORIZING_PLEASE_WAIT.msg.getCode()) {
            return AUTHORIZING_PLEASE_WAIT;
        } else if (b == CLEAR_DISPLAY.msg.getCode()) {
            return CLEAR_DISPLAY;
        } else {
            return NOT_AVAILABLE;
        }
    }

}
