package digital.paynetics.phos.kernel.mastercard;

import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;


public final class MastercardTag {
    private final EmvTag emvTag;
    private final boolean isActUpdateAllowed;
    private final boolean isKernelUpdateAllowed;
    private final boolean isRaUpdateAllowed;
    private final boolean isDetUpdateAllowed;
    private final int lengthFrom;
    private final int lengthTo;
    private final EmvTag[] templates;


    MastercardTag(EmvTag emvTag,
                  boolean isActUpdateAllowed,
                  boolean isKernelUpdateAllowed,
                  boolean isRaUpdateAllowed,
                  boolean isDetUpdateAllowed, int lengthFrom, int lengthTo, EmvTag... templates) {

        this.emvTag = emvTag;
        this.isKernelUpdateAllowed = isKernelUpdateAllowed;
        this.isRaUpdateAllowed = isRaUpdateAllowed;
        this.isActUpdateAllowed = isActUpdateAllowed;
        this.isDetUpdateAllowed = isDetUpdateAllowed;
        this.lengthFrom = lengthFrom;
        this.lengthTo = lengthTo;
        this.templates = templates;
    }


    MastercardTag(EmvTag emvTag,
                  boolean isActUpdateAllowed,
                  boolean isKernelUpdateAllowed,
                  boolean isRaUpdateAllowed,
                  boolean isDetUpdateAllowed, int lengthFrom, int lengthTo) {

        this.emvTag = emvTag;
        this.isKernelUpdateAllowed = isKernelUpdateAllowed;
        this.isRaUpdateAllowed = isRaUpdateAllowed;
        this.isActUpdateAllowed = isActUpdateAllowed;
        this.isDetUpdateAllowed = isDetUpdateAllowed;
        this.lengthFrom = lengthFrom;
        this.lengthTo = lengthTo;
        this.templates = new EmvTag[]{};
    }

    public EmvTag getEmvTag() {
        return emvTag;
    }


    public boolean isActUpdateAllowed() {
        return isActUpdateAllowed;
    }


    public boolean isKernelUpdateAllowed() {
        return isKernelUpdateAllowed;
    }


    public boolean isRaUpdateAllowed() {
        return isRaUpdateAllowed;
    }


    public boolean isDetUpdateAllowed() {
        return isDetUpdateAllowed;
    }


    public EmvTag[] getTemplates() {
        return templates;
    }


    public int getLengthFrom() {
        return lengthFrom;
    }


    public int getLengthTo() {
        return lengthTo;
    }
}
