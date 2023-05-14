package digital.paynetics.phos.kernel.mastercard.misc;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;


public class GetDataTags {
    private static final Set<EmvTag> tags = new HashSet<>();

    static {
        tags.add(EmvTag.OFFLINE_ACCUMULATOR_BALANCE);
        tags.add(EmvTag.PROTECTED_DATA_ENVELOPE_1);
        tags.add(EmvTag.PROTECTED_DATA_ENVELOPE_2);
        tags.add(EmvTag.PROTECTED_DATA_ENVELOPE_3);
        tags.add(EmvTag.PROTECTED_DATA_ENVELOPE_4);
        tags.add(EmvTag.PROTECTED_DATA_ENVELOPE_5);
        tags.add(EmvTag.UNPROTECTED_DATA_ENVELOPE_1);
        tags.add(EmvTag.UNPROTECTED_DATA_ENVELOPE_2);
        tags.add(EmvTag.UNPROTECTED_DATA_ENVELOPE_3);
        tags.add(EmvTag.UNPROTECTED_DATA_ENVELOPE_4);
        tags.add(EmvTag.UNPROTECTED_DATA_ENVELOPE_5);
    }


    public static boolean containsGetDataTags(List<EmvTag> list) {
        for (EmvTag tag : list) {
            if (tags.contains(tag)) {
                return true;
            }
        }

        return false;
    }


    public static boolean isGetDataTag(EmvTag tag) {
        return tags.contains(tag);
    }
}
