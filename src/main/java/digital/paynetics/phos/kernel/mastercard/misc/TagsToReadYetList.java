package digital.paynetics.phos.kernel.mastercard.misc;

import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.misc.McEmvTagList;


public class TagsToReadYetList extends McEmvTagList {
    public EmvTag getNextGetDataTag() {
        EmvTag ret = null;
        for (EmvTag tag : asList()) {
            if (GetDataTags.isGetDataTag(tag)) {
                remove(tag);
                ret = tag;
                break;
            }
        }

        return ret;
    }
}
