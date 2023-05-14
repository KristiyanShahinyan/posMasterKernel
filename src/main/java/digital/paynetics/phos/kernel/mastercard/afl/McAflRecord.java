package digital.paynetics.phos.kernel.mastercard.afl;

import java.util.ArrayList;
import java.util.List;

import digital.paynetics.phos.kernel.common.emv.kernel.common.Afl;


public class McAflRecord {
    private final Afl afl;
    private final int index;


    public McAflRecord(Afl afl, int index) {
        this.afl = afl;
        this.index = index;
    }


    public static List<McAflRecord> explodeAfls(List<Afl> afls) {
        List<McAflRecord> ret = new ArrayList<>();
        for (Afl afl : afls) {
            for (int index = afl.getFirstRecord(); index <= afl.getLastRecord(); index++) {
                ret.add(new McAflRecord(afl, index));
            }
        }

        return ret;
    }


    public Afl getAfl() {
        return afl;
    }


    public int getIndex() {
        return index;
    }

}
