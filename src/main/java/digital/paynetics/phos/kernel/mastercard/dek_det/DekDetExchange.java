package digital.paynetics.phos.kernel.mastercard.dek_det;

import java.util.List;


public class DekDetExchange {
    private final byte[] dek;
    private final List<byte[]> det;


    public DekDetExchange(byte[] dek, List<byte[]> det) {
        this.dek = dek;
        this.det = det;
    }


    public byte[] getDek() {
        return dek;
    }


    public List<byte[]> getDet() {
        return det;
    }
}
