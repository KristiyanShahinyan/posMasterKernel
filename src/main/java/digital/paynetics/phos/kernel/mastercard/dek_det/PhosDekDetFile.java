package digital.paynetics.phos.kernel.mastercard.dek_det;

import java.util.List;


public class PhosDekDetFile {
    private final String fileName;
    private final List<DekDetExchange> items;


    public PhosDekDetFile(String fileName, List<DekDetExchange> items) {
        this.fileName = fileName;
        this.items = items;
    }


    public String getFileName() {
        return fileName;
    }


    public List<DekDetExchange> getItems() {
        return items;
    }
}
