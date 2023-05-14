package digital.paynetics.phos.kernel.mastercard.misc;

import java.util.ArrayList;
import java.util.List;

import digital.paynetics.phos.kernel.common.emv.ui.UserInterfaceRequest;


public class MessageStoreImplMc implements MessageStoreMc {
    private List<UserInterfaceRequest> uiList = new ArrayList<>();


    @Override
    public void add(UserInterfaceRequest ui) {
        uiList.add(ui);
    }


    @Override
    public List<UserInterfaceRequest> getAll() {
        return new ArrayList<>(uiList);
    }


    @Override
    public void clear() {
        uiList.clear();
    }
}
