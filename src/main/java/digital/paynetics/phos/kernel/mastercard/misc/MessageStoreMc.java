package digital.paynetics.phos.kernel.mastercard.misc;

import java.util.List;

import digital.paynetics.phos.kernel.common.emv.ui.UserInterfaceRequest;


public interface MessageStoreMc {
    void add(UserInterfaceRequest ui);

    List<UserInterfaceRequest> getAll();

    void clear();
}
