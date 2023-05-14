package digital.paynetics.phos.kernel.mastercard.misc;

import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapReadOnly;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import java8.util.Optional;


public interface TlvDb extends TlvMapReadOnly {
    void addAct(Tlv tlv);

    void updateOrAddAct(Tlv tlv);

    void addKernel(Tlv tlv);

    void updateOrAddKernel(Tlv tlv);

//    void addRa(@NonNull Tlv tlv) throws EmvException;

    void updateOrAddRa(Tlv tlv) throws EmvException;

    void addDet(Tlv tlv) throws EmvException;

    void updateOrAddDet(Tlv tlv);

    Optional<SensitiveData> getPan();

    Optional<SensitiveData> getTrack2();

    Optional<SensitiveData> getTrack2Eqv();

    Optional<SensitiveData> getTrack1();

    void remove(EmvTag tag);

    TlvMapReadOnly asUnencrypted();
}
