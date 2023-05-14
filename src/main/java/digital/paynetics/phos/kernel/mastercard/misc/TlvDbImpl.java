package digital.paynetics.phos.kernel.mastercard.misc;

import org.slf4j.LoggerFactory;

import java.util.List;

import digital.paynetics.phos.kernel.common.crypto.EncDec;
import digital.paynetics.phos.kernel.common.crypto.EncryptedItem;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMap;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapImpl;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapReadOnly;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import digital.paynetics.phos.kernel.mastercard.MastercardTag;
import digital.paynetics.phos.kernel.mastercard.MastercardTags;
import java8.util.Optional;

import static digital.paynetics.phos.kernel.common.misc.PhosMessageFormat.format;


public class TlvDbImpl implements TlvDb {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());
    private TlvMap map = new TlvMapImpl();

    private final EncDec encDec;

    private EncryptedItem track2enc;
    private EncryptedItem track2eqvEnc;
    private EncryptedItem track1enc;
    private EncryptedItem pan;


    public TlvDbImpl(EncDec encDec) {
        this.encDec = encDec;
    }


    @Override
    public Tlv get(EmvTag tag) {
        return map.get(tag);
    }


    @Override
    public Optional<Tlv> getAsOptional(EmvTag tag) {
        return map.getAsOptional(tag);
    }


    @Override
    public boolean isTagPresentAndNonEmpty(EmvTag tag) {
        return map.isTagPresentAndNonEmpty(tag);
    }


    @Override
    public boolean isTagPresent(EmvTag tag) {
        return map.isTagPresent(tag);
    }


    @Override
    public List<Tlv> asList() {
        return map.asList();
    }


    @Override
    public void addAct(Tlv tlv) {
        Optional<MastercardTag> mtO = MastercardTags.get(tlv.getTag());
        if (mtO.isPresent()) {
            if (mtO.get().isActUpdateAllowed()) {
                addSecure(tlv);
            } else {
                logger.warn("addAct called with tag {} {} but ACT update is not allowed",
                        ByteUtils.toHexString(tlv.getTag().getTagBytes()), tlv.getTag().name());
            }
        } else {
            if (map.isTagPresentAndNonEmpty(tlv.getTag())) {
                map.update(tlv);
            }
        }
    }


    @Override
    public void updateOrAddAct(Tlv tlv) {
        Optional<MastercardTag> mtO = MastercardTags.get(tlv.getTag());
        if (mtO.isPresent()) {
            if (mtO.get().isActUpdateAllowed()) {
                addSecure(tlv);
            } else {
                logger.warn("updateOrAddAct called with tag {} {} but ACT update is not allowed",
                        ByteUtils.toHexString(tlv.getTag().getTagBytes()), tlv.getTag().name());
            }
        } else {
            if (map.isTagPresentAndNonEmpty(tlv.getTag())) {
                map.update(tlv);
            }
        }
    }


    @Override
    public void addKernel(Tlv tlv) {
        Optional<MastercardTag> mtO = MastercardTags.get(tlv.getTag());
        if (mtO.isPresent()) {
            if (mtO.get().isKernelUpdateAllowed()) {
                addSecure(tlv);
            } else {
                logger.warn("addKernel called with tag {} {} but Kernel update is not allowed",
                        ByteUtils.toHexString(tlv.getTag().getTagBytes()), tlv.getTag().name());
            }
        } else {
            addSecure(tlv);
        }
    }


    @Override
    public void updateOrAddKernel(Tlv tlv) {
        Optional<MastercardTag> mtO = MastercardTags.get(tlv.getTag());
        if (mtO.isPresent()) {
            if (mtO.get().isKernelUpdateAllowed()) {
                updateOrAddSecure(tlv);
            } else {
                logger.warn("updateOrAddKernel called with tag {} {} but Kernel update is not allowed",
                        ByteUtils.toHexString(tlv.getTag().getTagBytes()), tlv.getTag().name());
            }
        } else {
            updateOrAddSecure(tlv);
        }
    }


    /**
     * This method is essentially parseAndStoreCardResponse()
     * Checking for the correct template is missing though - it have to be done outside with MastercardTags.checkInValidTemplate()
     *
     * @param tlv
     * @throws EmvException
     */
    @Override
    public void updateOrAddRa(Tlv tlv) throws EmvException {
        Optional<MastercardTag> mtO = MastercardTags.get(tlv.getTag());
        if (!(mtO.isPresent() && mtO.get().getEmvTag().isPrivateClass() && !mtO.get().isRaUpdateAllowed())) {
            if (mtO.isPresent()) { // is known
                if (map.isTagPresent(tlv.getTag())) {
                    Tlv tlvExisting = map.get(tlv.getTag());
                    if (tlvExisting.getValueBytes().length != 0) {
                        throw new EmvException(format("updateOrAddRa called with tag {} {} which is known but non-empty",
                                ByteUtils.toHexString(tlv.getTag().getTagBytes()), tlv.getTag().name()));
                    }
                }

                MastercardTag mt = mtO.get();
                if (mt.isRaUpdateAllowed()) {
                    if (!MastercardTags.isValidSize(tlv, mt)) {
                        throw new EmvException(format("Invalid length for TLV with tag {}, actual length: {}", mt.getEmvTag().getName(),
                                tlv.getValueBytes().length));
                    }
                    updateOrAddSecure(tlv);
                } else {
                    throw new EmvException(format("updateOrAddRa called with tag {} {} but RA update is not allowed",
                            ByteUtils.toHexString(tlv.getTag().getTagBytes()), tlv.getTag().name()));

                }
            } else {
                if (map.isTagPresent(tlv.getTag())) {
                    Tlv tlvExisting = map.get(tlv.getTag());
                    if (tlvExisting.getValueBytes().length == 0) {
                        updateOrAddSecure(tlv);
                    } else {
                        throw new EmvException(format("updateOrAddRa called with tag {} {} but the tag " +
                                        "is not known and already have value",
                                ByteUtils.toHexString(tlv.getTag().getTagBytes()), tlv.getTag().name()));
                    }
                }
            }
        }
    }


    @Override
    public void addDet(Tlv tlv) throws EmvException {
        Optional<MastercardTag> mtO = MastercardTags.get(tlv.getTag());
        if (mtO.isPresent()) {
            MastercardTag mt = mtO.get();
            if (mt.isDetUpdateAllowed()) {
                if (!MastercardTags.isValidSize(tlv, mt)) {
                    throw new EmvException(format("Invalid length for TLV with tag {}, actual length: {}", mt.getEmvTag().getName(),
                            tlv.getValueBytes().length));
                }
                addSecure(tlv);
            } else {
                logger.warn("addDet called with tag {} {} but DET update is not allowed",
                        ByteUtils.toHexString(tlv.getTag().getTagBytes()), tlv.getTag().name());
            }
        } else {
            if (map.isTagPresentAndNonEmpty(tlv.getTag())) {
                map.update(tlv);
            }
        }
    }


    @Override
    public void updateOrAddDet(Tlv tlv) {
        Optional<MastercardTag> mtO = MastercardTags.get(tlv.getTag());
        if (mtO.isPresent()) {
            if (mtO.get().isDetUpdateAllowed()) {
                updateOrAddSecure(tlv);
            } else {
                logger.warn("updateOrAddDet called with tag {} {} but DET update is not allowed",
                        ByteUtils.toHexString(tlv.getTag().getTagBytes()), tlv.getTag().name());
            }
        } else {
            if (map.isTagPresentAndNonEmpty(tlv.getTag())) {
                map.update(tlv);
            }
        }
    }


    @Override
    public Optional<SensitiveData> getPan() {
        if (pan != null) {
            return Optional.of(new SensitiveData(encDec.decrypt(pan)));
        } else {
            return Optional.empty();
        }
    }


    @Override
    public Optional<SensitiveData> getTrack2() {
        if (track2enc != null) {
            return Optional.of(new SensitiveData(encDec.decrypt(track2enc)));
        } else {
            return Optional.empty();
        }
    }


    @Override
    public Optional<SensitiveData> getTrack2Eqv() {
        if (track2eqvEnc != null) {
            return Optional.of(new SensitiveData(encDec.decrypt(track2eqvEnc)));
        } else {
            return Optional.empty();
        }
    }


    @Override
    public Optional<SensitiveData> getTrack1() {
        if (track1enc != null) {
            return Optional.of(new SensitiveData(encDec.decrypt(track1enc)));
        } else {
            return Optional.empty();
        }
    }


    @Override
    public void remove(EmvTag tag) {
        map.remove(tag);
    }


    @Override
    public TlvMapReadOnly asUnencrypted() {
        if (pan != null) {
            byte[] data = encDec.decrypt(pan);
            map.updateOrAdd(new Tlv(EmvTag.PAN, data.length, data));
        }


        if (track1enc != null) {
            byte[] data = encDec.decrypt(track1enc);
            map.updateOrAdd(new Tlv(EmvTag.TRACK1_DATA, data.length, data));
        }

        if (track2enc != null) {
            byte[] data = encDec.decrypt(track2enc);
            map.updateOrAdd(new Tlv(EmvTag.TRACK2_DATA, data.length, data));
        }

        if (track2eqvEnc != null) {
            byte[] data = encDec.decrypt(track2eqvEnc);
            map.updateOrAdd(new Tlv(EmvTag.TRACK_2_EQV_DATA, data.length, data));
        }

        return map;
    }


    private void addSecure(Tlv tlv) {
        switch (tlv.getTag()) {
            case TRACK1_DATA:
                logger.debug("Track1 data add: {}", tlv.getValueAsHex());
                track1enc = encDec.encrypt(tlv.getValueBytes());
                map.add(new Tlv(EmvTag.TRACK1_DATA, 1, new byte[1]));
                break;
            case TRACK2_DATA:
                logger.debug("Track2 data add: {}", tlv.getValueAsHex());
                track2enc = encDec.encrypt(tlv.getValueBytes());
                map.add(new Tlv(EmvTag.TRACK2_DATA, 1, new byte[1]));
                break;
            case TRACK_2_EQV_DATA:
                track2eqvEnc = encDec.encrypt(tlv.getValueBytes());
                map.add(new Tlv(EmvTag.TRACK_2_EQV_DATA, 1, new byte[1]));
                break;
            case PAN:
                pan = encDec.encrypt(tlv.getValueBytes());
                map.add(new Tlv(EmvTag.PAN, 1, new byte[1]));
                break;
            default:
                map.add(tlv);
        }
    }


    private void updateOrAddSecure(Tlv tlv) {
        switch (tlv.getTag()) {
            case TRACK1_DATA:
                if (tlv.getValueBytes().length > 0) {
                    logger.debug("Track1 data update: {}", new String(tlv.getValueBytes()));
                    track1enc = encDec.encrypt(tlv.getValueBytes());
                    map.updateOrAdd(new Tlv(EmvTag.TRACK1_DATA, 1, new byte[1]));
                } else {
                    map.updateOrAdd(new Tlv(EmvTag.TRACK1_DATA, 0, new byte[0]));
                }
                break;
            case TRACK2_DATA:
                if (tlv.getValueBytes().length > 0) {
                    logger.debug("Track2 data update: {}", tlv.getValueAsHex());
                    track2enc = encDec.encrypt(tlv.getValueBytes());
                    map.updateOrAdd(new Tlv(EmvTag.TRACK2_DATA, 1, new byte[1]));
                } else {
                    map.updateOrAdd(new Tlv(EmvTag.TRACK1_DATA, 0, new byte[0]));
                }
                break;
            case TRACK_2_EQV_DATA:
                if (tlv.getValueBytes().length > 0) {
                    track2eqvEnc = encDec.encrypt(tlv.getValueBytes());
                    map.updateOrAdd(new Tlv(EmvTag.TRACK_2_EQV_DATA, 1, new byte[1]));
                } else {
                    map.updateOrAdd(new Tlv(EmvTag.TRACK1_DATA, 0, new byte[0]));
                }

                break;
            case PAN:
                if (tlv.getValueBytes().length > 0) {
                    pan = encDec.encrypt(tlv.getValueBytes());
                    map.updateOrAdd(new Tlv(EmvTag.PAN, 1, new byte[1]));
                } else {
                    map.updateOrAdd(new Tlv(EmvTag.TRACK1_DATA, 0, new byte[0]));
                }
                break;
            default:
                map.updateOrAdd(tlv);
        }
    }
}
