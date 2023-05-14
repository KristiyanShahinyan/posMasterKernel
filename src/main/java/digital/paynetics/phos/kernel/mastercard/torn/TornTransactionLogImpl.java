package digital.paynetics.phos.kernel.mastercard.torn;

import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;

import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMap;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapImpl;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import java8.util.Optional;


public class TornTransactionLogImpl implements TornTransactionLog {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());

    private final boolean useLightLogging;

    private List<TornTransactionLogRecord> log = new ArrayList<>();
    private int maxSize;


    @Inject
    public TornTransactionLogImpl(@Named("use light logging") boolean useLightLogging) {
        this.useLightLogging = useLightLogging;
        log = new ArrayList<>();
    }


    @Override
    public List<TornTransactionLogRecord> getLog() {
        return log;
    }


    @Override
    public void setLog(List<TornTransactionLogRecord> log) {
        this.log = log;
    }


    @Override
    public void reset() {
        logger.debug("Resetting Torn");
        log.clear();
    }


    @Override
    public void setMaxSize(int maxSize) {
        if (maxSize < this.maxSize) {
            logger.warn("Torn maxSize < this.maxSize");
            reset();
        }

        if (maxSize < log.size()) {
            logger.warn("Torn maxSize < log.size()");
            reset();
        }

        this.maxSize = maxSize;
    }


    @Override
    public Optional<TornTransactionLogRecord> add(TornTransactionLogRecord rec) {
        TornTransactionLogRecord evicted = null;

        TlvMap map = new TlvMapImpl(rec.getTlvs());

        if (!useLightLogging) {
            logger.debug("Adding torn record. PAN hash {}, DRDOL {}", ByteUtils.toHexString(rec.getPanHash()),
                    ByteUtils.toHexString(map.get(EmvTag.DRDOL_RELATED_DATA).getValueBytes()));
        }

        if (log.size() == maxSize) {
            evicted = log.remove(0);
            map = new TlvMapImpl(evicted.getTlvs());
            if (!useLightLogging) {
                logger.debug("Evicted torn record. PAN hash {}, DRDOL {}", ByteUtils.toHexString(evicted.getPanHash()),
                        ByteUtils.toHexString(map.get(EmvTag.DRDOL_RELATED_DATA).getValueBytes()));
            }

        }
        log.add(rec);

        return Optional.ofNullable(evicted);
    }


    @Override
    public Optional<TornTransactionLogRecord> getIfExists(byte[] panHash) {
        List<TornTransactionLogRecord> logRev = new ArrayList<>(log);
        Collections.reverse(logRev);

        for (TornTransactionLogRecord rec : logRev) {
            if (Arrays.equals(rec.getPanHash(), panHash)) {
                return Optional.of(rec);
            }
        }

        return Optional.empty();
    }


    @Override
    public void remove(byte[] panHash) {
        for (int i = log.size(); i-- > 0; ) {
            TornTransactionLogRecord rec = log.get(i);
            if (Arrays.equals(rec.getPanHash(), panHash)) {
                TornTransactionLogRecord removed = log.remove(i);
                TlvMap map = new TlvMapImpl(removed.getTlvs());

                if (!useLightLogging) {
                    logger.debug("Removed torn record. PAN hash {}, DRDOL_RELATED_DATA {}", ByteUtils.toHexString(removed.getPanHash()),
                            ByteUtils.toHexString(map.get(EmvTag.DRDOL_RELATED_DATA).getValueBytes()));
                }

                break;
            }
        }

//        Iterator<TornTransactionLogRecord> it = log.listIterator();
//        while (it.hasNext()) {
//            TornTransactionLogRecord rec = it.next();
//            if (Arrays.equals(rec.getPanHash(), panHash)) {
//                it.remove();
//                break;
//            }
//        }
    }


    @Override
    public List<TornTransactionLogRecord> clean(long now, int ttlSeconds) {
        List<TornTransactionLogRecord> removed = new ArrayList<>();

        Iterator<TornTransactionLogRecord> it = log.listIterator();
        while (it.hasNext()) {
            TornTransactionLogRecord rec = it.next();
            if ((rec.getTs() + ttlSeconds * 1000) < now) {
                removed.add(rec);
                it.remove();
            }
        }

        return removed;
    }
}
