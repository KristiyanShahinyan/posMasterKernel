package digital.paynetics.phos.kernel.mastercard.torn;

import java.util.List;

import java8.util.Optional;


public interface TornTransactionLog {
    void reset();

    List<TornTransactionLogRecord> getLog();

    void setLog(List<TornTransactionLogRecord> log);

    void setMaxSize(int maxSize);

    Optional<TornTransactionLogRecord> add(TornTransactionLogRecord rec);

    Optional<TornTransactionLogRecord> getIfExists(byte[] panHash);

    void remove(byte[] panHash);

    List<TornTransactionLogRecord> clean(long now, int ttlSeconds);
}
