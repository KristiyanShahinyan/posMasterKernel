package digital.paynetics.phos.kernel.mastercard.misc;

public interface MastercardMagstripeFailedCounter {
    void increment();

    int get();

    void reset();
}
