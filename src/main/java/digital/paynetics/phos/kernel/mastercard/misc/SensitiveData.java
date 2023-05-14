package digital.paynetics.phos.kernel.mastercard.misc;

import org.slf4j.LoggerFactory;

import java.util.Arrays;

import digital.paynetics.phos.kernel.common.misc.ByteUtils;


public final class SensitiveData {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());

    private final byte[] data;
    private volatile boolean isPurged = false;


    public SensitiveData(byte[] data) {
        this.data = data;
    }


    public void purge() {
        isPurged = true;
        Arrays.fill(data, (byte) 0);
    }


    public byte[] getData() {
        return data.clone();
    }


    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        if (!isPurged) {
            logger.warn("SensitiveData data not purged: {}", ByteUtils.toHexString(data));
        }
    }
}
