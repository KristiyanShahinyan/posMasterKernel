package digital.paynetics.phos.kernel.mastercard.ccc;

import org.slf4j.LoggerFactory;

import java.math.BigInteger;

import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapReadOnly;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import digital.paynetics.phos.kernel.common.misc.Track1Data;
import digital.paynetics.phos.kernel.common.misc.Track2Data;
import digital.paynetics.phos.kernel.mastercard.MastercardKernel;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardErrorIndication;
import digital.paynetics.phos.kernel.mastercard.misc.MastercardMagstripeFailedCounter;
import digital.paynetics.phos.kernel.mastercard.misc.SensitiveData;
import digital.paynetics.phos.kernel.mastercard.misc.TlvDb;

import static digital.paynetics.phos.kernel.mastercard.misc.MastercardMessageIdentifier.ERROR_OTHER_CARD;


public interface Ccc {
    org.slf4j.Logger logger = LoggerFactory.getLogger(Ccc.class);

    static CccResult cardDataMissing(MastercardMagstripeFailedCounter mastercardMagstripeFailedCounter, TlvMapReadOnly tlvDb) {
        try {
            logger.debug("CCCtimer (sleep): {} ms", Math.pow(2, mastercardMagstripeFailedCounter.get()) * 300);
            Thread.sleep((long) (Math.pow(2, mastercardMagstripeFailedCounter.get()) * 300));
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        // S13.42.2
        mastercardMagstripeFailedCounter.increment();


        MastercardErrorIndication ei = MastercardErrorIndication.
                createL2Error(MastercardErrorIndication.L2Error.CARD_DATA_MISSING, ERROR_OTHER_CARD);
        return CccResult.createFailResult(Outcome.createTryAnotherCardOutcome(MastercardKernel.buildDiscretionaryData(false, tlvDb, ei)));
    }


    static char[] updateTrack2DiscretionaryData(int pcvc3, int cvc3, char[] discretionaryDataCh,
                                                int punAtc, int atc, char[] random, int nUn, int nUnFinal, int t) {

        // S13.18
        char[] discretionaryDataCh2 = updateTrack2DiscretionaryDataCvc3(pcvc3, cvc3, discretionaryDataCh);
        updateTrack2DiscretionaryDataPunAtc(discretionaryDataCh2, punAtc, atc, random, nUn, t);
        char c = Integer.toString(nUnFinal).charAt(0);

        // S13.19
        discretionaryDataCh[discretionaryDataCh.length - 1] = c;

        return discretionaryDataCh;
    }


    static char[] updateTrack2DiscretionaryDataCvc3(int pcvc3, int cvc3, char[] discretionaryDataCh) {
        char[] cvc3Ch = Integer.toString(cvc3).toCharArray();

        int q = Integer.bitCount(pcvc3);

        updateDdLess(discretionaryDataCh, pcvc3, cvc3Ch, q);

        return discretionaryDataCh;
    }


    static void updateTrack2DiscretionaryDataPunAtc(char[] discretionaryDataCh, int punAtc, int atc,
                                                    char[] random, int nUn, int t) {

        BigInteger bi = BigInteger.valueOf(punAtc);
        int copied = 0;

        updateDdLess(discretionaryDataCh, punAtc, random, nUn);

        if (t > 0) {
            char[] atcCh = ByteUtils.fitCharArray(Integer.toString(atc).toCharArray(), t);
            for (int i = discretionaryDataCh.length - 1; i >= 0; i--) {
                if (bi.testBit(i)) {
                    // TODO fix index out of bounds 3G10-0152(A_03)
                    discretionaryDataCh[discretionaryDataCh.length - i - 1] = atcCh[atcCh.length - t + copied];

                    copied++;

                    if (copied == atcCh.length || t == copied) {
                        break;
                    }
                }
            }
        }
    }


    static void updateDdLess(char[] discretionaryDataCh, long positions, char[] data, int max) {
        BigInteger bi = BigInteger.valueOf(positions);
        int copied = 0;

        if (max > 0) {
            char[] tmp = ByteUtils.fitCharArray(data, max);
            for (int i = 0; i < discretionaryDataCh.length; i++) {
                if (bi.testBit(i)) {
                    discretionaryDataCh[discretionaryDataCh.length - i - 1] = tmp[tmp.length - copied - 1];
                    copied++;

                    if (copied == tmp.length || max == copied) {
                        break;
                    }
                }
            }
        }
    }


    static String updateTrack1DiscretionaryData(long pcvc3, int cvc3, String discretionaryData, long punAtc,
                                                int atc, char[] random, int nUn, int nUnFinal, int t) {
        char[] discretionaryDataCh = updateTrack1DiscretionaryDataCvc3(pcvc3, cvc3, discretionaryData);
        updateTrack1DiscretionaryDataPunAtc(discretionaryDataCh, punAtc, atc, random, nUn, t);

        char c = Integer.toString(nUnFinal).charAt(0);

        // S13.22
        discretionaryDataCh[discretionaryDataCh.length - 1] = c;
        return new String(discretionaryDataCh);
    }


    static char[] updateTrack1DiscretionaryDataCvc3(long pcvc3, int cvc3, String discretionaryDataStr) {
        char[] discretionaryDataCh = discretionaryDataStr.toCharArray();
        char[] cvc3Ch = Integer.toString(cvc3).toCharArray();

        int q = Long.bitCount(pcvc3);

        updateDdLess(discretionaryDataCh, pcvc3, cvc3Ch, q);

        return discretionaryDataCh;
    }


    static void updateTrack1DiscretionaryDataPunAtc(char[] discretionaryDataCh, long punAtc, int atc,
                                                    char[] random, int nUn, int t) {

        BigInteger bi = BigInteger.valueOf(punAtc);
        int copied = 0;
        updateDdLess(discretionaryDataCh, punAtc, random, nUn);

        if (t > 0) {
            char[] atcCh = ByteUtils.fitCharArray(Integer.toString(atc).toCharArray(), t);
            for (int i = discretionaryDataCh.length - 1; i >= 0; i--) {
                if (bi.testBit(i)) {
                    discretionaryDataCh[discretionaryDataCh.length - i - 1] = atcCh[atcCh.length - t + copied];
                    copied++;

                    if (copied == atcCh.length || t == copied) {
                        break;
                    }
                }
            }
        }
    }


    static void updateTrackData(TlvDb tlvDb, int nUn, char[] random, int nUnFinal) throws EmvException {
        int pcvc3 = tlvDb.get(EmvTag.PCVC3_TRACK2).getValueAsHexInt();
        int cvc3 = tlvDb.get(EmvTag.CVC3_TRACK2).getValueAsHexInt();
        SensitiveData t2sd = tlvDb.getTrack2().get();
        Track2Data t2d = new Track2Data(t2sd.getData());
        int atc = tlvDb.get(EmvTag.APP_TRANSACTION_COUNTER).getValueAsHexInt();
        int punAtc = tlvDb.get(EmvTag.TERMINAL_TRANSACTION_QUALIFIERS__PUNATC_TRACK2).getValueAsHexInt();
        int t = tlvDb.get(EmvTag.NATC_TRACK2).getValueAsHexInt();

        char[] updatedDiscretionaryDataTrack2 = Ccc.updateTrack2DiscretionaryData(pcvc3, cvc3, t2d.getDiscretionaryData(),
                punAtc, atc, random, nUn, nUnFinal, t);

        Track2Data t2dUpdated = new Track2Data(t2d, updatedDiscretionaryDataTrack2);
        byte[] t2bytes = t2dUpdated.toBytes();
        logger.debug("Track2 out: {}", ByteUtils.toHexString(t2bytes));

        Tlv tlvT2 = new Tlv(EmvTag.TRACK2_DATA, t2bytes.length, t2bytes);
        tlvDb.updateOrAddKernel(tlvT2);
        Track1Data t1dUpdated;
        // S13.20
        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.TRACK1_DATA)) {
            Track1Data t1d = new Track1Data(new String(tlvDb.getTrack1().get().getData()));

            long pcvc3L = tlvDb.get(EmvTag.PCVC3_TRACK1).getValueAsHexLong();
            cvc3 = tlvDb.get(EmvTag.CVC3_TRACK1).getValueAsHexInt();
            long punAtcL = tlvDb.get(EmvTag.PUNATC_TRACK1).getValueAsHexLong();
            t = tlvDb.get(EmvTag.NATC_TRACK1).getValueAsHexInt();

            String updatedDiscretionaryDataTrack1 = Ccc.updateTrack1DiscretionaryData(pcvc3L, cvc3,
                    t1d.getDiscretionaryData(), punAtcL, atc, random, nUn, nUnFinal, t);

            t1dUpdated = new Track1Data(t1d, updatedDiscretionaryDataTrack1);
            byte[] t1bytes = t1dUpdated.toBytes();
            logger.debug("Track1 out: {}", new String(t1bytes));

            Tlv tlvT1 = new Tlv(EmvTag.TRACK1_DATA, t1bytes.length, t1bytes);
            tlvDb.updateOrAddKernel(tlvT1);
        }

        t2sd.purge();
        t2d.purge();
        t2dUpdated.purge();
        ByteUtils.purge(t2bytes);
    }

}
