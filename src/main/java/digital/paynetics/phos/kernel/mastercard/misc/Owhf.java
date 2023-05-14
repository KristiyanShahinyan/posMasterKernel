package digital.paynetics.phos.kernel.mastercard.misc;

import org.slf4j.LoggerFactory;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import digital.paynetics.phos.kernel.common.misc.ByteUtils;


public class Owhf {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(Owhf.class);

    public static byte[] owhf2(byte[] dsId, byte[] oid, byte[] input) {
        logger.debug("owhf2");


        if (input == null) {
            throw new NullPointerException("input is null");
        }

        if (oid == null) {
            throw new NullPointerException("oid is null");
        }

        if (dsId == null) {
            throw new NullPointerException("dsId is null");
        }

        if (input.length != 8) {
            throw new IllegalArgumentException("invalid length of input");
        }

        if (oid.length != 8) {
            throw new IllegalArgumentException("invalid length of oid");
        }

        if (dsId.length < 8) {
            throw new IllegalArgumentException("invalid length of dsId");
        }

        logger.debug("dsId: {}", ByteUtils.toHexString(dsId));
        logger.debug("oid: {}", ByteUtils.toHexString(oid));
        logger.debug("input: {}", ByteUtils.toHexString(input));

        byte[] kl = new byte[8];
        byte[] kr = new byte[8];
        int pl = dsId.length;
        for (int i = 0; i < 6; i++) {
            int tmp1 = dsId[i] & 0xFF;
            kl[i] = (byte) (((tmp1 / 16 * 10) + (tmp1 % 16)) * 2);
            int tmp2 = dsId[pl - 6 + i] & 0xFF;
            kr[i] = (byte) ((((tmp2 / 16) * 10) + (tmp2 % 16)) * 2);
        }

        kl[6] = oid[4];
        kl[7] = oid[5];
        kr[6] = oid[6];
        kr[7] = oid[7];

        Key keyLeft = new SecretKeySpec(kl, 0, kl.length, "DES");
        Key keyRight = new SecretKeySpec(kr, 0, kr.length, "DES");

        try {
            Cipher desCipher = Cipher.getInstance("DES/ECB/NoPadding");
            desCipher.init(Cipher.ENCRYPT_MODE, keyLeft);
            byte r1[] = desCipher.doFinal(ByteUtils.byteArrayXor(oid, input));
            desCipher.init(Cipher.DECRYPT_MODE, keyRight);
            byte r2[] = desCipher.doFinal(r1);
            desCipher.init(Cipher.ENCRYPT_MODE, keyLeft);
            byte r3[] = desCipher.doFinal(r2);

            return ByteUtils.byteArrayXor(r3, input);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException |
                IllegalBlockSizeException e) {

            throw new RuntimeException(e);
        }
    }


    public static byte[] owhf2aes(byte[] dsId, byte[] oid, byte[] input) {
        logger.debug("owhf2aes");

        if (input == null) {
            throw new NullPointerException("input is null");
        }

        if (oid == null) {
            throw new NullPointerException("oid is null");
        }

        if (dsId == null) {
            throw new NullPointerException("dsId is null");
        }

        if (input.length != 8) {
            throw new IllegalArgumentException("invalid length of input");
        }

        if (oid.length != 8) {
            throw new IllegalArgumentException("invalid length of oid");
        }

        if (dsId.length < 8) {
            throw new IllegalArgumentException("invalid length of dsId");
        }

        logger.debug("dsId: {}", ByteUtils.toHexString(dsId));
        logger.debug("oid: {}", ByteUtils.toHexString(oid));
        logger.debug("input: {}", ByteUtils.toHexString(input));


        byte[] m = ByteUtils.byteArrayConcat(input, oid);
        byte[] y = ByteUtils.leftPad(dsId, 11);
        byte[] keyTmp = ByteUtils.byteArrayConcat(y, Arrays.copyOfRange(oid, 4, 8));
        byte[] key = new byte[16];
        System.arraycopy(keyTmp, 0, key, 0, 15);
        key[15] = 0x3f;

        try {
            Cipher aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
            Key keyLeft = new SecretKeySpec(key, 0, key.length, "AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, keyLeft);
            byte[] enc = aesCipher.doFinal(m);
            byte[] t = ByteUtils.byteArrayXor(enc, m);

            return Arrays.copyOfRange(t, 0, 8);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException
                | InvalidKeyException e) {

            throw new RuntimeException(e);
        }
    }
}
