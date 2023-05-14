package digital.paynetics.phos.kernel.mastercard.misc;


import java.security.SecureRandom;
import java.util.Random;

import digital.paynetics.phos.kernel.common.crypto.EncDec;
import digital.paynetics.phos.kernel.common.crypto.EncryptedItem;


/**
 * This is simpler and faster implementation in order to speed up the entire transqaction because using AES is too slow
 */
public class FastEncDec implements EncDec {
    private Random random = new SecureRandom();
    public FastEncDec() {

    }




    @Override
    public EncryptedItem encrypt(byte[] bytes) {
        byte[] xorKey = new byte[bytes.length + random.nextInt(20)];

        if (bytes.length > xorKey.length) {
            throw new RuntimeException("bytes.length > xorKey.length");
        }

        byte[] encrypted = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            encrypted[i] = (byte) (xorKey[i] ^ bytes[i]);
        }

        return new EncryptedItem(encrypted, xorKey);
    }


    @Override
    public byte[] decrypt(EncryptedItem encryptedItem) {
        byte[] encrypted = encryptedItem.getData();
        byte[] decrypted = new byte[encryptedItem.getData().length];
        for (int i = 0; i < encrypted.length; i++) {
            decrypted[i] = (byte) (encryptedItem.getIv()[i] ^ encrypted[i]);
        }

        return decrypted;
    }
}
