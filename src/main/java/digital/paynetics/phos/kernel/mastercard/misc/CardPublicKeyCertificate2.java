package digital.paynetics.phos.kernel.mastercard.misc;

import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import digital.paynetics.phos.kernel.common.crypto.CardPublicKeyCertificate;
import digital.paynetics.phos.kernel.common.crypto.CryptoException;
import digital.paynetics.phos.kernel.common.crypto.EmvPublicKey;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;

import static digital.paynetics.phos.kernel.common.crypto.CryptoUtils.calculateSha1;
import static digital.paynetics.phos.kernel.common.crypto.CryptoUtils.rsaDecrypt;


public class CardPublicKeyCertificate2 {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(CardPublicKeyCertificate.class);

    private final EmvPublicKey publicKey;
    private final byte certFormat;
    private final byte[] certExpirationDate;
    private final byte[] certSerialNumber;
    private final int hashAlgorithmIndicator;
    private final byte[] hash;
    private final int cardPublicKeyAlgorithmIndicator;
    private final int cardPublicKeyModLengthTotal;
    private final int cardPublicKeyExpLengthTotal;
    private final byte[] panRaw;
    private final byte[] cardPublicKeyPadding;

    private volatile boolean isPurged;


    public CardPublicKeyCertificate2(EmvPublicKey publicKey,
                                     byte certFormat,
                                     byte[] certExpirationDate,
                                     byte[] certSerialNumber,
                                     int hashAlgorithmIndicator,
                                     byte[] hash,
                                     int cardPublicKeyAlgorithmIndicator,
                                     int cardPublicKeyModLengthTotal,
                                     int cardPublicKeyExpLengthTotal,
                                     byte[] panRaw, byte[] cardPublicKeyPadding) {

        this.publicKey = publicKey;
        this.certFormat = certFormat;
        this.certExpirationDate = certExpirationDate;
        this.certSerialNumber = certSerialNumber;
        this.hashAlgorithmIndicator = hashAlgorithmIndicator;
        this.hash = hash;
        this.cardPublicKeyAlgorithmIndicator = cardPublicKeyAlgorithmIndicator;
        this.cardPublicKeyModLengthTotal = cardPublicKeyModLengthTotal;
        this.cardPublicKeyExpLengthTotal = cardPublicKeyExpLengthTotal;
        this.panRaw = panRaw;
        this.cardPublicKeyPadding = cardPublicKeyPadding;
    }


    @SuppressWarnings("ResultOfMethodCallIgnored")
    public static CardPublicKeyCertificate2 fromBytes(byte[] publicKeyCertificateData,
                                                      byte[] publicKeyRemainder,
                                                      byte[] publicKeyExponent,
                                                      EmvPublicKey parentKey) throws CryptoException {

        byte[] recovered = rsaDecrypt(publicKeyCertificateData,
                parentKey.getExponent(),
                parentKey.getModulus());

        ByteArrayInputStream bis = new ByteArrayInputStream(recovered);

        if (bis.read() != 0x6a) { //Header
            throw new CryptoException("Header != 0x6a");
        }

        byte certFormat = (byte) bis.read();

        if (certFormat != 0x04) { //Always 0x04
            throw new CryptoException("Invalid certificate format");
        }

        byte[] panRaw = new byte[10];
        byte[] certExpirationDate = new byte[2];
        byte[] certSerialNumber = new byte[3];

        int hashAlgorithmIndicator;
        int cardPublicKeyAlgorithmIndicator;


        bis.read(panRaw, 0, panRaw.length);

        bis.read(certExpirationDate, 0, certExpirationDate.length);

        bis.read(certSerialNumber, 0, certSerialNumber.length);

        hashAlgorithmIndicator = bis.read() & 0xFF;

        cardPublicKeyAlgorithmIndicator = bis.read() & 0xFF;

        if (cardPublicKeyAlgorithmIndicator != 1) {
            throw new CryptoException("ICC public key algorithm not supported");
        }


        int a = bis.read();
        int cardPublicKeyModLengthTotal = a & 0xFF;

        int cardPublicKeyExpLengthTotal = bis.read() & 0xFF;

        int modBytesLength = parentKey.getModulus().length - 42;

        int toRead;
        if (publicKeyRemainder != null) {
            toRead = cardPublicKeyModLengthTotal - publicKeyRemainder.length;
        } else {
            toRead = cardPublicKeyModLengthTotal;
        }
        byte[] modtmp = new byte[toRead];
        bis.read(modtmp, 0, toRead);
        byte[] padding = null;
        if (cardPublicKeyModLengthTotal < modBytesLength) {
            padding = new byte[modBytesLength - cardPublicKeyModLengthTotal];
            bis.read(padding, 0, padding.length);
        }


        EmvPublicKey cardPublicKey = new EmvPublicKey(publicKeyExponent, modtmp,
                publicKeyRemainder);

        byte[] hash = new byte[20];
        bis.read(hash, 0, hash.length);

        int trailer = bis.read();

        if (trailer != 0xbc) {//Trailer
            throw new CryptoException("Trailer != 0xbc");
        }

        if (bis.available() > 0) {
            throw new CryptoException("Error parsing certificate. Bytes left=" + bis.available());
        }

        return new CardPublicKeyCertificate2(cardPublicKey,
                certFormat,
                certExpirationDate,
                certSerialNumber,
                hashAlgorithmIndicator,
                hash,
                cardPublicKeyAlgorithmIndicator,
                cardPublicKeyModLengthTotal,
                cardPublicKeyExpLengthTotal,
                panRaw, padding);
    }


    public boolean isHashValid(EmvPublicKey parentKey, byte[] offlineAuthenticationData) {
        ByteArrayOutputStream hashStream = new ByteArrayOutputStream();

        //Header not included in hash
        hashStream.write(certFormat);
        hashStream.write(panRaw, 0, panRaw.length);
        hashStream.write(certExpirationDate, 0, certExpirationDate.length);
        hashStream.write(certSerialNumber, 0, certSerialNumber.length);
        hashStream.write((byte) hashAlgorithmIndicator);
        hashStream.write((byte) cardPublicKeyAlgorithmIndicator);
        hashStream.write((byte) cardPublicKeyModLengthTotal);
        hashStream.write((byte) cardPublicKeyExpLengthTotal);

        hashStream.write(publicKey.getKey(), 0, publicKey.getKey().length);
        if (cardPublicKeyPadding != null) {
            hashStream.write(cardPublicKeyPadding, 0, cardPublicKeyPadding.length);
        }
        if (publicKey.getRemainder() != null) {
            hashStream.write(publicKey.getRemainder(), 0, publicKey.getRemainder().length);
        }
        byte[] ipkExponent = publicKey.getExponent();
        hashStream.write(ipkExponent, 0, ipkExponent.length);

        if (offlineAuthenticationData != null) {
            hashStream.write(offlineAuthenticationData, 0, offlineAuthenticationData.length);
        }

        byte[] sha1Result = calculateSha1(hashStream.toByteArray());

        return Arrays.equals(sha1Result, hash);
    }


    public EmvPublicKey getPublicKey() {
        return publicKey;
    }


    public byte getCertFormat() {
        return certFormat;
    }


    public byte[] getCertExpirationDate() {
        return certExpirationDate;
    }


    public byte[] getCertSerialNumber() {
        return certSerialNumber;
    }


    public int getHashAlgorithmIndicator() {
        return hashAlgorithmIndicator;
    }


    public byte[] getHash() {
        return hash;
    }


    public int getCardPublicKeyAlgorithmIndicator() {
        return cardPublicKeyAlgorithmIndicator;
    }


    public int getCardPublicKeyModLengthTotal() {
        return cardPublicKeyModLengthTotal;
    }


    public int getCardPublicKeyExpLengthTotal() {
        return cardPublicKeyExpLengthTotal;
    }


    public byte[] getPanRaw() {
        return panRaw;
    }


    public void purge() {
        isPurged = true;
        ByteUtils.purge(panRaw);
    }


    @Override
    protected void finalize() throws Throwable {
        super.finalize();

        if (!isPurged) {
            logger.warn("CardPublicKeyCertificate not purged!");
        }
    }
}
