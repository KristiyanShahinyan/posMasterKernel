package digital.paynetics.phos.kernel.mastercard.generate_ac;

import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;


public class Template1HandlerImpl implements Template1Handler {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());


    @Inject
    public Template1HandlerImpl() {
    }


    @Override
    public List<Tlv> handle(byte[] data) throws EmvException {
        logger.debug("RESPONSE_MESSAGE_TEMPLATE_1 ({})",
                ByteUtils.toHexString(EmvTag.RESPONSE_MESSAGE_TEMPLATE_1.getTagBytes()));

        List<Tlv> ret = new ArrayList<>();
        int length = data.length;
        if (length >= 11 && length <= 43) {
            // skipping IsNotEmpty(TagOf(* we don't keep traditional TLV Database or have any such info as
            // described here

            try (ByteArrayInputStream is = new ByteArrayInputStream(data)) {
                byte[] cid = {(byte) is.read()};
                Tlv cryptogramInformationData = new Tlv(EmvTag.CRYPTOGRAM_INFORMATION_DATA,
                        1,
                        cid);
                ret.add(cryptogramInformationData);

                byte[] atc = new byte[2];
                //noinspection ResultOfMethodCallIgnored - it will succeed because we checked length above
                is.read(atc, 0, 2);
                Tlv applicationTransactionCounter = new Tlv(EmvTag.APP_TRANSACTION_COUNTER, 2, atc);
                ret.add(applicationTransactionCounter);

                byte[] ac = new byte[8];
                //noinspection ResultOfMethodCallIgnored
                is.read(ac, 0, 8);
                Tlv applicationCryptoGram = new Tlv(EmvTag.APP_CRYPTOGRAM, 8, ac);
                ret.add(applicationCryptoGram);

                if (length > 11) {
                    byte[] iad = new byte[length - 11];
                    //noinspection ResultOfMethodCallIgnored
                    is.read(iad, 0, length - 11);
                    Tlv issuerApplicationData = new Tlv(EmvTag.ISSUER_APPLICATION_DATA, length - 11, iad);
                    ret.add(issuerApplicationData);
                }
            } catch (IOException e) {
                throw new AssertionError("Cannot happen");
            }
        } else {
            throw new EmvException("Invalid data length (S9.18): " + length);
        }

        return ret;
    }
}
