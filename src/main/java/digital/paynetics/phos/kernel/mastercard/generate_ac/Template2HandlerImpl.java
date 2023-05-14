package digital.paynetics.phos.kernel.mastercard.generate_ac;

import org.slf4j.LoggerFactory;

import java.util.List;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;
import digital.paynetics.phos.kernel.common.emv.tag.TlvUtils;


public class Template2HandlerImpl implements Template2Handler {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());


    @Inject
    public Template2HandlerImpl() {
    }


    @Override
    public List<Tlv> handle(byte[] data) throws TlvException {
        logger.debug("RESPONSE_MESSAGE_TEMPLATE_2");

        List<Tlv> list = TlvUtils.getChildTlvs(data, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2);
        if (list.size() != 0) {
            logger.debug("Parsing OK");
        }

        return list;
    }
}
