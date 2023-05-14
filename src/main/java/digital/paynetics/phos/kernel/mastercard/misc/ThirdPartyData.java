package digital.paynetics.phos.kernel.mastercard.misc;

import java.util.Arrays;

import digital.paynetics.phos.kernel.common.misc.ByteUtils;


public class ThirdPartyData {
    private final String countryCode;
    private final byte[] uniqueIdentifier;
    private final String deviceType;
    private final byte[] proprietaryData;


    public ThirdPartyData(String countryCode, byte[] uniqueIdentifier, String deviceType, byte[] proprietaryData) {
        this.countryCode = countryCode;
        this.uniqueIdentifier = uniqueIdentifier;
        this.deviceType = deviceType;
        this.proprietaryData = proprietaryData;
    }


    public static ThirdPartyData fromBytes(byte[] data) {
        if (data == null) {
            throw new NullPointerException("data is null");
        }

        if (data.length < 5) {
            throw new IllegalArgumentException("Data length is < 5: " + data.length);
        }

        byte[] cc = Arrays.copyOfRange(data, 0, 2);
        String countryCode = ByteUtils.bcdToString(cc);

        byte[] uniqueId = Arrays.copyOfRange(data, 2, 4);
        int ppStart;
        String deviceType = null;
        if ((uniqueId[0] & 0b10000000) == 0b00000000) {
            ppStart = 6;
            deviceType = ByteUtils.toHexString(Arrays.copyOfRange(data, 4, 6));
        } else {
            ppStart = 4;
        }
        byte[] proprietaryData = Arrays.copyOfRange(data, ppStart, data.length);

        return new ThirdPartyData(countryCode, uniqueId, deviceType, proprietaryData);
    }


    public String getCountryCode() {
        return countryCode;
    }


    public byte[] getUniqueIdentifier() {
        return uniqueIdentifier;
    }


    public String getDeviceType() {
        return deviceType;
    }


    public byte[] getProprietaryData() {
        return proprietaryData;
    }
}
