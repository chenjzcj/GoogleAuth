package com.felix.googleauthlibrary;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.SecureRandom;

/**
 * Created by Felix.Zhong on 2018/10/31 14:13
 * https://www.jianshu.com/p/de903c074d77
 */
public class GoogleAuthHelper {

    public static String secretKeyDefalut = "QXKIWLCEOWNNCIYHK2VGKYV73FERXSF3";

    public static void main(String[] args) {
        String secretKey = createSecretKey();
        secretKey = secretKeyDefalut;
        //1970-01-01 00:00:00 以来的毫秒数除以 30
        long time = System.currentTimeMillis() / 1000 / 30;
        String totp = getTOTP(secretKey, time);

        System.out.println("secretKey = " + secretKey + ",time = " + time + ",totp = " + totp);

        //验证
        boolean verify = verify(secretKey, "345018");
        boolean verifyNoExcursion = verifyNoExcursion(secretKey, "345018");

        System.out.println("secretKey = " + secretKey + ",time = " + time + ",totp = " + totp + ",verify = " + verify + ",verifyNoExcursion = " + verifyNoExcursion);
    }

    /**
     * Randomly generate a key (lowercase).
     *
     * @return String
     */
    public static String createSecretKey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);
        Base32 base32 = new Base32();
        String secretKey = base32.encodeToString(bytes);
        return secretKey.toLowerCase();
    }

    /**
     * Randomly generate a key (uppercase).
     *
     * @return String
     */
    public static String createSecretKeyUpperCase() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);
        Base32 base32 = new Base32();
        String secretKey = base32.encodeToString(bytes);
        return secretKey.toUpperCase();
    }


    /**
     * Obtaining verification code based on key
     * 返The return string is because the verification code is likely to start at 0.
     *
     * @param secretKey 密钥
     * @param time      The first few 30 seconds System.currentTimeMillis() / 1000 / 30
     * @return String
     */
    public static String getTOTP(String secretKey, long time) {
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(secretKey.toUpperCase());
        String hexKey = Hex.encodeHexString(bytes);
        String hexTime = Long.toHexString(time);
        return TOTP.generateTOTP(hexKey, hexTime, "6");
    }

    /**
     * Obtaining verification code based on key
     * The return string is because the verification code is likely to start at 0.
     *
     * @param secretKey 密钥
     * @param time      The first few 30 seconds System.currentTimeMillis() / 1000 / 30
     * @return String
     */
    public static String getTOTPForAndroid(String secretKey, long time) {
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(secretKey.toUpperCase());
        //The following method calls are not applicable to Android devices, and will report exceptions[No static method encodeHexString([B)Ljava/lang/String; in class Lorg/apache/commons/codec/binary/Hex;]
        //解决方案：https://blog.csdn.net/diandianxiyu_geek/article/details/79153703
        //String hexKey = Hex.encodeHexString(bytes); for Android device below method
        String hexKey = new String(Hex.encodeHex(bytes));
        String hexTime = Long.toHexString(time);
        return TOTP.generateTOTP(hexKey, hexTime, "6");
    }


    /**
     * Information needed to generate Google Authenticator two-dimensional code
     * Google Authenticator The agreed two-dimensional code
     * Parameters need URL code + number need to be replaced by%20.
     *
     * @param secret  密钥 使用 createSecretKey 方法生成
     * @param account User accounts such as:example@domain.com or 138XXXXXXXX
     * @param issuer  Service names: such as Google Github impression notes
     * @return String
     */
    public static String createGoogleAuthQRCodeData(String secret, String account, String issuer) {
        String qrCodeData = "otpauth://totp/%s?secret=%s&issuer=%s";
        try {
            account = URLEncoder.encode(issuer + ":" + account, "UTF-8").replace("+", "%20");
            secret = URLEncoder.encode(secret, "UTF-8").replace("+", "%20");
            issuer = URLEncoder.encode(issuer, "UTF-8").replace("+", "%20");
            //format: otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer};
            return String.format(qrCodeData, account, secret, issuer);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return "";
    }

    /**
     * Create GoogleAuth QRCode String
     *
     * @param secret  密钥 使用 createSecretKey 方法生成
     * @param account User accounts such as:example@domain.com or 138XXXXXXXX
     * @param issuer  Service names: such as Google Github impression notes
     * @return GoogleAuth QRCode Str
     */
    public static String createGoogleAuthQRCodeStr(String secret, String account, String issuer) {
        String qrCodeData = "otpauth://totp/%s?secret=%s&issuer=%s";
        //Format: Example: otpauth://totp/15013226240?secret=6QUZJQ5A3AW5J2VU&issuer=Huobi or otpauth://totp/11051500@qq.com?secret=6QUZJQ5A3AW5J2VU&issuer=TOKOK
        return String.format(qrCodeData, account, secret, issuer);
    }


    /**
     * Time offset
     */
    private static final int timeExcursion = 3;

    /**
     * 校验方法
     *
     * @param secretKey 密钥
     * @param code      User input TOTP verification code
     * @return boolean
     */
    public static boolean verify(String secretKey, String code) {
        long time = System.currentTimeMillis() / 1000 / 30;
        for (int i = -timeExcursion; i <= timeExcursion; i++) {
            String totp = getTOTP(secretKey, time + i);
            if (code.equals(totp)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 校验方法
     *
     * @param secretKey 密钥
     * @param code      User input TOTP verification code
     * @return boolean
     */
    public static boolean verifyForAndroid(String secretKey, String code) {
        long time = System.currentTimeMillis() / 1000 / 30;
        for (int i = -timeExcursion; i <= timeExcursion; i++) {
            String totp = getTOTPForAndroid(secretKey, time + i);
            if (code.equals(totp)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Calibration method (no offset)
     *
     * @param secretKey 密钥
     * @param code      User input TOTP verification code
     * @return boolean
     */
    public static boolean verifyNoExcursion(String secretKey, String code) {
        long time = System.currentTimeMillis() / 1000 / 30;
        String totp = getTOTP(secretKey, time);
        return code.equals(totp);
    }

    /**
     * Calibration method (no offset)
     *
     * @param secretKey 密钥
     * @param code      User input TOTP verification code
     * @return boolean
     */
    public static boolean verifyNoExcursionForAndroid(String secretKey, String code) {
        long time = System.currentTimeMillis() / 1000 / 30;
        String totp = getTOTPForAndroid(secretKey, time);
        return code.equals(totp);
    }
}
