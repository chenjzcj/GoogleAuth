package com.felix.googleauth.googleauth;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.SecureRandom;

/**
 * Created by Felix.Zhong on 2018/10/31 14:13
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
     * 随机生成一个密钥(小写)
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
     * 随机生成一个密钥(大写)
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
     * 根据密钥获取验证码
     * 返回字符串是因为验证码有可能以 0 开头
     *
     * @param secretKey 密钥
     * @param time      第几个 30 秒 System.currentTimeMillis() / 1000 / 30
     */
    public static String getTOTP(String secretKey, long time) {
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(secretKey.toUpperCase());
        String hexKey = Hex.encodeHexString(bytes);
        String hexTime = Long.toHexString(time);
        return TOTP.generateTOTP(hexKey, hexTime, "6");
    }

    /**
     * 根据密钥获取验证码
     * 返回字符串是因为验证码有可能以 0 开头
     *
     * @param secretKey 密钥
     * @param time      第几个 30 秒 System.currentTimeMillis() / 1000 / 30
     */
    public static String getTOTPForAndroid(String secretKey, long time) {
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(secretKey.toUpperCase());
        //String hexKey = Hex.encodeHexString(bytes);//不适用于安卓设备，会报异常【No static method encodeHexString([B)Ljava/lang/String; in class Lorg/apache/commons/codec/binary/Hex;】
        String hexKey = new String(Hex.encodeHex(bytes));
        String hexTime = Long.toHexString(time);
        return TOTP.generateTOTP(hexKey, hexTime, "6");
    }


    /**
     * 生成 Google Authenticator 二维码所需信息
     * Google Authenticator 约定的二维码信息格式 : otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}
     * 参数需要 url 编码 + 号需要替换成 %20
     *
     * @param secret  密钥 使用 createSecretKey 方法生成
     * @param account 用户账户 如: example@domain.com 138XXXXXXXX
     * @param issuer  服务名称 如: Google Github 印象笔记
     */
    public static String createGoogleAuthQRCodeData(String secret, String account, String issuer) {
        String qrCodeData = "otpauth://totp/%s?secret=%s&issuer=%s";
        try {
            return String.format(qrCodeData, URLEncoder.encode(issuer + ":" + account, "UTF-8").replace("+", "%20"), URLEncoder.encode(secret, "UTF-8")
                    .replace("+", "%20"), URLEncoder.encode(issuer, "UTF-8").replace("+", "%20"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return "";
    }


    /**
     * 时间前后偏移量
     */
    private static final int timeExcursion = 3;

    /**
     * 校验方法
     *
     * @param secretKey 密钥
     * @param code      用户输入的 TOTP 验证码
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
     * @param code      用户输入的 TOTP 验证码
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
     * 校验方法(无偏移)
     *
     * @param secretKey 密钥
     * @param code      用户输入的 TOTP 验证码
     */
    public static boolean verifyNoExcursion(String secretKey, String code) {
        long time = System.currentTimeMillis() / 1000 / 30;
        String totp = getTOTP(secretKey, time);
        return code.equals(totp);
    }

    /**
     * 校验方法(无偏移)
     *
     * @param secretKey 密钥
     * @param code      用户输入的 TOTP 验证码
     */
    public static boolean verifyNoExcursionForAndroid(String secretKey, String code) {
        long time = System.currentTimeMillis() / 1000 / 30;
        String totp = getTOTPForAndroid(secretKey, time);
        return code.equals(totp);
    }
}
