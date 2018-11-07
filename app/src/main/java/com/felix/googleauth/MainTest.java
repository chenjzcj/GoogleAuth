package com.felix.googleauth;

import com.felix.googleauthlibrary.GoogleAuthHelper;

/**
 * Created by Felix.Zhong on 2018/10/7 11:48
 * 测试类
 */
public class MainTest {

    public static void main(String[] args) {
        String googleAuthQRCodeData = GoogleAuthHelper.createGoogleAuthQRCodeData("aaaaaaaaaaaaaa", "54246346", "TOKOK");
        System.out.print("googleAuthQRCodeData = " + googleAuthQRCodeData);
    }
}
