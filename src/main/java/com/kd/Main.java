package com.kd;

import cn.hutool.http.ContentType;
import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import cn.hutool.http.HttpUtil;
import com.alibaba.fastjson.JSONObject;
import com.kd.sm.SmUtils;
import com.sgcc.dlsc.aes.AESUtils;
import com.sgcc.dlsc.aes.enumtype.AESMode;
import com.sgcc.dlsc.aes.enumtype.Algorithm;
import com.sgcc.dlsc.aes.enumtype.Padding;

import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

public class Main {
    public static void main(String[] args) {
        String httpUrl= "https://pmos.gs.sgcc.com.cn/px-common-stategridconnected/stategridconnected/bsGetBusinessData/2.0.0/getBusinessData";

        String AppId = "GS-ZHXNY--B000034";
        String AppSecret = "07dd98c207291d48b3f0e0fe321c75a6b7b97c74";
        String pubKey = "？？？";
        String ivKey="？？？";
        String serectKey= "？？？";

//
//        String httpUrl = "http://172.25.67.1/px-common-stategridconnected/stategridconnected/bsGetBusinessData/2.0.0/getBusinessData";
//        String AppId = "GS-LXXNYYXZRGS-SCZT-B000008";
//        String AppSecret = "57556573d76417071eb668830245a2285f7de043";
//        String pubKey = "04dc573849bbfe079b20b85ecd2e7527f13b4f56d18937f204219144cb2462f4105b66bc48b0e86881771aea89825516d546b435c590ddbd55300684e0ea7091f7";
//        String ivKey="BIEns5e6vyydQlQT";
//        String serectKey= "MSJHvWNOkvVY2h3v";


        HttpRequest post = HttpUtil.createPost(httpUrl);
        String reqParameter = getReqParameter(AppId, AppSecret);
        System.out.println("请求头:"+reqParameter);
        post.header("reqParamter",reqParameter);

        String requestParam1 = getRequestParam(pubKey);
        post.body(requestParam1);
        post.contentType(ContentType.JSON.getValue());
        HttpResponse execute = post.execute();
        String body = execute.body();
        int status = execute.getStatus();
        System.out.println(status);
        System.out.println("body"+body);

        String decrypt = AESUtils.decrypt(Algorithm.AES, AESMode.CBC,
                Padding.PKCS5Padding, serectKey, ivKey, body);
        System.out.println(decrypt);
    }
    private static String  getRequestParam(String pubKey){

        Map<String,Object> paramsMap =new HashMap<String,Object>();

        Map  bizParams  =new HashMap();
        bizParams.put("interfaceName","publicDLYH");
        bizParams.put("bizValue", new String[]{});
        bizParams.put("pageNo", "0");
        bizParams.put("pageSize", "10");
        paramsMap.put("bizParameter",bizParams);

        JSONObject jsonObject = new JSONObject(paramsMap);
        System.out.println("参数加密前:"+jsonObject.toString());
        String encryptedStr = SmUtils.encryptSM2(jsonObject.toString(),pubKey);
        System.out.println("参数加密后:"+encryptedStr);

        return encryptedStr;
    }
    private static String getReqParameter(String APPID , String APP_SECRET) {
        Map<String, Object> map = new HashMap<String, Object>();
        String randomStr = "L58Ece1W";
        long currentTimeMillis = System.currentTimeMillis();
        String token = null;
        try {
            token = shaEncode(APP_SECRET + currentTimeMillis + randomStr);
        } catch (Exception e1) {
            e1.printStackTrace();
        }
        map.put("APPID", APPID);
        map.put("TOKEN", token);
        map.put("TIMESTAMP", currentTimeMillis);
        map.put("RANDOMSTR", randomStr);
        JSONObject jsonObject = new JSONObject(map);
        String jsonStr = jsonObject.toString();
        return jsonStr;
    }

    public static String shaEncode(String inStr) throws Exception {
        MessageDigest sha = null;
        try {
            sha = MessageDigest.getInstance("SHA");
        } catch (Exception e) {
            System.out.println(e.toString());
            e.printStackTrace();
            return "";
        }
        byte[] byteArray = inStr.getBytes("UTF-8");
        byte[] md5Bytes = sha.digest(byteArray);
        StringBuffer hexValue = new StringBuffer();
        for (int i = 0; i < md5Bytes.length; i++) {
            int val = ((int) md5Bytes[i]) & 0xff;
            if (val < 16) {
                hexValue.append("0");
            }
            hexValue.append(Integer.toHexString(val));
        }
        return hexValue.toString();
    }
}
