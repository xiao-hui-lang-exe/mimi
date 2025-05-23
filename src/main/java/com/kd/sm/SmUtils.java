package com.kd.sm;

import com.sgitg.sgcc.sm.SM2Utils;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author scy
 *
 */
public class SmUtils {

    private static final Logger log = LoggerFactory.getLogger(SmUtils.class);
	/**
	 * 加密
	 * @param str 需要加密的信息
	 * @param Sm4Key sm4秘钥
	 * @return
	 */
    public static Map<String, String> encrypt(String str, String Sm4Key) {
        Map<String, String> result = new HashMap<String, String>();
        try {
        	SM2 sm2 = new SM2();
        	SM3 sm3 = new SM3();
        	SM4 sm4 = new SM4();
        	//获取sm2公钥私钥
        	Map<String, String> map = getSm2Key();

            //SM3加密A生成密文B
            String sm3Digest = sm3.SM3Digest(str);
            //用SM2加密明文参数A+B生成密文C
            String encryptBySM4ECB = sm2.encryptBySM2(str + sm3Digest, map.get("pubKey"));
            //用SM4的秘钥Sm4Key加密Sm2的私钥生成D
            String encryptBySM2 = sm4.encryptBySM4ECB(map.get("priKey"), Sm4Key);
            result.put("Sm4After", encryptBySM4ECB);
            result.put("Sm2After", encryptBySM2);
        } catch (Exception e) {
            log.error("异常信息:{}", e.getMessage());
        }
        return result;
    }

    /**
     * 解密
     * @param SM2After
     * @param SM4After
     * @param Sm4Key sm4秘钥
     * @return
     */
    public static String decrypt(String SM2After, String SM4After, String Sm4Key) {
        String result = "";
        try {
        	SM2 sm2 = new SM2();
        	SM3 sm3 = new SM3();
        	SM4 sm4 = new SM4();
        	//用SM4的私钥Sm4Key解密D得到SM2的秘钥S2K
            String priKey = sm4.decryptBySM4ECB(SM2After, Sm4Key);
            //用Sm2秘钥解密C得到B+S3E
            String MWAndSM3After = sm2.decryptBySM2(SM4After, priKey);
            //截取出A(SM3加密的密文S3E为64位固定长度)
            result = MWAndSM3After.substring(0, MWAndSM3After.length() - 64);
            String SM3After = sm3.SM3Digest(result);
            if (!SM3After.equals(MWAndSM3After.substring(MWAndSM3After.length() - 64))) {
            	result = "密文一致性遭到破坏";
            }
        } catch (Exception e) {
            log.error(e.getMessage());
            result = "解密失败";
        }
        return result;
    }

    /**
     * 获取sm4秘钥
     * @return
     */
    public static String getSm4Key(){
    	SM4 sm4 = new SM4();
		return sm4.generateKeyOrIV();
    }

    /**
     * SM2加密
     * @param str 需要加密的信息
     * @param pubKey sm2公钥
     * @return
     */
    public static String encryptSM2(String str, String pubKey){
    	SM2 sm2 = new SM2();
    	return sm2.encryptBySM2(str, pubKey);
    }

    /**
     * SM2解密
     * @param str 需要解密的信息
     * @param priKey sm2私钥
     * @return
     */
    public static String decryptSM2(String str, String priKey){
    	SM2 sm2 = new SM2();
    	return sm2.decryptBySM2(str, priKey);
    }
    /**
     * SM4加密
     * @param str 需要加密的信息
     * @param pubKey sm4公钥
     * @return
     */
    public static String encryptSM4(String str, String pubKey){
    	SM4 sm4 = new SM4();
    	return sm4.encryptBySM4ECB(str,pubKey);
    }

    /**
     * SM4解密
     * @param str 需要解密的信息
     * @param priKey sm4私钥
     * @return
     */
    public static String decryptSM4(String str, String priKey){
        SM4 sm4 = new SM4();
        return sm4.decryptBySM4ECB(str,priKey);
    }

    /**
     * 获取sm2公钥和私钥
     * @return map priKey 私钥 pubKey 公钥
     */
    public static Map<String, String> getSm2Key(){
    	Map<String, String> map = new HashMap<String, String>();
    	SM2Utils sm2Utils = new SM2Utils();
    	byte[] bytes = sm2Utils.SG_generateKeyPair();
    	String key = Strings.fromUTF8ByteArray(Hex.encode(bytes));
    	//sm2私钥
    	String priKey = key.substring(0, 64);
    	//sm2公钥
    	String pubKey = key.substring(64);
    	map.put("priKey", priKey);
    	map.put("pubKey", pubKey);
    	return map;
    }

    public static void main(String[] args) {
        String plainText = "{\"bizParameter\":\n"
                + "{\"interfaceName\":\"privateHISTORYPOWER\",\"bizValue\":[\"2021-04-01\"],\"pageNo\":\"1\",\"pageSize\":\"10\"}}";
        System.out.println("原文：" + plainText);

        //------------------SM2部分------------------
        // 获得密钥对
        Map<String, String> sm2Key = SmUtils.getSm2Key();
        /*String pubKey = sm2Key.get("pubKey");
        String priKey = sm2Key.get("priKey");*/
        String pubKey = "04695983a10c11183cb19d0a0d289adf35dbb78ae02ce8f2bdd34890333ca8fad79dd0dcf4e5f48883fc343996747810ece8388bda60442f6c86a461db7e37d0b7";
        String priKey = "61935d02805bde306ed659846bf25c8b120fee57205d8c67112292a7bd6c8610";
        System.out.println("公钥：" + pubKey);
        System.out.println("私钥：" + priKey);

        String cipherText = encryptSM2(plainText, pubKey);
        System.out.println("加密: " + cipherText);

        String text = decryptSM2(cipherText, priKey);
        System.out.println("解密: " + text);

        //------------------SM4部分------------------
       /* String sm4Key = getSm4Key();
        System.out.println("Sm4密匙：" + sm4Key);

        Map<String, String> encrypt = encrypt(plainText, sm4Key);
        System.out.println("Sm4加密：" + encrypt);
        System.out.println("Sm4After："+encrypt.get("Sm4After"));
        System.out.println("Sm2After："+encrypt.get("Sm2After"));

        String decrypt = decrypt(encrypt.get("Sm2After"), encrypt.get("Sm4After"), sm4Key);
        System.out.println("Sm4解密: " + decrypt);*/
        // AES加密方式
        // String encryptErrMsg = AESUtils.encrypt(Algorithm.AES, AESMode.CBC, Padding.PKCS5Padding, "AES密钥", "AES向量偏移量", "加密内容");
//        String text = decryptSM2("047ec96e611cc5212c94293ca490a054d7a398873343992f01798888500ef8c9394db94d70748d7f43a59f49da975956a9e5a2add614e87c14e586ed8b928107a201bf8478155eeb308540e8669ba45c9038e2dd34caa8ad0cc41300a9563f004109cbee9458b750", "4227b25fa671d5b6add2af3f17c34c910a0810b8a7ade62632c3b17b69b57801");
    }
}
