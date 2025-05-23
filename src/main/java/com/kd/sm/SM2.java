package com.kd.sm;

import com.sgitg.sgcc.sm.SM2Utils;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Service;

import java.io.IOException;

/**
 * 本类主要提供国密SM2算法 使用样例，
 * 此样例包含国密SM2算法的加密、解密、签名、验签方法的使用；
 * <p>
 * *********注意事项*********
 * 1) 所使用的包名为com.sgitg.sgcc.sm.*;
 * 2) 此算法使用只能依赖bcprov-jdk16-1.46.jar,项目中不能同时含有bouncy castle的其他版本的jar，
 * 否则使用过程中算法运算会抛出异常
 * 3) 以下SM2Util针对String字符串进行算法操作，
 * 若项目组需要进行文件加密操作请使用SM2Utils对外方法进行byte数组算法运算处理
 */
@Service("SM2")
public class SM2 extends SM2Utils {

    /**
     * 国密SM2算法加密方法
     *
     * @param plainText 需要加密的数据
     * @param pubKey    加密所需要的hex编码公钥
     * @return 返回加密后hex编码字符串
     */
    public  String encryptBySM2(String plainText, String pubKey) {
        //将需要加密的信息进行utf8编码转换为byte数组
        byte[] msg = Strings.toUTF8ByteArray(plainText);
        //hex编码的公钥进行转换为byte数组
        byte[] key = Hex.decode(pubKey);
        byte[] cipherByteArray = null;
        try {
            cipherByteArray = SG_SM2EncData(key, msg);
        } catch (IOException e) {
            throw new RuntimeException("国密SM2算法加密失败", e);
        }
        //将加密后的byte数组进行hex编码，以String字符形式输出
        return Strings.fromUTF8ByteArray(Hex.encode(cipherByteArray));
    }

    /**
     * 国密SM2算法解密方法
     *
     * @param cipherText 加密后的hex编码数据
     * @param priKey     解密需要的hex 编码的私钥
     * @return 加密后明文数据
     */
    public  String decryptBySM2(String cipherText, String priKey) {
        //加密后的密文先进行hex解码为byte数组
        byte[] cipher = Hex.decode(cipherText);
        //私钥进行hex解码为byte数组
        byte[] prikey = Hex.decode(priKey);
        byte[] plainByteArray = null;
        try {
            plainByteArray = SG_SM2DecData(prikey, cipher);
        } catch (IOException e) {
            throw new RuntimeException("国密SM2算法解密失败", e);
        }
        //解密后进行字符转为字符串形式
        return Strings.fromUTF8ByteArray(plainByteArray);
    }

    /**
     * 国密SM2算法签名方法
     *
     * @param plainText 需要进行签名的数据
     * @param priKey    签名需要的hex编码私钥
     * @param userID    用户的唯一标识
     * @return 返回签名后的hex编码的密文
     */
    public  String signBySM2(String plainText, String priKey, String userID) {
        byte[] signatureByteArray = null;
        try {
            signatureByteArray = SG_SM2Sign(Strings.toUTF8ByteArray(userID), Hex.decode(priKey), Strings.toUTF8ByteArray(plainText));
        } catch (IOException e) {
            throw new RuntimeException("国密SM2算法签名失败", e);
        }
        return Strings.fromUTF8ByteArray(Hex.encode(signatureByteArray));
    }

    /**
     * 国密SM2算法验签方法
     *
     * @param cipherText 签名后的hex编码密文
     * @param plainText  签名之前的明文
     * @param pubKey     验签需要的hex编码的公钥
     * @param userID     用户的唯一标识
     * @return 返回验签的结果
     */
    public  boolean verifyBySM2(String cipherText, String plainText, String pubKey, String userID) {
        boolean verifySignByteArray = false;
        try {
            verifySignByteArray = SG_SM2VerifySign(Strings.toUTF8ByteArray(userID), Hex.decode(pubKey), Strings.toUTF8ByteArray(plainText), Hex.decode(cipherText));
        } catch (IOException e) {
            throw new RuntimeException("国密SM2算法验签失败", e);
        }
        return verifySignByteArray;
    }

}
