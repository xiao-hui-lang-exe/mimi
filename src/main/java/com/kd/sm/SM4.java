package com.kd.sm;

import com.sgitg.sgcc.sm.SM4Utils;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;

/**
 * 本类主要提供国密SM4算法使用样例，
 * 此样例包含国密SM4算法的(ECB模式|CBC模式)两种模式下的加密和解密方法的使用；
 * <p>
 * *********注意事项*********
 * 1) 所使用的包名为com.sgitg.sgcc.sm.*;
 * 2) 此算法使用只能依赖bcprov-jdk16-1.46.jar,项目中不能同时含有bouncy castle的其他版本的jar，
 * 否则使用过程中算法运算会抛出异常
 * 3) 以下SM4Util针对字符串进行算法操作，
 * 若项目组需要进行文件加密操作请使用SM4Utils对外方法进行byte数组算法运算处理
 */
@Service("SM4")
public class SM4 extends SM4Utils {

    /**
     * generate a secret key.
     *
     * @return a random key or iv with hex code type.
     */
    public String generateKeyOrIV() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return Strings.fromUTF8ByteArray(Hex.encode(key));
    }

    /**
     * 使用国密SM4算法ECB模式进行加密数据
     *
     * @param plainText 需要加密的明文数据
     * @param key       加密需要的hex编码的秘钥
     * @return 返回加密后的hex编码的密文
     */
    public final String encryptBySM4ECB(String plainText, String key) {
        //调用国密SM4算法的ecb模式对明文数据进行加密
        byte[] sg_EncECBData = SG_EncECBData(Hex.decode(key), Strings.toUTF8ByteArray(plainText));
        return Strings.fromUTF8ByteArray(Hex.encode(sg_EncECBData));
    }


    /**
     * 使用国密	SM4算法ECB模式进行解密数据
     *
     * @param cipherText 需要进行解密hex编码密文
     * @param key        解密需要的hex编码的秘钥
     * @return 返回解密后的明文信息
     */
    public final String decryptBySM4ECB(String cipherText, String key) {
        //调用国密SM4算法ECB模式对密文进行解密
        byte[] sg_EncECBData = SG_DecECBData(Hex.decode(key), Hex.decode(cipherText));
        return Strings.fromUTF8ByteArray(sg_EncECBData);
    }

    /**
     * 使用国密SM4算法CBC模式进行加密数据
     *
     * @param plainText 需要加密的明文数据
     * @param key       加密需要的hex编码的秘钥
     * @param iv        加密需要的hex编码的初始向量
     * @return 返回加密后的hex编码的密文字符
     */
    public final String encryptBySM4CBC(String plainText, String key, String iv) {
        //调用国密SM4算法的CBC模式对明文数据进行加密
        byte[] encryptData_CBC = encryptData_CBC(Hex.decode(iv), Hex.decode(key), Strings.toUTF8ByteArray(plainText));
        return Strings.fromUTF8ByteArray(Hex.encode(encryptData_CBC));
    }

    /**
     * 使用国密SM4算法的CBC模式进行解密数据
     *
     * @param cipherText 加密后的hex编码密文数据
     * @param key        解密需要的hex编码的秘钥
     * @param iv         解密需要的hex编码的初始向量
     * @return 返回解密后明文字符串
     */
    public final String decryptBySM4CBC(String cipherText, String key, String iv) {
        //调用国密SM4算法CBC模式对密文进行解密
        byte[] decryptData_CBC = decryptData_CBC(Hex.decode(iv), Hex.decode(key), Hex.decode(cipherText));
        return Strings.fromUTF8ByteArray(decryptData_CBC);
    }
}
