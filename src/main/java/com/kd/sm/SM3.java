package com.kd.sm;

import com.sgitg.sgcc.sm.SM3Utils;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Service;

/**
 * 本类主要提供国密SM3算法 使用样例，
 * 此样例包含国密SM3算法的加密方法的使用；
 * <p>
 * *********注意事项*********
 * 1) 所使用的包名为com.sgitg.sgcc.sm.*;
 * 2) 此算法使用只能依赖bcprov-jdk16-1.46.jar,项目中不能同时含有bouncy castle的其他版本的jar，
 * 否则使用过程中算法运算会抛出异常
 */
@Service("SM3")
public class SM3 extends SM3Utils {

    /**
     * 国密SM3算法加密
     *
     * @param plainText 需要进行加密的数据
     * @return 返回加密后hex编码字符
     */
    public final String SM3Digest(String plainText) {
        // 需要加密的数据转化为byte数组
        byte[] byteArray = Strings.toUTF8ByteArray(plainText);
        SG_SM3UpDate(byteArray);
        byte[] sg_SM3Final = null;
        try {
            sg_SM3Final = SG_SM3Final();
        } catch (Exception e) {
            throw new RuntimeException("国密SM3算法加密失败", e);
        }
        return Strings.fromUTF8ByteArray(Hex.encode(sg_SM3Final));
    }
}
