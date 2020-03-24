package sg.edu.ntu.sce.sands.crypto.dcpabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PublicKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.SecretKey;


/**
 * CP-ABE算法工具类
 * @author heqiang
 * @date 2020/3/23 14:05
 */
public class CpabeAlgorithmTool {

    private static GlobalParameters globalSetup(String pairingParametersPath){
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(pairingParametersPath);
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Element G1 = pairing.getG1().newRandomElement().getImmutable();

        GlobalParameters gp = new GlobalParameters();
        gp.setPairingParameters(pairingParameters);
        gp.setG1(G1);
        return gp;
    }

    /**
     * 向系统属性集合中新增属性
     * @param attributes 新增的属性集合
     * @return
     */
    public static String addNewAttributes(String authorityKeysJson, String pairingParametersPath, String... attributes){
        AuthorityKeys authorityKeys = getCurrentAuthorityKeys(authorityKeysJson);
        if (authorityKeys == null) {
            throw new NullPointerException("authorityKeys is null!");
        }
        GlobalParameters globalParameters = globalSetup(pairingParametersPath);//CpabeAlgorithm.globalSetup(160);
        Pairing pairing = PairingFactory.getPairing(globalParameters.getPairingParameters());
        Element eg1g1 = pairing.pairing(globalParameters.getG1(), globalParameters.getG1()).getImmutable();
        for (String attribute : attributes) {
            //校验新增的属性已存在系统属性集合中
            if (authorityKeys.getPublicKeys().containsKey(attribute)){
                continue;
            }
            Element ai = pairing.getZr().newRandomElement().getImmutable();
            Element yi = pairing.getZr().newRandomElement().getImmutable();
            authorityKeys.getPublicKeys().put(attribute, new PublicKey(eg1g1.powZn(ai).toBytes(),
                    globalParameters.getG1().powZn(yi).toBytes()));
            authorityKeys.getSecretKeys().put(attribute, new SecretKey(ai.toBytes(), yi.toBytes()));
        }
        return JsonUtils.toJson(authorityKeys);
    }

    /**
     * 从系统属性集合中移除废弃的属性
     * @param attributes 废弃的属性集合
     * @return
     */
    public static String removeAttribute(String authorityKeysJson, String... attributes) throws Exception{
        AuthorityKeys authorityKeys = getCurrentAuthorityKeys(authorityKeysJson);
        if (authorityKeys == null) {
            throw new Exception("authorityKeys is null!");
        }
        for (String attribute : attributes) {
            authorityKeys.getPublicKeys().remove(attribute);
            authorityKeys.getSecretKeys().remove(attribute);
        }
        return JsonUtils.toJson(authorityKeys);
    }

    /**
     * 向系统中添加属性
     * @param attributes 属性集合
     * @return
     */
    public static String  authorityKeysSetup(String pairingParametersPath, String... attributes) {
        AuthorityKeys authorityKeys = DCPABE.authoritySetup(null, globalSetup(pairingParametersPath), attributes);
        return JsonUtils.toJson(authorityKeys);
    }

    /**
     * 获取系统中所有的属性集合
     * @return
     */
    public static AuthorityKeys getCurrentAuthorityKeys(String authorityKeysJson){
        AuthorityKeys authorityKeys = JsonUtils.parseJson(authorityKeysJson, AuthorityKeys.class);
        return authorityKeys;
    }

    /**
     * 根据用户的身份标识和属性，生成用户个人私钥
     * @param userID 用户身份ID
     * @param attributes 用户身份的属性集合，例如attributes="a","b","c";
     * @return
     */
    public static PersonalKeys PersonalKeysGen(String userID, String authorityKeysJson, String pairingParametersPath,
                                               String ... attributes) throws Exception{
        PersonalKeys personalKeys = new PersonalKeys(userID);
        AuthorityKeys authorityKeys = getCurrentAuthorityKeys(authorityKeysJson);
        if (authorityKeys == null) {
            throw new Exception("authorityKeys is null!");
        }
        for (String attribute : attributes) {
            personalKeys.addKey(DCPABE.keyGen(userID, attribute,
                    authorityKeys.getSecretKeys().get(attribute), globalSetup(pairingParametersPath)));
        }
        return personalKeys;
    }

    /**
     * 生成系统公钥，仅数据加密方加密数据时使用
     * 注意：如果系统属性集合改变，需要重新生成系统公钥
     * @return
     */
    public static PublicKeys PublicKeysGen(String authorityKeysJson)throws Exception {
        PublicKeys publicKeys = new PublicKeys();
        AuthorityKeys authorityKeys = getCurrentAuthorityKeys(authorityKeysJson);
        if (authorityKeys == null) {
            throw new Exception("authorityKeys is null!");
        }
        publicKeys.subscribeAuthority(authorityKeys.getPublicKeys());
        return publicKeys;
    }

    /**
     * 根据访问策略加密数据msg
     * @param msg 原始数据
     * @param as 访问策略
     * @param pks 系统公钥
     * @return
     */
    public static Ciphertext encrypt(Message msg, AccessStructure as, PublicKeys pks, String pairingParametersPath) {
        return DCPABE.encrypt(msg, as, globalSetup(pairingParametersPath),pks);
    }

    /**
     * 根据用户私钥解密数据ct
     * @param ct 密文数据
     * @param pks 用户私钥
     * @return
     */
    public static Message decrypt(Ciphertext ct, PersonalKeys pks, String pairingParametersPath) {
        return DCPABE.decrypt(ct, pks, globalSetup(pairingParametersPath));
    }

    /**
     * 构建访问控制结构，撤销、扩展、恢复都使用此方法
     * @param as 访问控制结构，例如："and a or d and b or c and e f"
     * @return
     */
    public static AccessStructure buildAccessStructure(String as){
        return AccessStructure.buildFromPolicy(as);
    }
}
