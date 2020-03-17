import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import sg.edu.ntu.sce.sands.crypto.dcpabe.*;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PersonalKey;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;


@RunWith(JUnit4.class)
public class Testing {
    @Test
    public void test() {
        GlobalParameters gp = DCPABE.globalSetup(517);

        FileOutputStream fos= null;
        try {
            fos = new FileOutputStream("F://MyTest.txt");
            ObjectOutputStream objectOutputStream=new ObjectOutputStream(fos);
            objectOutputStream.writeObject(gp);
            objectOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testDCPABE2() {
        GlobalParameters gp = DCPABE.globalSetup(160);
        PublicKeys publicKeys = new PublicKeys();

        AuthorityKeys authority1 = DCPABE.authoritySetup("a1", gp, "a", "b");
        publicKeys.subscribeAuthority(authority1.getPublicKeys());

        AuthorityKeys authority2 = DCPABE.authoritySetup("a2", gp, "c", "d");
        publicKeys.subscribeAuthority(authority2.getPublicKeys());

        AuthorityKeys authority3 = DCPABE.authoritySetup("a3", gp, "e", "f");
        publicKeys.subscribeAuthority(authority3.getPublicKeys());


        AccessStructure as = AccessStructure.buildFromPolicy("and a or d and b or c and e f");
        Message message = DCPABE.generateRandomMessage(gp);
        Ciphertext ct = DCPABE.encrypt(message, as, gp, publicKeys);

        PersonalKeys pkeys = new PersonalKeys("user");
        pkeys.addKey(DCPABE.keyGen("user", "a", authority1.getSecretKeys().get("a"), gp));
        pkeys.addKey(DCPABE.keyGen("user", "d", authority2.getSecretKeys().get("d"), gp));
        Message dmessage = DCPABE.decrypt(ct, pkeys, gp);
        System.out.println("message: " + new String(dmessage.getM()));

        PersonalKeys pkeys2 = new PersonalKeys("user");
        pkeys.addKey(DCPABE.keyGen("user", "a", authority1.getSecretKeys().get("a"), gp));
        pkeys.addKey(DCPABE.keyGen("user", "b", authority2.getSecretKeys().get("b"), gp));
        pkeys.addKey(DCPABE.keyGen("user", "e", authority2.getSecretKeys().get("e"), gp));
        Message dmessage2 = DCPABE.decrypt(ct, pkeys2, gp);
        System.out.println("message: " + new String(dmessage2.getM()));

        PersonalKeys pkeys3 = new PersonalKeys("user");
        pkeys.addKey(DCPABE.keyGen("user", "a", authority1.getSecretKeys().get("a"), gp));
        pkeys.addKey(DCPABE.keyGen("user", "b", authority2.getSecretKeys().get("b"), gp));
        pkeys.addKey(DCPABE.keyGen("user", "e", authority2.getSecretKeys().get("e"), gp));
        pkeys.addKey(DCPABE.keyGen("user", "f", authority2.getSecretKeys().get("f"), gp));
        Message dmessage3 = DCPABE.decrypt(ct, pkeys3, gp);
        System.out.println("message: " + new String(dmessage3.getM()));
    }


    @Test
    public void testDCPABE1() {
        GlobalParameters gp = DCPABE.globalSetup(160);

        PublicKeys publicKeys = new PublicKeys();

        AuthorityKeys authority0 = DCPABE.authoritySetup("a1", gp, "a", "b", "c", "d");
        publicKeys.subscribeAuthority(authority0.getPublicKeys());

        AccessStructure as = AccessStructure.buildFromPolicy("and a or d and b c");

        PersonalKeys pkeys = new PersonalKeys("user");
        PersonalKey k_user_a = DCPABE.keyGen("user", "a", authority0.getSecretKeys().get("a"), gp);
        PersonalKey k_user_d = DCPABE.keyGen("user", "d", authority0.getSecretKeys().get("d"), gp);
        pkeys.addKey(k_user_a);
        pkeys.addKey(k_user_d);

        Message message = DCPABE.generateRandomMessage(gp);
        Ciphertext ct = DCPABE.encrypt(message, as, gp, publicKeys);

        Message dMessage = DCPABE.decrypt(ct, pkeys, gp);

        System.out.println("M(" + message.getM().length + ") = " + Arrays.toString(message.getM()));
        System.out.println("DM(" + dMessage.getM().length + ") = " + Arrays.toString(dMessage.getM()));

        assertArrayEquals(message.getM(), dMessage.getM());
    }

    @Test
    public void testAS() {
        AccessStructure as1 = AccessStructure.buildFromPolicy("and a or d and b c");
        System.out.println(as1.toString());
        as1.printMatrix();

        AccessStructure as2 = AccessStructure.buildFromPolicy("and or d and b c a");
        System.out.println(as2.toString());
        as2.printMatrix();

        AccessStructure as3 = AccessStructure.buildFromPolicy("and or a b and c d");
        System.out.println(as3.toString());
        as3.printMatrix();
    }

    @Test
    public void testBilinearity() {
        SecureRandom random = new SecureRandom("12345".getBytes());
        Pairing pairing = PairingFactory.getPairing(new TypeACurveGenerator(random, 181, 603, true).generate());

        Element g1 = pairing.getG1().newRandomElement().getImmutable();
        Element g2 = pairing.getG2().newRandomElement().getImmutable();

        Element a = pairing.getZr().newRandomElement().getImmutable();
        Element b = pairing.getZr().newRandomElement().getImmutable();

        Element ga = g1.powZn(a);
        Element gb = g2.powZn(b);

        Element gagb = pairing.pairing(ga, gb);

        Element ggab = pairing.pairing(g1, g2).powZn(a.mulZn(b));

        assertTrue(gagb.isEqual(ggab));
    }

}
