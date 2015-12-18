package miyasaka;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesCryptTest
{
    private final String CIPHER_ALGORITHM = "AES";
    private final String CIPHER_TRANSFORMATION = CIPHER_ALGORITHM + "/CBC/PKCS5Padding";
    private Cipher _encrypt;
    private Cipher _decrypter;
    private IvParameterSpec _iv;

    public static void main(String[] args)
    {
        new AesCryptTest().run();
    }

    public void run()
    {
     //   String txt = "文字列漢字表現な何か？";
        String txt = "Hello World. Are you Ready?";
        String password = "1234567890";

        //Key key = createKey(password, 256);
        Key key = createKey(password, 128);
        initializeCipher(key);
        password = null; // もっとちゃんと破棄すべき?

        byte[] encrypted = encrypt(txt.getBytes() );
        byte[] decrypted = decrypt(encrypted );
        print("[key]",key.getEncoded());
        print("[encrypted]:",encrypted);
        print("[decryped]:",decrypted);
        System.out.println(new String(decrypted) );
    }

    // passwordをシードにしてbitNumサイズのバイト列を作り、鍵にする。
    // 本番(何の?)に耐えられるかは不明。
    public Key createKey(String password, int bitNum)
    {
        SecureRandom random = new SecureRandom(password.getBytes() );
        byte buff[] = new byte[bitNum >> 3];
        random.nextBytes(buff);
        return new SecretKeySpec(buff, CIPHER_ALGORITHM);
    }

    public void initializeCipher(Key key)
    {
        try
        {
            _encrypt = Cipher.getInstance(CIPHER_TRANSFORMATION);
            _encrypt.init(Cipher.ENCRYPT_MODE, key);
            _iv = new IvParameterSpec(_encrypt.getIV());

            _decrypter = Cipher.getInstance(CIPHER_TRANSFORMATION);
            _decrypter.init(Cipher.DECRYPT_MODE, key, _iv);
        }
        catch(Exception exc)
        {
            exc.printStackTrace();
        }
    }

    public byte[] encrypt(byte[] src)
    {
        try
        {
            return _encrypt.doFinal(src);
        }
        catch (Exception exc)
        {
            exc.printStackTrace();
            return null;
        }
    }

    public byte[] decrypt(byte[] src)
    {
        try
        {
            return _decrypter.doFinal(src);
        }
        catch (Exception exc)
        {
            exc.printStackTrace();
            return null;
        }
    }

    public static void print(String tag, byte[] bs) {
        System.out.print(tag);
        for (int i = 0; i < bs.length; ++i) {
            if (i % 16 == 0) {
                System.out.println();
            }
            System.out.print(String.format(" %02X", bs[i]));
        }
        System.out.println();
    }


}