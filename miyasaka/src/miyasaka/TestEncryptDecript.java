package miyasaka;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

// test
public class TestEncryptDecript {
	public static void main(String[] args) {
		String JamRNo ="00982130009";
		String salt ="s7Ymb593rf73Uk9a";
		// String plain_text ="Hello World!";
		String base_key = "1234567890abcdef";
		StringBuffer query_header_text = new StringBuffer();
		StringBuffer plain_text = new StringBuffer();
		String sjisStr ="[チョコレート食べたい]";

		/* VerifyCode ハッシュ値を求める */
		byte[] hash_value = createHash(JamRNo+salt);
		String strVerify = convertDigestToString(hash_value);
		System.out.println("Verified:"+ strVerify);

/*
		try{
			sjisStr = new String(sjisStr.getBytes("Shift-JIS"), "Shift-JIS");
		}catch(Exception e){
			System.out.println("文字変換エラー" + e);
		}
*/
		query_header_text.append("jamr-app://agreement?verify="+ strVerify +"&data=");
		plain_text.append("no=00982130009&version=20151124130000&loginid=uu084293&name=");
		plain_text.append(sjisStr);
		plain_text.append("&file_name=image01");
		System.out.println("Query:" + plain_text);

		/* 暗号化する共通鍵とbit長を渡す*/
		Key skey = makeKey1(base_key,128);
		//System.out.println("[skey]:"+skey);
		// 暗号化
		String enc = encrypt(plain_text.toString().getBytes(), skey);
		System.out.println("enc:" + enc);

		//Base64でdecode
/*
		String str_64encoded = Base64.getEncoder().encodeToString(enc);
		System.out.println("Base64-encode:" + str_64encoded);
		QueryString = query_header_text + str_64encoded;
		System.out.println("QueryString:" + QueryString);
*/
/*
		// data=xxxxxx を抜き出す
		// map = getQueryMap(QueryString);
		//Base64でdecode
		String wk = map.get("data");
		//wk = wk +"==";
		System.out.println("Base64-decode:" + wk);
		String str_decoded = new String(Base64.getDecoder().decode(wk));
		// System.out.println("Base64-decode:" + str_decoded);
		byte[] byte_dec = str_decoded.getBytes();
		print("[byte_rec]:",byte_dec);
*/
		// 復号化
		String dec = decrypt(enc, skey);
		System.out.println("decript:" + dec);

	}

	/* ハッシュ値を作成する
	 * 160bit(20byte) Hex40桁
	 */
	public static byte[] createHash(String mess){
		MessageDigest md;

		try{
			md = MessageDigest.getInstance("SHA1");
			md.update(mess.getBytes());
			byte[] wk = md.digest();
			return wk;
		}catch (NoSuchAlgorithmException e){
			throw new RuntimeException(e);
		}
	}

	/*
	 * 秘密鍵をバイト列から生成する
	 * @param key_bits 鍵の長さ（ビット単位）
	 */
	public static Key makeKey1(String base_key,int key_bits) {
		// バイト列
		byte[] byte_base_key = new byte[key_bits / 8];
		byte_base_key = base_key.getBytes();

		// バイト列の内容（秘密鍵の値）はプログラマーが決める
		System.out.printf("Key length: %d\n",byte_base_key.length);
		return new SecretKeySpec(byte_base_key, "AES");
	}

	/**
	 * 暗号化
	 */
	public static String encrypt(byte[] src, Key skey) {
		try {
			Cipher cipher = Cipher.getInstance("AES");
			int maxKeyLen = cipher.getMaxAllowedKeyLength("AES");
			System.out.printf("cipher max key len[%d]\n",maxKeyLen);
			cipher.init(Cipher.ENCRYPT_MODE, skey);
			byte[] encVal = cipher.doFinal(src);
			// 暗号化したbit列をBase64でencodeする。
			String encryptedValue = DatatypeConverter.printBase64Binary(encVal);
			return encryptedValue;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * 復号化
	 */
//	public static byte[] decrypt(byte[] src, Key skey) {
	public static String decrypt(String src, Key skey) {
		try {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, skey);
			//暗号化、Base64でencodeした文字列をbit列に戻す
			byte[] decordeValue = DatatypeConverter.parseBase64Binary(src);
			byte[] decValue = cipher.doFinal(decordeValue);
			String decryptedValue = new String(decValue);
			return decryptedValue;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
    /* QueryString をパース
    *
   */
   public static Map<String, String> getQueryMap(String query)
   {
       String[] params = query.split("&");
       Map<String, String> map = new HashMap<String, String>();
       for (String param : params){
       	String[] splitted = param.split("=");
       	map.put(splitted[0], splitted[1]);
	    }
       return map;
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
	/**
	 * バイト配列を得て文字列に変換して出力
	 * @param digest ダイジェスト
	 */
	public static String convertDigestToString(byte[] digest) {
			StringBuffer buffer = new StringBuffer();
			for (int i= 0; i< digest.length;i++){
				String tmpStr = Integer.toHexString(digest[i] & 0xff);
				if(tmpStr.length() == 1){
					buffer.append('0').append(tmpStr);
				}else{
					buffer.append(tmpStr);
				}
			}
			// System.out.println(buffer.toString());
            return buffer.toString();
	}
}
