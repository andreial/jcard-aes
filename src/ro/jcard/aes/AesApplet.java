package ro.jcard.aes;

import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacardx.annotations.*;
import javacardx.crypto.Cipher;

import static ro.jcard.aes.AesAppletStrings.*;

@StringPool(value = {
	    @StringDef(name = "Package", value = "ro.jcard.aes"),
	    @StringDef(name = "AppletName", value = "AesApplet")},
	name = "AesAppletStrings")
public class AesApplet extends Applet {

	public static final byte CLA_APP = 0x00;
	public static final byte AES_SET_KEY = 0x15;
	public static final byte AES_ENCRYPT = 0x25;
	public static final byte AES_DECRYPT = 0x35;
	
    private Cipher cipher;
    private AESKey aesKey;
    private byte[] input;
	private static final short INPUT_LEN = 0x80;
	
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new AesApplet();
    }

    protected AesApplet() {
    	input = new byte[INPUT_LEN];
    	cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        register();
    }

    @Override
    public void process(APDU apdu) {
    	if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
		if (buffer[ISO7816.OFFSET_CLA] != CLA_APP) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		switch (buffer[ISO7816.OFFSET_INS]) {
        case AES_SET_KEY:
            aesKey.setKey(buffer, ISO7816.OFFSET_CDATA);
            break;
        case AES_ENCRYPT:
            cipher.init(aesKey, Cipher.MODE_ENCRYPT);
            cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, INPUT_LEN, input, (short)0x00);
            Util.arrayCopyNonAtomic(input, (short)0x00, buffer, (short)0x00, INPUT_LEN);
            apdu.setOutgoingAndSend((short)0x00, INPUT_LEN);
            break;
        case AES_DECRYPT:
        	cipher.init(aesKey, Cipher.MODE_DECRYPT);
        	cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, INPUT_LEN, input, (short)0x00);
        	Util.arrayCopyNonAtomic(input, (short)0x00, buffer, (short)0x00, INPUT_LEN);
            apdu.setOutgoingAndSend((short)0x00, INPUT_LEN);
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
    }
}
