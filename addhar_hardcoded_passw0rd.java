import android.net.Uri;
import android.nfc.NdefRecord;
import android.os.CountDownTimer;
import android.os.Environment;
import android.os.Parcelable;
import android.support.v4.content.l;
import android.support.v7.app.c;
import android.telephony.TelephonyManager;
import android.text.Editable;
import android.text.TextUtils;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.text.method.TransformationMethod;
import android.util.Base64;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;
import in.gov.uidai.mAadhaarPlus.BaseApplication;
import in.gov.uidai.mAadhaarPlus.b.f;
import in.gov.uidai.mAadhaarPlus.beans.ResidentProfile;
import in.gov.uidai.mAadhaarPlus.beans.enums.Gender;
import in.gov.uidai.mAadhaarPlus.e.a;
import in.gov.uidai.mAadhaarPlus.service.CountDownService;
import in.gov.uidai.mAadhaarPlus.ui.activity.WebViewActivity;
import in.gov.uidai.mAadhaarPlus.util.b;
import in.gov.uidai.mAadhaarPlus.util.h;
import in.gov.uidai.mAadhaarPlus.util.j;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class i {
    private static final String ALGORITHM = "AES";
    public static boolean BIO_LOCK_STATUS_FETCHED = false;
    public static final String DB_KEY_BIO_LOCK_TIMEOUT;
    public static final String DB_KEY_CONFIG;
    public static final String DB_KEY_KI_VALUE;
    public static final String DB_KEY_MPIN;
    public static final String DB_KEY_NOTIFICATION;
    public static CountDownTimer LOGOUT_TIMER;
    public static boolean LOGOUT_TIMER_ON = false;
    private static final String PASSWORD_PATTERN = "(^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#&%*()!-])(?=\\S+$).{8,}$)";
    public static final String PWD_SALT;
    public static final String SIM_DIFFERENT = "1";
    public static final String SIM_INACTIVE = "2";
    public static final String SIM_OK = "0";
    private static final String TAG;
    public static EditText otpEditText;

    static {
        TAG = i.class.getSimpleName();
        LOGOUT_TIMER_ON = true;
        BIO_LOCK_STATUS_FETCHED = false;
        PWD_SALT = String.valueOf(2131296316);
        DB_KEY_MPIN = String.valueOf(2131296313);
        DB_KEY_KI_VALUE = String.valueOf(2131296312);
        DB_KEY_CONFIG = String.valueOf(2131296311);
        DB_KEY_BIO_LOCK_TIMEOUT = String.valueOf(2131296310);
        DB_KEY_NOTIFICATION = String.valueOf(2131296314);
    }

    public static String byteArrayToHex(byte[] arrby) {
        StringBuffer stringBuffer = new StringBuffer();
        for (int i2 = 0; i2 < arrby.length; ++i2) {
            stringBuffer.append(Integer.toString((arrby[i2] & 255) + 256, 16).substring(1));
        }
        return stringBuffer.toString();
    }

    public static void cancelLogOffTimer() {
        if (LOGOUT_TIMER_ON) {
            LOGOUT_TIMER.cancel();
            LOGOUT_TIMER_ON = false;
        }
    }

    public static boolean checkSDcardAvailable() {
        boolean bl2 = false;
        if (Environment.getExternalStorageState().equals("mounted")) {
            bl2 = true;
        }
        return bl2;
    }

    public static boolean checkWhetherSIMisValid(Context context, String string2) {
        return false;
    }

    public static String convertPasswordHash(String string2) {
        try {
            string2 = i.hashPassword(string2, PWD_SALT);
            return string2;
        }
        catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            Log.e((String)TAG, (String)("Error:" + noSuchAlgorithmException.getMessage()));
            Log.getStackTraceString((Throwable)noSuchAlgorithmException);
            return null;
        }
    }

    /*
     * Enabled aggressive block sorting
     */
    public static NdefRecord createNewNdefRecord(String arrby, Locale object, boolean bl2) {
        byte[] arrby2 = object.getLanguage().getBytes(Charset.forName("US-ASCII"));
        object = bl2 ? Charset.forName("UTF-8") : Charset.forName("UTF-16");
        arrby = arrby.getBytes((Charset)object);
        int n2 = bl2 ? 0 : 128;
        n2 = (char)(n2 + arrby2.length);
        object = new byte[arrby2.length + 1 + arrby.length];
        object[0] = (byte)n2;
        System.arraycopy(arrby2, 0, object, 1, arrby2.length);
        System.arraycopy(arrby, 0, object, arrby2.length + 1, arrby.length);
        return new NdefRecord(1, NdefRecord.RTD_TEXT, new byte[0], (byte[])object);
    }

    public static String createXmlDocument(String string2) {
        try {
            Object object = DocumentBuilderFactory.newInstance();
            object.setNamespaceAware(true);
            object = object.newDocumentBuilder().parse(new InputSource(new StringReader(string2)));
            StringWriter stringWriter = new StringWriter();
            TransformerFactory.newInstance().newTransformer().transform(new DOMSource((Node)object), new StreamResult(stringWriter));
            object = stringWriter.getBuffer().toString();
            return object;
        }
        catch (SAXException sAXException) {
            Log.e((String)TAG, (String)("Error:" + sAXException.getMessage()));
            Log.getStackTraceString((Throwable)sAXException);
            return string2;
        }
        catch (IOException iOException) {
            Log.e((String)TAG, (String)("Error:" + iOException.getMessage()));
            Log.getStackTraceString((Throwable)iOException);
            return string2;
        }
        catch (ParserConfigurationException parserConfigurationException) {
            Log.e((String)TAG, (String)("Error:" + parserConfigurationException.getMessage()));
            Log.getStackTraceString((Throwable)parserConfigurationException);
            return string2;
        }
        catch (TransformerConfigurationException transformerConfigurationException) {
            Log.e((String)TAG, (String)("Error:" + transformerConfigurationException.getMessage()));
            Log.getStackTraceString((Throwable)transformerConfigurationException);
            return string2;
        }
        catch (TransformerException transformerException) {
            Log.e((String)TAG, (String)("Error:" + transformerException.getMessage()));
            Log.getStackTraceString((Throwable)transformerException);
            return string2;
        }
    }

    public static byte[] decodeBase64(String string2) {
        return Base64.decode((byte[])string2.getBytes(), (int)2);
    }

    /*
     * Enabled force condition propagation
     * Lifted jumps to return sites
     */
    public static byte[] decryptByte(byte[] arrby, String object) {
        try {
            object = i.generateKey(i.returnStringOfLength16((String)object).getBytes());
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(2, (Key)object);
            return cipher.doFinal(Base64.decode((byte[])arrby, (int)2));
        }
        catch (BadPaddingException badPaddingException) {
            do {
                return null;
                break;
            } while (true);
        }
        catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            return null;
        }
        catch (NoSuchPaddingException noSuchPaddingException) {
            return null;
        }
        catch (InvalidKeyException invalidKeyException) {
            return null;
        }
        catch (IllegalBlockSizeException illegalBlockSizeException) {
            return null;
        }
    }

    /*
     * Enabled force condition propagation
     * Lifted jumps to return sites
     */
    public static String decryptString(String string2, String object) {
        try {
            object = i.generateKey(i.returnStringOfLength16((String)object).getBytes());
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(2, (Key)object);
            return new String(cipher.doFinal(i.decodeBase64(string2)));
        }
        catch (BadPaddingException badPaddingException) {
            do {
                return null;
                break;
            } while (true);
        }
        catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            return null;
        }
        catch (NoSuchPaddingException noSuchPaddingException) {
            return null;
        }
        catch (InvalidKeyException invalidKeyException) {
            return null;
        }
        catch (IllegalBlockSizeException illegalBlockSizeException) {
            return null;
        }
    }

    public static String encodeBase64(String string2) {
        return Base64.encodeToString((byte[])string2.getBytes(), (int)2);
    }

    public static byte[] encryptByte(byte[] arrby, String object) {
        object = i.generateKey(i.returnStringOfLength16((String)object).getBytes());
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(1, (Key)object);
        return Base64.encode((byte[])cipher.doFinal(arrby), (int)2);
    }

    public static String encryptString(String string2, String object) {
        object = i.generateKey(i.returnStringOfLength16((String)object).getBytes());
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(1, (Key)object);
        return new String(Base64.encode((byte[])cipher.doFinal(string2.getBytes()), (int)2));
    }

    public static void enlargeImage(Context context, String string2, ImageView imageView) {
        context = new Dialog(context);
        context.setContentView(2130968649);
        context.setTitle((CharSequence)string2);
        context.setCancelable(true);
        context.getWindow().setBackgroundDrawable((Drawable)new ColorDrawable(0));
        ((ImageView)context.findViewById(2131689705)).setImageDrawable(imageView.getDrawable());
        context.show();
    }

    public static Bitmap fetchImageFromSDcard(String object) {
        if ((object = new File((String)object)) != null && object.exists() && (object = BitmapFactory.decodeFile((String)object.getAbsolutePath())) != null) {
            return object;
        }
        return null;
    }

    public static String formatAadhaarNumber(String string2, boolean bl2) {
        if (string2.length() == 12 && !bl2) {
            return string2.substring(0, 4) + " " + string2.substring(4, 8) + " " + string2.substring(8, 12);
        }
        if (string2.length() == 12 && bl2) {
            return string2.substring(0, 2) + "XX-XXXX-" + string2.substring(8, 12);
        }
        return "Invalid format";
    }

    /*
     * Enabled force condition propagation
     * Lifted jumps to return sites
     */
    public static String formatEnrolmentNumber(String string2) {
        if (TextUtils.isEmpty((CharSequence)string2)) {
            return "";
        }
        String string3 = string2;
        if (string2.length() != 14) return string3;
        return string2.substring(0, 4) + "/" + string2.substring(4, 9) + "/" + string2.substring(9, 14);
    }

    public static String formatISOTimeStamp(String string2) {
        Object object = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.getDefault());
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault());
        try {
            object = simpleDateFormat.format(object.parse(string2).getTime());
            return object;
        }
        catch (ParseException parseException) {
            Log.e((String)TAG, (String)("" + parseException.getMessage()));
            return string2;
        }
    }

    public static String formatISOTimeStampNew(String string2) {
        Object object = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.getDefault());
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd-MM-yyyy HH:mm", Locale.getDefault());
        try {
            object = simpleDateFormat.format(object.parse(string2).getTime());
            return object;
        }
        catch (ParseException parseException) {
            Log.e((String)TAG, (String)("" + parseException.getMessage()));
            return string2;
        }
    }

    public static int generate3DigitRandom() {
        Random random = new Random();
        new StringBuffer();
        return random.nextInt(900) + 100;
    }

    public static String generateDBPassword() {
        Object object = new Random();
        object.setSeed(123456789);
        int n2 = object.nextInt(10);
        object = BaseApplication.getApplication().getString(2131296496);
        object = i.encodeBase64((String)object + n2);
        Log.d((String)TAG, (String)("Password: " + (String)object));
        return object;
    }

    private static Key generateKey(byte[] arrby) {
        return new SecretKeySpec(arrby, "AES");
    }

    public static String generateQRCodeXml(ResidentProfile residentProfile) {
        return i.createXmlDocument("<PrintLetterBarcodeData  uid=\"" + h.formatString(residentProfile.getUid()) + "\"" + " name=\"" + h.formatString(residentProfile.getName()) + "\"" + " gender=\"" + h.formatString(residentProfile.getGender()) + "\"" + " yob=\"" + h.formatString(i.getYearOfBirth(residentProfile.getDob())) + "\"" + " dob=\"" + h.formatString(residentProfile.getDob()) + "\"" + " co=\"" + h.formatString(residentProfile.getCareof()) + "\"" + " house=\"" + h.formatString(residentProfile.getBuilding()) + "\"" + " street=\"" + h.formatString(residentProfile.getStreet()) + "\"" + " loc=\"" + h.formatString(residentProfile.getLocality()) + "\"" + " vtc=\"" + h.formatString(residentProfile.getVtcName()) + "\"" + " po=\"" + h.formatString(residentProfile.getPoName()) + "\"" + " dist=\"" + h.formatString(residentProfile.getDistrictName()) + "\"" + " subdist=\"" + h.formatString(residentProfile.getSubDist()) + "\"" + " state=\"" + h.formatString(residentProfile.getStateName()) + "\"" + " pc=\"" + h.formatString(residentProfile.getPincode()) + "\"" + " />");
    }

    public static String getFormattedString(String string2, boolean bl2) {
        if (string2 != null) {
            if (!string2.isEmpty()) {
                String string3 = string2;
                if (!bl2) {
                    string3 = string2 + ",\n";
                }
                return string3;
            }
            return "";
        }
        return "";
    }

    /*
     * Enabled force condition propagation
     * Lifted jumps to return sites
     */
    public static String getGenderValue(String string2) {
        if (string2.equalsIgnoreCase("M")) {
            return Gender.M.getValue();
        }
        if (string2.equalsIgnoreCase("F")) {
            return Gender.F.getValue();
        }
        String string3 = string2;
        if (!string2.equalsIgnoreCase("T")) return string3;
        return Gender.T.getValue();
    }

    public static Bitmap getImageAsBitmapFromBase64EncodedFormat(String string2) {
        return BitmapFactory.decodeStream((InputStream)new ByteArrayInputStream(i.decodeBase64(string2)));
    }

    public static File getImageStorageFilePath() {
        File file;
        File file2 = file = new File(BaseApplication.getApplication().getFilesDir(), "images");
        if (!file.exists()) {
            file2 = file;
            if (!file.mkdirs()) {
                Log.d((String)TAG, (String)"failed to create directory");
                file2 = null;
            }
        }
        return file2;
    }

    private static Intent getMyService(Class<?> class_, String string2) {
        Iterator iterator = ((ActivityManager)BaseApplication.getApplication().getSystemService("activity")).getRunningServices(Integer.MAX_VALUE).iterator();
        while (iterator.hasNext()) {
            ActivityManager.RunningServiceInfo runningServiceInfo = (ActivityManager.RunningServiceInfo)iterator.next();
            if (!class_.getName().equals(runningServiceInfo.service.getClassName())) continue;
            Object object = runningServiceInfo.service;
            runningServiceInfo = new Intent();
            runningServiceInfo.setComponent((ComponentName)object);
            object = runningServiceInfo.getStringExtra("bundle_key_uid");
            if (object == null || !object.equals(string2)) continue;
            return runningServiceInfo;
        }
        return null;
    }

    public static String getPayloadData(String string2, boolean bl2, boolean bl3) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n    <UpdateRequest requestMedium=\"MOBILE\" uid=\"" + string2 + "\" xmlns=\"http://www.uidai.gov.in/coreupdateapi/1.0\">\n" + "    <client-id>123</client-id>\n" + "    <client-version>1.0</client-version>\n" + "    <pref>\n" + "    <unlockBiometrics>" + bl2 + "</unlockBiometrics>" + "    <enableBiometricsLock>" + bl3 + "</enableBiometricsLock>\n" + "    </pref>\n" + "    </UpdateRequest>";
    }

    /*
     * Enabled aggressive block sorting
     */
    public static List<Integer> getQRCodeWidthHeight(Context context) {
        ArrayList<Integer> arrayList = new ArrayList<Integer>();
        context = context.getResources().getDisplayMetrics();
        int n2 = context.heightPixels;
        int n3 = (int)((double)context.widthPixels / 1.2);
        int n4 = n2 > n3 ? n3 : n2;
        int n5 = n2;
        if (n2 > n3) {
            n5 = n2 - (n2 - n3);
        }
        arrayList.add(n4);
        arrayList.add(n5);
        return arrayList;
    }

    public static String[] getTelephoneInformation(Context context) {
        context = (TelephonyManager)context.getSystemService("phone");
        return new String[]{context.getDeviceId(), context.getSubscriberId(), context.getLine1Number(), Integer.toString(context.getSimState())};
    }

    public static String getUserPasswordHash(Context context, String string2) {
        return null;
    }

    private static String getYearOfBirth(String string2) {
        String string3 = string2;
        if (!TextUtils.isEmpty((CharSequence)string2)) {
            string3 = string2;
            if (string2.contains("-")) {
                string3 = string2.substring(string2.lastIndexOf("-") + 1, string2.length());
            }
        }
        return string3;
    }

    public static String hashPassword(String string2, String string3) {
        if (TextUtils.isEmpty((CharSequence)string2) || TextUtils.isEmpty((CharSequence)string3)) {
            return null;
        }
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.reset();
        messageDigest.update(string3.getBytes());
        return i.byteArrayToHex(messageDigest.digest(string2.getBytes()));
    }

    public static String hashSaltedApiKey(String string2) {
        if (TextUtils.isEmpty((CharSequence)string2)) {
            return null;
        }
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.reset();
        return i.byteArrayToHex(messageDigest.digest(string2.getBytes()));
    }

    public static boolean isAadhaarNumberValid(String string2) {
        if (TextUtils.isEmpty((CharSequence)string2)) {
            return false;
        }
        return j.validateVerhoeff(string2);
    }

    /*
     * Enabled aggressive block sorting
     */
    public static boolean isEnrolmentNumberValid(String string2) {
        if (TextUtils.isEmpty((CharSequence)string2) || string2.length() != 14) {
            return false;
        }
        return true;
    }

    /*
     * Enabled aggressive block sorting
     */
    public static boolean isPhoneNumberValid(String string2) {
        if (TextUtils.isEmpty((CharSequence)string2) || string2.length() != 10) {
            return false;
        }
        return true;
    }

    /*
     * Enabled aggressive block sorting
     */
    public static boolean isPinCodeNumberValid(String string2) {
        if (TextUtils.isEmpty((CharSequence)string2) || string2.length() != 6) {
            return false;
        }
        return true;
    }

    public static boolean isValidEmailAddress(String string2) {
        return Pattern.compile("^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$").matcher(string2).matches();
    }

    public static boolean isValidOTP(String string2) {
        Context context = BaseApplication.getApplication().getApplicationContext();
        Log.d((String)TAG, (String)("otp is " + string2));
        if (TextUtils.isEmpty((CharSequence)string2) || string2.length() == 0) {
            i.showToastMessage(context.getString(2131296379));
            return false;
        }
        return true;
    }

    public static boolean isValidPassword(String string2) {
        return Pattern.compile("(^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#&%*()!-])(?=\\S+$).{8,}$)").matcher(string2).matches();
    }

    public static ResidentProfile parseEKYCData(String string2) {
        ResidentProfile residentProfile = null;
        if (!TextUtils.isEmpty((CharSequence)string2)) {
            string2 = string2.replace("\n", "").replace("\r", "");
            residentProfile = new in.gov.uidai.mAadhaarPlus.g.a().parse(string2);
        }
        return residentProfile;
    }

    public static String parseXMLString(String object, String string2) {
        object = Pattern.compile("<" + string2 + ">(.+?)</" + string2 + ">").matcher((CharSequence)object);
        if (object.find()) {
            return object.group(1);
        }
        return null;
    }

    public static String readFromAsset(Context object, String arrby) {
        object = object.getAssets();
        try {
            object = object.open((String)arrby);
            arrby = new byte[object.available()];
            object.read(arrby);
            object.close();
            object = new String(arrby).replace("\n", "").replace("\r", "");
            return object;
        }
        catch (IOException iOException) {
            Log.e((String)TAG, (String)("Error:" + iOException.getMessage()));
            Log.getStackTraceString((Throwable)iOException);
            return null;
        }
    }

    public static void removeImageFromDirectory() {
        File file = i.getImageStorageFilePath();
        if (file.isDirectory()) {
            String[] arrstring = file.list();
            for (int i2 = 0; i2 < arrstring.length; ++i2) {
                new File(file, arrstring[i2]).delete();
            }
            Log.d((String)TAG, (String)"delete single file");
        }
    }

    public static String returnStringOfLength16(String string2) {
        if (string2.length() == 16) {
            return string2;
        }
        if (string2.length() < 16) {
            int n2 = string2.length();
            String string3 = "";
            for (int i2 = 0; i2 < 16 - n2; ++i2) {
                string3 = string3 + "#";
            }
            return string2 + string3;
        }
        if (string2.length() > 16) {
            return string2.substring(0, 16);
        }
        return null;
    }

    /*
     * Exception decompiling
     */
    public static void saveImageToStorage(Bitmap var0, File var1_11) {
        // This method has failed to decompile.  When submitting a bug report, please provide this stack trace, and (if you hold appropriate legal rights) the relevant class file.
        // org.benf.cfr.reader.util.ConfusedCFRException: Tried to end blocks [11[CATCHBLOCK], 9[CATCHBLOCK]], but top level block is 19[UNCONDITIONALDOLOOP]
        // org.benf.cfr.reader.bytecode.analysis.opgraph.Op04StructuredStatement.processEndingBlocks(Op04StructuredStatement.java:397)
        // org.benf.cfr.reader.bytecode.analysis.opgraph.Op04StructuredStatement.buildNestedBlocks(Op04StructuredStatement.java:449)
        // org.benf.cfr.reader.bytecode.analysis.opgraph.Op03SimpleStatement.createInitialStructuredBlock(Op03SimpleStatement.java:2877)
        // org.benf.cfr.reader.bytecode.CodeAnalyser.getAnalysisInner(CodeAnalyser.java:825)
        // org.benf.cfr.reader.bytecode.CodeAnalyser.getAnalysisOrWrapFail(CodeAnalyser.java:217)
        // org.benf.cfr.reader.bytecode.CodeAnalyser.getAnalysis(CodeAnalyser.java:162)
        // org.benf.cfr.reader.entities.attributes.AttributeCode.analyse(AttributeCode.java:95)
        // org.benf.cfr.reader.entities.Method.analyse(Method.java:355)
        // org.benf.cfr.reader.entities.ClassFile.analyseMid(ClassFile.java:769)
        // org.benf.cfr.reader.entities.ClassFile.analyseTop(ClassFile.java:701)
        // org.benf.cfr.reader.Main.doJar(Main.java:134)
        // org.benf.cfr.reader.Main.main(Main.java:189)
        throw new IllegalStateException("Decompilation failed");
    }

    public static void setStringToEditText(EditText editText, String string2) {
        if (!TextUtils.isEmpty((CharSequence)string2) && !string2.equalsIgnoreCase("null")) {
            editText.setText((CharSequence)string2.trim());
            return;
        }
        editText.setText((CharSequence)"");
    }

    public static void setStringToTextView(TextView textView, String string2) {
        if (!TextUtils.isEmpty((CharSequence)string2) && !string2.equalsIgnoreCase("null")) {
            textView.setText((CharSequence)string2.trim());
            return;
        }
        textView.setText((CharSequence)"");
    }

    public static void shareApp(Context context) {
        Intent intent = new Intent("android.intent.action.SEND");
        intent.setType("text/plain");
        intent.putExtra("android.intent.extra.SUBJECT", "mAadhaar");
        intent.putExtra("android.intent.extra.TEXT", "Hi, did you try the latest app from UIDAI - m-Aadhaar? It offers you to carry Aadhaar eKYC details in your mobile which you can even share with others. To download, please click https://goo.gl/6voUxj");
        context.startActivity(Intent.createChooser((Intent)intent, (CharSequence)"mAadhaar"));
    }

    public static void shareEKYCData(Context context, Uri uri) {
        Intent intent = new Intent("android.intent.action.SEND");
        if (uri != null) {
            intent.setDataAndType(uri, BaseApplication.getApplication().getContentResolver().getType(uri));
        }
        intent.setType("application/zip");
        intent.putExtra("android.intent.extra.STREAM", (Parcelable)uri);
        context.startActivity(Intent.createChooser((Intent)intent, (CharSequence)"Share e-KYC"));
    }

    public static void shareQRCode(Context context, Uri uri) {
        Intent intent = new Intent("android.intent.action.SEND");
        if (uri != null) {
            intent.setDataAndType(uri, BaseApplication.getApplication().getContentResolver().getType(uri));
        }
        intent.setType("image/jpeg");
        intent.putExtra("android.intent.extra.STREAM", (Parcelable)uri);
        context.startActivity(Intent.createChooser((Intent)intent, (CharSequence)"Share QRcode"));
    }

    public static void showAlertWithOk(Context context, String string2, String string3) {
        i.showToastMessage(string2, string3);
    }

    public static c showCustomAlertDialog(Context context, String string2, final a a2) {
        c.a a3 = new c.a(context);
        a3.setCancelable(false);
        View view = ((LayoutInflater)context.getSystemService("layout_inflater")).inflate(2130968630, null);
        a3.setView(view);
        ((TextView)view.findViewById(2131689646)).setText((CharSequence)string2);
        ((Button)view.findViewById(2131689647)).setOnClickListener(new View.OnClickListener(){

            public void onClick(View view) {
                a2.onPosButtonPressed(this, null);
            }
        });
        if (!((Activity)context).isFinishing()) {
            return a3.show();
        }
        return null;
    }

    /*
     * Enabled aggressive block sorting
     */
    public static c showDisclaimerDialog(Context context, final a a2, boolean bl2) {
        c.a a3 = new c.a(context);
        a3.setCancelable(false);
        View view = ((LayoutInflater)context.getSystemService("layout_inflater")).inflate(2130968632, null);
        a3.setView(view);
        Button button = (Button)view.findViewById(2131689647);
        view = (TextView)view.findViewById(2131689646);
        if (bl2) {
            view.setText(2131296512);
        } else {
            view.setText(2131296511);
        }
        button.setOnClickListener(new View.OnClickListener(){

            public void onClick(View view) {
                a2.onPosButtonPressed(this, "");
            }
        });
        if (!((Activity)context).isFinishing()) {
            return a3.show();
        }
        return null;
    }

    /*
     * Enabled aggressive block sorting
     */
    public static c showEnterOtpDialog(final Context context, final a a2) {
        c.a a3 = new c.a(context);
        a3.setCancelable(false);
        View view = ((LayoutInflater)context.getSystemService("layout_inflater")).inflate(2130968633, null);
        a3.setView(view);
        otpEditText = (EditText)view.findViewById(2131689650);
        if (f.buildType_Q || f.buildType_U) {
            otpEditText.setEnabled(true);
        } else {
            otpEditText.setEnabled(false);
        }
        Button button = (Button)view.findViewById(2131689649);
        ((Button)view.findViewById(2131689647)).setOnClickListener(new View.OnClickListener(){

            public void onClick(View view) {
                if (TextUtils.isEmpty((CharSequence)i.otpEditText.getText().toString()) || i.otpEditText.getText().toString().length() == 0) {
                    i.showToastMessage(context.getString(2131296507));
                    return;
                }
                a2.onPosButtonPressed(this, i.otpEditText.getText().toString());
            }
        });
        button.setOnClickListener(new View.OnClickListener(){

            public void onClick(View view) {
                a2.onNegButtonPressed(this);
            }
        });
        if (!((Activity)context).isFinishing()) {
            return a3.show();
        }
        return null;
    }

    public static void showGuidlines(Context context, String string2, String string3) {
        Intent intent = new Intent(context, WebViewActivity.class);
        intent.putExtra("URL", string2);
        intent.putExtra("bundle_key_title", string3);
        intent.putExtra("calledFrom", "HA");
        context.startActivity(intent);
    }

    public static void showHelp(Context context, String string2, String string3) {
        Intent intent = new Intent(context, WebViewActivity.class);
        intent.putExtra("URL", string2);
        intent.putExtra("bundle_key_title", string3);
        intent.putExtra("calledFrom", "O");
        context.startActivity(intent);
    }

    public static c showPasswordDialog(Context context, a a2) {
        return i.showPasswordDialog(null, context, a2);
    }

    public static c showPasswordDialog(String string2, Context context, a a2) {
        return i.showPasswordDialog(string2, context, a2, null, null);
    }

    public static c showPasswordDialog(String string2, Context context, final a a2, String string3, String string4) {
        c.a a3 = new c.a(context);
        View view = ((LayoutInflater)context.getSystemService("layout_inflater")).inflate(2130968634, null);
        a3.setView(view);
        TextView textView = (TextView)view.findViewById(2131689570);
        if (!TextUtils.isEmpty((CharSequence)string2)) {
            textView.setText((CharSequence)string2);
        }
        string2 = (EditText)view.findViewById(2131689651);
        textView = (Button)view.findViewById(2131689649);
        Button button = (Button)view.findViewById(2131689647);
        ((CheckBox)view.findViewById(2131689652)).setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener((EditText)string2){
            final /* synthetic */ EditText val$editText;

            public void onCheckedChanged(CompoundButton compoundButton, boolean bl2) {
                if (!bl2) {
                    int n2 = this.val$editText.getSelectionStart();
                    int n3 = this.val$editText.getSelectionEnd();
                    this.val$editText.setTransformationMethod((TransformationMethod)new PasswordTransformationMethod());
                    this.val$editText.setSelection(n2, n3);
                    return;
                }
                int n4 = this.val$editText.getSelectionStart();
                int n5 = this.val$editText.getSelectionEnd();
                this.val$editText.setTransformationMethod((TransformationMethod)new HideReturnsTransformationMethod());
                this.val$editText.setSelection(n4, n5);
            }
        });
        if (!TextUtils.isEmpty((CharSequence)string3)) {
            button.setText((CharSequence)string3);
        }
        if (!TextUtils.isEmpty((CharSequence)string4)) {
            textView.setText((CharSequence)string4);
        }
        button.setOnClickListener(new View.OnClickListener((EditText)string2){
            final /* synthetic */ EditText val$editText;

            public void onClick(View view) {
                a2.onPosButtonPressed(this, this.val$editText.getText().toString());
            }
        });
        textView.setOnClickListener(new View.OnClickListener(){

            public void onClick(View view) {
                a2.onNegButtonPressed(this);
            }
        });
        a3.setCancelable(false);
        if (!((Activity)context).isFinishing()) {
            return a3.show();
        }
        return null;
    }

    public static void showToastMessage(String string2) {
        i.showToastMessage(null, string2);
    }

    public static void showToastMessage(String string2, String string3) {
        Context context = BaseApplication.getApplication().getApplicationContext();
        String string4 = string2;
        if (TextUtils.isEmpty((CharSequence)string2)) {
            string4 = context.getString(2131296428);
        }
        string2 = ((LayoutInflater)context.getSystemService("layout_inflater")).inflate(2130968677, null, false);
        ((TextView)string2.findViewById(2131689757)).setText((CharSequence)string4);
        ((TextView)string2.findViewById(2131689758)).setText((CharSequence)string3);
        string3 = new Toast(context);
        string3.setGravity(55, 0, 0);
        string3.setDuration(1);
        string3.setView((View)string2);
        string3.show();
    }

    public static void startBioLockTimer(String string2, boolean bl2, boolean bl3) {
        Log.i((String)TAG, (String)("isCountDownTimerRunning::" + String.valueOf(b.getInstance().isCountDownTimerRunning(string2))));
        if (b.getInstance().isCountDownTimerRunning(string2)) {
            return;
        }
        try {
            b.getInstance().setCountDownTimer(string2, "" + System.currentTimeMillis());
            Log.i((String)TAG, (String)("isRemainingTimer::" + bl2));
            BaseApplication baseApplication = BaseApplication.getApplication();
            Intent intent = new Intent((Context)baseApplication, CountDownService.class);
            intent.putExtra("bundle_key_uid", string2);
            intent.putExtra("bundle_key_remaining_timer", bl2);
            baseApplication.startService(intent);
            return;
        }
        catch (Exception exception) {
            exception.printStackTrace();
            Log.e((String)TAG, (String)(exception.getMessage() + exception.toString()));
            return;
        }
    }

    public static void startLogOffTimer(int n2) {
        LOGOUT_TIMER = new CountDownTimer(n2, 1000){

            public void onFinish() {
                i.LOGOUT_TIMER_ON = false;
            }

            public void onTick(long l2) {
                i.LOGOUT_TIMER_ON = true;
                Log.d((String)"UID", (String)("Time remaining" + l2 / 60000));
            }
        }.start();
    }

    public static void stopBioLockTimer(String string2) {
        BaseApplication baseApplication = BaseApplication.getApplication();
        Intent intent = new Intent("broad_cast_action_count_down_timer");
        intent.putExtra("bundle_key_uid", string2);
        intent.putExtra("bundle_key_count_down_timer", -1);
        l.getInstance((Context)baseApplication).sendBroadcast(intent);
        intent = new Intent((Context)baseApplication, CountDownService.class);
        intent.putExtra("bundle_key_uid", string2);
        baseApplication.stopService(intent);
        b.getInstance().removeCountDownTimer(string2);
    }

    /*
     * Enabled aggressive block sorting
     */
    public static String stringSplitter(String object, String arrstring, int n2) {
        object = arrstring == null ? new StringTokenizer((String)object) : new StringTokenizer((String)object, (String)arrstring);
        arrstring = new String[object.countTokens()];
        int n3 = 0;
        while (object.hasMoreTokens()) {
            arrstring[n3] = object.nextToken();
            ++n3;
        }
        return arrstring[n2];
    }

}