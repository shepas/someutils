package ru.vista.fss;

import org.w3c.dom.Document;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import sun.security.x509.X500Name;

import javax.annotation.Resource;
import javax.jws.WebService;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Created by Sony on 28.11.2017.
 * Веб-сервис
 */

@WebService(endpointInterface = "ru.vista.fss.VistaServiceInterface")
public class VistaService implements VistaServiceInterface {

    @Resource
    WebServiceContext context;
    String fssCertPath = null;
    String fssServeceAddr = null;
    String defogrn = null;
    VistaService(String cert, String serviceAddr, String ogrn){
        fssCertPath = cert;
        fssServeceAddr = serviceAddr;
        defogrn = ogrn;
    }

    private void createHeaders() throws Exception {
        /**
        * Добавление транспортных заголовков
         */
        Map<String, Object> responseHeaders = new HashMap<String, Object>();
        responseHeaders.put("Access-Control-Allow-Origin", Arrays.asList("*"));
        responseHeaders.put("Access-Control-Allow-Methods", Arrays.asList("POST, GET, OPTIONS"));
        responseHeaders.put("Access-Control-Allow-Headers", Arrays.asList("*"));
        MessageContext mc = context.getMessageContext();
        mc.put(MessageContext.HTTP_RESPONSE_HEADERS, responseHeaders);
    }


    //Загрузка информации с токена
    private void loadInfoByToken() throws Exception {
        KeyStore ks = KeyStore.getInstance("HDImageStore");
        ks.load(null, null);
        if (ks.aliases().hasMoreElements()) {
            String alias = ks.aliases().nextElement();
            X509Certificate moCert = (X509Certificate) ks.getCertificate(alias);
            Principal subject = moCert.getSubjectDN();
            int startPos = subject.getName().indexOf("OGRN=") + 5;
            int endPos = startPos + 13;
            String ogrn = subject.getName().substring(startPos, endPos);
            StaticsVariables.moOgrn = ogrn;
        }
    }

    //Получение текущего владельца ключа
    public ResponceService getSubjectOfKey(String alias) throws Exception {
        try {
            KeyStore ks = KeyStore.getInstance("HDImageStore");
            ks.load(null, null);
            if (ks.aliases().hasMoreElements()) {
                X509Certificate moCert = (X509Certificate) ks.getCertificate(alias);
                Principal subject = moCert.getSubjectDN();
                String subjectFIO = ((X500Name) subject).getGivenName() + " " + ((X500Name) subject).getSurname();
                return new ResponceService(1, subjectFIO);
            } else {
                return new ResponceService(0, "Ключей не найдено");
            }
        }catch (Exception e){
            return new ResponceService(0, "Ошибка при запросе ключей");
        }
    }

    //Получение сертификата
    public ResponceService getCertificate(String alias) throws Exception {
        try {
            KeyStore ks = KeyStore.getInstance("HDImageStore");
            ks.load(null, null);
            if (ks.aliases().hasMoreElements()) {
                X509Certificate moCert = (X509Certificate) ks.getCertificate(alias);
                BASE64Encoder encoder = new BASE64Encoder();
                String certificate = encoder.encodeBuffer(moCert.getEncoded()).replace("\r", "");
                return new ResponceService(1, certificate);
            } else {
                return new ResponceService(0, "Ключей не найдено");
            }
        } catch (NullPointerException e){
            return new ResponceService(0, "Ключей не найдено");
        } catch (Exception e){
            return new ResponceService(0, e.getMessage());
        }
    }

    //Получение огрн с токена
    public ResponceService loadOgrnByToken(String alias) throws Exception {
        try {
            KeyStore ks = KeyStore.getInstance("HDImageStore");
            ks.load(null, null);
            if (ks.aliases().hasMoreElements()) {
                X509Certificate moCert = (X509Certificate) ks.getCertificate(alias);
                Principal subject = moCert.getSubjectDN();
                int startPos = subject.getName().indexOf("OGRN=") + 5;
                int endPos = startPos + 13;
                String ogrn = subject.getName().substring(startPos, endPos);
                if (ogrn.contains(".") || ogrn.equals("")) {
                    startPos = subject.getName().indexOf("ОГРН=") + 5;
                    endPos = startPos + 13;
                    ogrn = subject.getName().substring(startPos, endPos);
                    if (ogrn.contains(".") || ogrn.equals(""))
                        ogrn = defogrn;
                    if (ogrn.contains(".") || ogrn.equals(""))
                        ogrn = "";
                }
                try {
                    int og = Integer.parseInt(ogrn);
                } catch (Exception e){
                    ogrn = defogrn;
                }
                StaticsVariables.moOgrn = ogrn;
                return new ResponceService(1, ogrn);
            } else {
                return new ResponceService(0, "Ключей не найдено");
            }
        } catch (NullPointerException e){
            return new ResponceService(0, "Ключей не найдено");
        } catch (Exception e){
            return new ResponceService(0, e.getMessage());
        }
    }

    //Зарузка алиасов из токена
    public ResponceService getCerts() throws Exception{
        KeyStore ks = KeyStore.getInstance("HDImageStore");
        ks.load(null, null);
        if (ks.aliases().hasMoreElements()) {
            Date curDate = new Date();
            String responce = "";
            Class<?> claz = ks.aliases().getClass();
            Field field = claz.getDeclaredField("val$c");
            field.setAccessible(true);
            ArrayList<String> aliases = (ArrayList<String>) field.get(ks.aliases());
            for (String alias: aliases) {
                X509Certificate moCert = (X509Certificate) ks.getCertificate(alias);
                if(moCert.getNotAfter().after(curDate)) {
                    Principal subject = moCert.getSubjectDN();
                    responce += ((X500Name) subject).getGivenName() + " " + ((X500Name) subject).getSurname() + ":" + alias + ";";
                }
            }
            return new ResponceService(1, responce);
        } else {
            return new ResponceService(0, "Ключей не найдено");
        }
    }

    //Установка МО
    private void setMoByAlias(String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance("HDImageStore");
        ks.load(null, null);
        if (ks.aliases().hasMoreElements()) {
            StaticsVariables.moOgrn = defogrn;
        }
    }


    //Получение номера больничного
    public ResponceService getLnNewNum(String message, String alias, String password) throws Exception {
        try {
            setMoByAlias(alias);
            BASE64Decoder decoder = new BASE64Decoder();
            message = new String(decoder.decodeBuffer(message));
            Document doc = Utils.loadXMLFromString(message);
            CEncrypt encryptor = new CEncrypt(doc, fssCertPath, alias, password);
            System.out.println("Prepare doc");
            Utils.writeDoc(doc, System.out);
            Document encryptedDoc = encryptor.encrypt(doc);
            System.out.println("Encrypted doc");
            encryptedDoc = Utils.createDoc(encryptedDoc);
            Utils.writeDoc(encryptedDoc, System.out);
            String result = Utils.dom2String(encryptedDoc);
            Document responceDoc = Utils.loadXMLFromString(CSoap.SendRequest(result, Variables.SOAP_ACTION_GetNewLNNum, fssServeceAddr));
            responceDoc = encryptor.decrypt(responceDoc);
            System.out.println("\n\n\nDecoded responce\n\n\n");
            Utils.writeDoc(responceDoc, System.out);
            BASE64Encoder encoder = new BASE64Encoder();
            if (responceDoc.getElementsByTagName("ns1:LNNum").item(0) != null) {
                String numbers = "";
                for (int i = 0; i < responceDoc.getElementsByTagName("ns1:LNNum").getLength(); i++) {
                    numbers += responceDoc.getElementsByTagName("ns1:LNNum").item(i).getTextContent() + ";";
                }
                return new ResponceService(1, encoder.encode(numbers.getBytes()));
            } else {
                String errMess = responceDoc.getElementsByTagName("ns1:MESS").item(0).getTextContent();
                return new ResponceService(1, encoder.encode(errMess.getBytes()));
            }
        }catch (Exception e){
            return new ResponceService(0, "Ошибка");
        }
    }

    public ResponceService prParseFilelnlpu(String message, String alias, String password) throws Exception {
        try {
            setMoByAlias(alias);
            BASE64Decoder decoder = new BASE64Decoder();
            message = new String(decoder.decodeBuffer(message));
            Document doc = Utils.loadXMLFromString(message);
            CEncrypt encryptor = new CEncrypt(doc, fssCertPath, alias, password);
            System.out.println("Prepare doc");
            Utils.writeDoc(doc, System.out);
            Document encryptedDoc = encryptor.encrypt(doc);
            System.out.println("Encrypted doc");
            encryptedDoc = Utils.createDoc(encryptedDoc);
            Utils.writeDoc(encryptedDoc, System.out);
            String result = Utils.dom2String(encryptedDoc);
            Document responceDoc = Utils.loadXMLFromString(CSoap.SendRequest(result, Variables.SOAP_ACTION_PrParseFileLnLpu, fssServeceAddr));
            responceDoc = encryptor.decrypt(responceDoc);
            BASE64Encoder encoder = new BASE64Encoder();
            System.out.println("\n\n\nDecrypted doc\n\n\n");
            Utils.writeDoc(responceDoc, System.out);
            String mess = responceDoc.getElementsByTagName("ns1:MESS").item(0).getTextContent();
            if (!responceDoc.getElementsByTagName("ns1:LN_HASH").item(0).getTextContent().isEmpty()){
                mess = responceDoc.getElementsByTagName("ns1:LN_HASH").item(0).getTextContent();
                return new ResponceService(1, encoder.encode(mess.getBytes()));
            }
            if (responceDoc.getElementsByTagName("ns1:ERR_MESS").getLength() != 0) {
                mess += "\n" + responceDoc.getElementsByTagName("ns1:ERR_MESS").item(0).getTextContent();
            }
            return new ResponceService(1, encoder.encode(mess.getBytes()));
        }catch (Exception e){
            BASE64Encoder encoder = new BASE64Encoder();
            return new ResponceService(0, encoder.encode("Произошла ошибка при формировании данных".getBytes()));
        }
    }

    public ResponceService disableLN(String message, String alias, String password) throws Exception {
        setMoByAlias(alias);
        BASE64Decoder decoder = new BASE64Decoder();
        message = new String (decoder.decodeBuffer(message));
        Document doc = Utils.loadXMLFromString(message);
        CEncrypt encryptor = new CEncrypt(doc, fssCertPath, alias, password);
        System.out.println("Prepare doc");
        Utils.writeDoc(doc, System.out);
        Document encryptedDoc = encryptor.encrypt(doc);
        System.out.println("Encrypted doc");
        encryptedDoc = Utils.createDoc(encryptedDoc);
        Utils.writeDoc(encryptedDoc, System.out);
        String result = Utils.dom2String(encryptedDoc);
        Document responceDoc =  Utils.loadXMLFromString(CSoap.SendRequest(result, Variables.SOAP_ACTION_DisableLn, fssServeceAddr));
        responceDoc = encryptor.decrypt(responceDoc);
        BASE64Encoder encoder = new BASE64Encoder();
        String mess = responceDoc.getElementsByTagName("ns1:MESS").item(0).getTextContent();
        return new ResponceService(1, encoder.encode(mess.getBytes()));
    }

    public ResponceService getLNData(String message, String alias, String password) throws Exception {
        setMoByAlias(alias);
        BASE64Decoder decoder = new BASE64Decoder();
        message = new String (decoder.decodeBuffer(message));
        Document doc = Utils.loadXMLFromString(message);
        CEncrypt encryptor = new CEncrypt(doc, fssCertPath, alias, password);
        System.out.println("Prepare doc");
        Utils.writeDoc(doc, System.out);
        Document encryptedDoc = encryptor.encrypt(doc);
        System.out.println("Encrypted doc");
        encryptedDoc = Utils.createDoc(encryptedDoc);
        Utils.writeDoc(encryptedDoc, System.out);
        String result = Utils.dom2String(encryptedDoc);
        Document responceDoc =  Utils.loadXMLFromString(CSoap.SendRequest(result, Variables.SOAP_ACTION_GetLnData, fssServeceAddr));
        responceDoc = encryptor.decrypt(responceDoc);
        System.out.println("\n\n\nDecrypted\n\n\n");
        Utils.writeDoc(responceDoc, System.out);
        BASE64Encoder encoder = new BASE64Encoder();
        if (responceDoc.getElementsByTagName("ns1:MESS").item(0) != null) {
            String mess = responceDoc.getElementsByTagName("ns1:MESS").item(0).getTextContent();
            return new ResponceService(0, encoder.encode(mess.getBytes()));
        } else {
            String mess = Utils.dom2String(responceDoc);
            return new ResponceService(1, encoder.encode(mess.getBytes()));
        }
    }

    public ResponceService getExistingLNNumRange(String message, String alias, String password) throws Exception {
        setMoByAlias(alias);
        BASE64Decoder decoder = new BASE64Decoder();
        message = new String (decoder.decodeBuffer(message));
        Document doc = Utils.loadXMLFromString(message);
        CEncrypt encryptor = new CEncrypt(doc, fssCertPath, alias, password);
        System.out.println("Prepare doc");
        Utils.writeDoc(doc, System.out);
        Document encryptedDoc = encryptor.encrypt(doc);
        System.out.println("Encrypted doc");
        encryptedDoc = Utils.createDoc(encryptedDoc);
        Utils.writeDoc(encryptedDoc, System.out);
        String result = Utils.dom2String(encryptedDoc);
        Document responceDoc =  Utils.loadXMLFromString(CSoap.SendRequest(result, Variables.SOAP_ACTION_GetExistingLNNumRange, fssServeceAddr));
        responceDoc = encryptor.decrypt(responceDoc);
        result = Utils.dom2String(responceDoc);
        BASE64Encoder encoder = new BASE64Encoder();
        createHeaders();
        return new ResponceService(1, encoder.encode(result.getBytes()));
    }

    public ResponceService getSignedDoc(String message, String alias, String password) throws Exception{
        setMoByAlias(alias);
        Document doc = Utils.loadXMLFromString(message);
        CEncrypt encryptor = new CEncrypt(doc, fssCertPath, alias, password);
        System.out.println("Prepare doc");
        Utils.writeDoc(doc, System.out);
        Document signDoc = encryptor.signDoc(doc);
        System.out.println("\n\n\nSigned doc\n\n\n");
        Utils.writeDoc(signDoc, System.out);
        String result = Utils.dom2String(signDoc);
        BASE64Encoder encoder = new BASE64Encoder();
        return new ResponceService(1, encoder.encode(result.getBytes()));
    }

    public ResponceService getSignedDocByDoc(String message, String eln, String num, String alias, String password) throws Exception{
        setMoByAlias(alias);
        Document doc = Utils.loadXMLFromString(message);
        CEncrypt encryptor = new CEncrypt(doc, fssCertPath, alias, password);
        System.out.println("Prepare doc");
        Utils.writeDoc(doc, System.out);
        Document signDoc = encryptor.signDocByDoc(doc, eln, num);
        System.out.println("\n\n\nSigned doc\n\n\n");
        Utils.writeDoc(signDoc, System.out);
        String result = Utils.dom2String(signDoc);
        BASE64Encoder encoder = new BASE64Encoder();
        return new ResponceService(1, encoder.encode(result.getBytes()));
    }

    public ResponceService getSignedDocByVk(String message, String eln, String alias, String password) throws Exception{
        setMoByAlias(alias);
        BASE64Decoder decoder = new BASE64Decoder();
        message = new String (decoder.decodeBuffer(message));
        Document doc = Utils.loadXMLFromString(message);
        CEncrypt encryptor = new CEncrypt(doc, fssCertPath, alias, password);
        System.out.println("Prepare doc");
        Utils.writeDoc(doc, System.out);
        Document signDoc = encryptor.signDocByVk(doc, eln);
        System.out.println("\n\n\nSigned doc\n\n\n");
        Utils.writeDoc(signDoc, System.out);
        String result = Utils.dom2String(signDoc);
        BASE64Encoder encoder = new BASE64Encoder();
        return new ResponceService(1, encoder.encode(result.getBytes()));
    }

    public ResponceService getSignedResult(String message, String eln, String alias, String password) throws Exception{
        setMoByAlias(alias);
        BASE64Decoder decoder = new BASE64Decoder();
        message = new String (decoder.decodeBuffer(message));
        Document doc = Utils.loadXMLFromString(message);
        CEncrypt encryptor = new CEncrypt(doc, fssCertPath, alias, password);
        System.out.println("Prepare doc");
        Utils.writeDoc(doc, System.out);
        Document signDoc = encryptor.signResDoc(doc, eln);
        System.out.println("\n\n\nSigned doc\n\n\n");
        Utils.writeDoc(signDoc, System.out);
        String result = Utils.dom2String(signDoc);
        BASE64Encoder encoder = new BASE64Encoder();
        return new ResponceService(1, encoder.encode(result.getBytes()));
    }

    public ResponceService getSignedDocByMo(String message, String eln, String alias, String password) throws Exception{
        setMoByAlias(alias);
        BASE64Decoder decoder = new BASE64Decoder();
        message = new String (decoder.decodeBuffer(message));
        Document doc = Utils.loadXMLFromString(message);
        CEncrypt encryptor = new CEncrypt(doc, fssCertPath, alias, password);
        System.out.println("Prepare doc");
        Utils.writeDoc(doc, System.out);
        Document signDoc = encryptor.signDocByMo(doc, eln);
        System.out.println("\n\n\nSigned doc\n\n\n");
        Utils.writeDoc(signDoc, System.out);
        String result = Utils.dom2String(signDoc);
        BASE64Encoder encoder = new BASE64Encoder();
        return new ResponceService(1, encoder.encode(result.getBytes()));
    }

    public ResponceService checkPassword(String alias, String passord) throws Exception{
        setMoByAlias(alias);
        try {
            CEncrypt encrypt = new CEncrypt(alias, passord);
            if (encrypt.passwordIsValid){
                return new ResponceService(1, "Успех");
            } else {
                return new ResponceService(0, "Пароль неверен");
            }
        } catch (Exception e){
            return new ResponceService(0, "Пароль неверен");
        }
    }


}
