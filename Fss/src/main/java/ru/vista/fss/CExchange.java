package ru.vista.fss;

import ru.CryptoPro.JCPxml.XmlInit;

import javax.xml.ws.Endpoint;
import java.util.Properties;

public class CExchange {
    public static void main(String[] args) throws Exception {
        XmlInit.init();
        CConfig config = new CConfig();
        Properties prop = config.getProp();
        Utils.logDir = prop.getProperty("LOG_DIR");
        Endpoint.publish(prop.getProperty("SERVER_ADDR"), new VistaService(prop.getProperty("FSS_CERT_PATH"), prop.getProperty("SERVICE_ADDR"), prop.getProperty("DEFAULT_OGRN")));
        System.out.println("Service started");
    }

}
