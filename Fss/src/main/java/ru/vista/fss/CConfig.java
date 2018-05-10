package ru.vista.fss;

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Properties;

/**
 * Created by Sony on 26.12.2017.
 */
public class CConfig {
    Properties prop = new Properties();
    InputStream output = null;
    CConfig() throws Exception {
        output = getClass().getResourceAsStream("/files/config.ini");
        prop.load(output);
    }

    Properties getProp(){
        return prop;
    }
}
