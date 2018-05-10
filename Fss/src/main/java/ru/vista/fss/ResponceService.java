package ru.vista.fss;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

/**
 * Created by Sony on 28.11.2017.
 */

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "Responce", namespace="http://fss.ivista.ru/")
public class ResponceService {
    private int status = 0;
    private String message = "";

    ResponceService(int status, String message){
        this.status = status;
        this.message = message;
    }

    /**
     * @return the status
     */
    public int getStatus(){
        return status;
    }

    /**
     * @return the message
     */
    public String getMessage(){
        return message;
    }
}
