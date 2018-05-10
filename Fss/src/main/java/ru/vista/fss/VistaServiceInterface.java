package ru.vista.fss;

/**
 * Created by Sony on 28.11.2017.
 */

import javax.jws.WebMethod;
import javax.jws.WebService;

@WebService
public interface VistaServiceInterface {
    //получить огрн
    @WebMethod ResponceService loadOgrnByToken(String alias) throws Exception;
    //получить фио
    @WebMethod ResponceService getSubjectOfKey(String alias) throws Exception;
    //новый номер больничного
    @WebMethod ResponceService getLnNewNum(String message, String alias, String password) throws Exception;
    //заполненый больничный
    @WebMethod ResponceService prParseFilelnlpu(String message, String alias, String password) throws Exception;
    //ануллирование больничного
    @WebMethod ResponceService disableLN(String message, String alias, String password) throws Exception;
    //получить данные по старым больничным
    @WebMethod ResponceService getLNData(String message, String alias, String password) throws Exception;
    //получить не использованные номера
    @WebMethod ResponceService getExistingLNNumRange(String message, String alias, String password) throws Exception;
    //подпись документа
    @WebMethod ResponceService getSignedDoc(String message, String alias, String password) throws Exception;
    //Получить сертификат
    @WebMethod ResponceService getCertificate(String alias) throws Exception;
    //Подпись врачем
    @WebMethod ResponceService getSignedDocByDoc(String message, String eln, String num, String alias, String password) throws  Exception;
    //Подпись вк
    @WebMethod ResponceService getSignedDocByVk(String message, String eln, String alias, String password) throws Exception;
    //подпись мо
    @WebMethod ResponceService getSignedDocByMo(String message, String eln, String alias, String password) throws Exception;
    //подпись результата
    @WebMethod ResponceService getSignedResult(String message, String eln, String alias, String password) throws Exception;
    //Получение сертификатов
    @WebMethod ResponceService getCerts() throws Exception;
    //Проверка пароля
    @WebMethod ResponceService checkPassword(String alias, String password) throws Exception;

}