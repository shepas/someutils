package ru.vista.fss;

/**
 * Created by Sony on 27.11.2017.
 */
public interface Variables {
    //String LPU_OGRN = "1037821049793";

    String SOAP_ACTION_GetLnData = "http://ru/ibs/fss/ln/ws/FileOperationsLn.wsdl/getLNData";
    String SOAP_ACTION_GetNewLNNum = "http://ru/ibs/fss/ln/ws/FileOperationsLn.wsdl/getNewLNNum";
    String SOAP_ACTION_DisableLn = "http://ru/ibs/fss/ln/ws/FileOperationsLn.wsdl/disableLn";
    String SOAP_ACTION_PrParseFileLnLpu = "http://ru/ibs/fss/ln/ws/FileOperationsLn.wsdl/prParseFilelnlpu";
    String SOAP_ACTION_GetExistingLNNumRange = "http://ru/ibs/fss/ln/ws/FileOperationsLn.wsdl/getExistingLNNumRange";
}
