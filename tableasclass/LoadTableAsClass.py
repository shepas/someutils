# -*- coding: utf-8 -*-
from PyQt4 import QtGui

from library import database
from library.Utils import forceString


class CTableAsClass(type):
    def __new__(cls, name=None, bases=(), attrs={}):
        if name is None:
            return None
        else:
            newAttrs = {}
            db = CInformSchemaDB().db
            tblCols = db.table('information_schema.COLUMNS')
            recs = db.getRecordList(tblCols, '*', [tblCols['TABLE_NAME'].eq(name)])
            if not recs:
                return None
            else:
                for rec in recs:
                    newAttrs[forceString(rec.value('COLUMN_NAME'))] = None
                return super(CTableAsClass, cls).__new__(cls, name, bases, newAttrs)

class CInformSchemaDB(object):
    _instance = None
    def __new__(cls_, *args, **kwargs):
        if not isinstance(cls_._instance, cls_):
            connectionInfo = {'driverName': QtGui.qApp.preferences.dbDriverName,
                              'host': QtGui.qApp.preferences.dbServerName,
                              'port': QtGui.qApp.preferences.dbServerPort,
                              'database': QtGui.qApp.preferences.dbDatabaseName,
                              'user': QtGui.qApp.preferences.dbUserName,
                              'password': QtGui.qApp.preferences.dbPassword,
                              'connectionName': QtGui.qApp.connectionName,
                              'compressData': QtGui.qApp.preferences.dbCompressData,
                              'afterConnectFunc': QtGui.qApp.afterConnectToDatabase}
            cls_.db = database.connectDataBaseByInfo(connectionInfo)
            cls_._instance = object.__new__(cls_, *args, **kwargs)
        return cls_._instance