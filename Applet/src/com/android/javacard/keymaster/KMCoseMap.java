package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * This class represents either a Cose_key or Cose headers as defined in https://datatracker.ietf.org/doc/html/rfc8152
 * This is basically a map containing key value pairs. The label for the key can be (uint / int / tstr) and
 * the value can be of any type. But this class is confined to support only key and value types which are
 * required for remote key provisioning. So keys of type (int / uint) and values of type (int / uint / simple / bstr)
 * only are supported. KMCoseHeaders and KMCoseKey implements this class.
 */
public abstract class KMCoseMap extends KMType {

  /**
   * This function creates an instance of either KMCoseHeaders or KMCoseKey based on the type information
   * provided.
   *
   * @param typePtr type information of the underlying KMType.
   * @param arrPtr instance of KMArray.
   * @return instance type of either KMCoseHeaders or KMCoseKey.
   */
  public static short createInstanceFromType(short typePtr, short arrPtr) {
    short mapType = KMType.getType(typePtr);
    switch (mapType) {
      case KMType.COSE_HEADERS_TYPE:
        return KMCoseHeaders.instance(arrPtr);
      case KMType.COSE_KEY_TYPE:
        return KMCoseKey.instance(arrPtr);
      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return 0;
    }
  }

  public static short getVals(short ptr) {
    short mapType = KMType.getType(ptr);
    switch (mapType) {
      case KMType.COSE_HEADERS_TYPE:
        return KMCoseHeaders.cast(ptr).getVals();
      case KMType.COSE_KEY_TYPE:
        return KMCoseKey.cast(ptr).getVals();
      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return 0;
    }
  }

  abstract public short getVals();

  abstract public short length();
}
