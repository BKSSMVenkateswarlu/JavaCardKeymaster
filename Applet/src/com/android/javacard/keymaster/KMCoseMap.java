package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

// TODO comments
public abstract class KMCoseMap extends KMType {

  // TODO
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
