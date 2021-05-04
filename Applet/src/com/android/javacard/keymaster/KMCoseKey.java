package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class KMCoseKey extends KMType {

  public static final byte COSE_KEY_KEY_TYPE = 1;
  public static final byte COSE_KEY_KEY_ID = 2;
  public static final byte COSE_KEY_ALGORITHM = 3;
  public static final byte COSE_KEY_KEY_OPS = 4;
  public static final byte COSE_KEY_CURVE = -1;
  public static final byte COSE_KEY_PUBKEY_X = -2;
  public static final byte COSE_KEY_PUBKEY_Y = -3;
  public static final byte COSE_KEY_PRIV_KEY = -4;

  private static KMCoseKey prototype;

  private KMCoseKey() {
  }

  private static KMCoseKey proto(short ptr) {
    if (prototype == null) {
      prototype = new KMCoseKey();
    }
    instanceTable[KM_COSE_KEY_OFFSET] = ptr;
    return prototype;
  }

  public static short exp() {
    short mapPtr = KMMap.instance((short) 8);
    KMMap map = KMMap.cast(mapPtr);
    map.add((short) 0, KMInteger.exp(), KMInteger.exp());
    map.add((short) 1, KMInteger.exp(), KMByteBlob.exp());
    return instance(mapPtr);
  }

  public static short instance(short vals) {
    short ptr = KMType.instance(COSE_KEY_TYPE, (short) 2);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), vals);
    return ptr;
  }

  public static KMCoseKey cast(short ptr) {
    if (heap[ptr] != COSE_KEY_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short arrPtr = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE));
    if (heap[arrPtr] != MAP_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public short getVals() {
    return Util.getShort(heap, (short) (instanceTable[KM_COSE_KEY_OFFSET] + TLV_HEADER_SIZE));
  }

  public short length() {
    short mapPtr = getVals();
    return KMMap.cast(mapPtr).length();
  }

}
