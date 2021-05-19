package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

// TODO Comments.
public class KMCoseHeaders extends KMCoseMap {

  private static KMCoseHeaders prototype;

  private KMCoseHeaders() {
  }

  private static KMCoseHeaders proto(short ptr) {
    if (prototype == null) {
      prototype = new KMCoseHeaders();
    }
    instanceTable[KM_COSE_HEADERS_OFFSET] = ptr;
    return prototype;
  }

  public static short exp() {
    short arrPtr = KMArray.instance((short) 4);
    // CoseKey is internally any Array so evaluate it separately.
    short coseKeyValueExp = KMCoseKeyCoseKeyValue.exp();
    KMArray arr = KMArray.cast(arrPtr);
    arr.add((short) 0, KMCoseKeyIntegerValue.exp());
    arr.add((short) 1, KMCoseKeyNIntegerValue.exp());
    arr.add((short) 2, KMCoseKeyByteBlobValue.exp());
    arr.add((short) 3, coseKeyValueExp);
    return KMCoseHeaders.instance(arrPtr);
  }


  public static short instance(short vals) {
    short ptr = KMType.instance(COSE_HEADERS_TYPE, (short) 2);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), vals);
    return ptr;
  }

  public static KMCoseHeaders cast(short ptr) {
    if (heap[ptr] != COSE_HEADERS_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short arrPtr = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE));
    if (heap[arrPtr] != ARRAY_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  @Override
  public short getVals() {
    return Util.getShort(heap, (short) (instanceTable[KM_COSE_HEADERS_OFFSET] + TLV_HEADER_SIZE));
  }

  @Override
  public short length() {
    short arrPtr = getVals();
    return KMArray.cast(arrPtr).length();
  }

  public void canonicalize() {
    // TODO
  }

}
