package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class KMCoseKeyIntegerValue extends KMCoseKeyTypeValue {

  private static KMCoseKeyIntegerValue prototype;


  private KMCoseKeyIntegerValue() {
  }

  private static KMCoseKeyIntegerValue proto(short ptr) {
    if (prototype == null) {
      prototype = new KMCoseKeyIntegerValue();
    }
    instanceTable[KM_COSE_KEY_INT_VAL_OFFSET] = ptr;
    return prototype;
  }

  // pointer to an empty instance used as expression
  public static short exp() {
    short ptr = instance(COSE_KEY_TAG_TYPE, (short) 4);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), KMType.INVALID_VALUE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), KMInteger.exp());
    return ptr;
  }

  public static short instance(short keyPtr, short valuePtr) {
    if (!KMCoseKeyTypeValue.isKeyPairValid(KMCoseKeyTypeValue.getKey(keyPtr), KMInteger.cast(valuePtr).getShort())) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short ptr = KMType.instance(COSE_KEY_TAG_TYPE, (short) 4);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), keyPtr);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), valuePtr);
    return ptr;
  }

  public static KMCoseKeyIntegerValue cast(short ptr) {
    byte[] heap = repository.getHeap();
    if (heap[ptr] != COSE_KEY_TAG_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Validate the keypair.
    short keyPtr = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE));
    short valuePtr = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2));
    if (!KMCoseKeyTypeValue.isKeyPairValid(KMCoseKeyTypeValue.getKey(keyPtr), KMNInteger.cast(valuePtr).getShort())) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public short getValueType() {
    return INTEGER_TYPE;
  }

}
