package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class KMCoseKeyNIntegerValue extends KMCoseKeyTypeValue {

  private static KMCoseKeyNIntegerValue prototype;


  private KMCoseKeyNIntegerValue() {
  }

  private static KMCoseKeyNIntegerValue proto(short ptr) {
    if (prototype == null) {
      prototype = new KMCoseKeyNIntegerValue();
    }
    instanceTable[KM_COSE_KEY_NINT_VAL_OFFSET] = ptr;
    return prototype;
  }

  // pointer to an empty instance used as expression
  public static short exp() {
    short ptr = instance(COSE_KEY_TAG_TYPE, (short) 4);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), KMType.INVALID_VALUE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), KMNInteger.exp());
    return ptr;
  }

  public static KMCoseKeyNIntegerValue cast(short ptr) {
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

  public static short instance(short keyPtr, short valuePtr) {
    if (!KMCoseKeyTypeValue.isKeyPairValid(KMCoseKeyTypeValue.getKey(keyPtr), KMNInteger.cast(valuePtr).getShort())) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short ptr = KMType.instance(COSE_KEY_TAG_TYPE, (short) 4);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), keyPtr);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), valuePtr);
    return ptr;
  }

  public short getValueType() {
    return NEG_INTEGER_TYPE;
  }

}
