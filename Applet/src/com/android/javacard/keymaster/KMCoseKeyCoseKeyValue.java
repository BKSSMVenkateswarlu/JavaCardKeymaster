package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

// TODO Comments
public class KMCoseKeyCoseKeyValue extends KMCoseKeyTypeValue {

  public static final byte[] keys = {
      KMCose.COSE_LABEL_COSE_KEY
  };
  private static KMCoseKeyCoseKeyValue prototype;

  private KMCoseKeyCoseKeyValue() {
  }

  private static KMCoseKeyCoseKeyValue proto(short ptr) {
    if (prototype == null) {
      prototype = new KMCoseKeyCoseKeyValue();
    }
    instanceTable[KM_COSE_KEY_COSE_KEY_VAL_OFFSET] = ptr;
    return prototype;
  }

  // pointer to an empty instance used as expression
  public static short exp() {
    short ptr = instance(COSE_KEY_TAG_TYPE, (short) 6);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), KMType.COSE_KEY_TAG_COSE_KEY_VALUE_TYPE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), KMType.INVALID_VALUE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 4), KMCoseKey.exp());
    return ptr;
  }

  public static short instance(short keyPtr, short valuePtr) {
    if (!isKeyValueValid(KMCoseKeyTypeValue.getKeyValueAsShort(keyPtr))) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (KMType.getType(valuePtr) != COSE_KEY_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short ptr = KMType.instance(COSE_KEY_TAG_TYPE, (short) 6);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), KMType.COSE_KEY_TAG_COSE_KEY_VALUE_TYPE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), keyPtr);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 4), valuePtr);
    return ptr;
  }

  public static KMCoseKeyCoseKeyValue cast(short ptr) {
    byte[] heap = repository.getHeap();
    if (heap[ptr] != COSE_KEY_TAG_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Validate the value pointer.
    short valuePtr = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE + 4));
    if (KMType.getType(valuePtr) != COSE_KEY_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public short getValueType() {
    return COSE_KEY_TYPE;
  }

  @Override
  public short getKeyPtr() {
    return Util.getShort(heap, (short) (instanceTable[KM_COSE_KEY_COSE_KEY_VAL_OFFSET] + TLV_HEADER_SIZE + 2));
  }

  @Override
  public short getValuePtr() {
    return Util.getShort(heap, (short) (instanceTable[KM_COSE_KEY_COSE_KEY_VAL_OFFSET] + TLV_HEADER_SIZE + 4));
  }

  public static boolean isKeyValueValid(short keyVal) {
    short index = 0;
    while (index < (short) keys.length) {
      if ((byte) (keyVal & 0xFF) == keys[index])
        return true;
      index++;
    }
    return false;
  }

}
