package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class KMNInteger extends KMInteger {
  private static KMNInteger prototype;

  private KMNInteger() {
  }

  private static KMNInteger proto(short ptr) {
    if (prototype == null) {
      prototype = new KMNInteger();
    }
    instanceTable[KM_NEG_INTEGER_OFFSET] = ptr;
    return prototype;
  }

  public static short exp() {
    return KMType.exp(NEG_INTEGER_TYPE);
  }

  // return an empty integer instance
  public static short instance(short length) {
    if ((length <= 0) || (length > 8)) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (length > 4) {
      length = KMInteger.UINT_64;
    } else {
      length = KMInteger.UINT_32;
    }
    return KMType.instance(NEG_INTEGER_TYPE, length);
  }

  public static short instance(byte[] num, short srcOff, short length) {
    if (length > 8) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (length == 1) {
      return uint_8(num[srcOff]);
    } else if (length == 2) {
      return uint_16(Util.getShort(num, srcOff));
    } else if (length == 4) {
      return uint_32(num, srcOff);
    } else {
      return uint_64(num, srcOff);
    }
  }

  public static KMNInteger cast(short ptr) {
    byte[] heap = repository.getHeap();
    if (heap[ptr] != NEG_INTEGER_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (Util.getShort(heap, (short) (ptr + 1)) == INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  // create integer and copy byte value
  public static short uint_8(byte num) {
    short ptr = instance(KMInteger.UINT_32);
    heap[(short) (ptr + TLV_HEADER_SIZE + 3)] = num;
    return ptr;
  }

  // create integer and copy short value
  public static short uint_16(short num) {
    short ptr = instance(KMInteger.UINT_32);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), num);
    return ptr;
  }

  // create integer and copy integer value
  public static short uint_32(byte[] num, short offset) {
    short ptr = instance(KMInteger.UINT_32);
    Util.arrayCopy(num, offset, heap, (short) (ptr + TLV_HEADER_SIZE), KMInteger.UINT_32);
    return ptr;
  }

  // create integer and copy integer value
  public static short uint_64(byte[] num, short offset) {
    short ptr = instance(KMInteger.UINT_64);
    Util.arrayCopy(num, offset, heap, (short) (ptr + TLV_HEADER_SIZE), KMInteger.UINT_64);
    return ptr;
  }

  @Override
  protected short getBaseOffset() {
    return instanceTable[KM_NEG_INTEGER_OFFSET];
  }
}
