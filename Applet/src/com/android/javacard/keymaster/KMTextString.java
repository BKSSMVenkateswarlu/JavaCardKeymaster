package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

//TODO Comments.
//TODO Merge KMTextString and KMByteBLob
public class KMTextString extends KMByteBlob {

  private static KMTextString prototype;

  private KMTextString() {
  }

  private static KMTextString proto(short ptr) {
    if (prototype == null) {
      prototype = new KMTextString();
    }
    instanceTable[KM_TEXT_STRING_OFFSET] = ptr;
    return prototype;
  }

  // pointer to an empty instance used as expression
  public static short exp() {
    return KMType.exp(TEXT_STRING_TYPE);
  }

  // return an empty byte blob instance
  public static short instance(short length) {
    return KMType.instance(TEXT_STRING_TYPE, length);
  }

  // byte blob from existing buf
  public static short instance(byte[] buf, short startOff, short length) {
    short ptr = instance(length);
    Util.arrayCopyNonAtomic(buf, startOff, heap, (short) (ptr + TLV_HEADER_SIZE), length);
    return ptr;
  }

  // cast the ptr to KMTextString
  public static KMTextString cast(short ptr) {
    if (heap[ptr] != TEXT_STRING_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (Util.getShort(heap, (short) (ptr + 1)) == INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  protected short getBaseOffset() {
    return instanceTable[KM_TEXT_STRING_OFFSET];
  }
}
