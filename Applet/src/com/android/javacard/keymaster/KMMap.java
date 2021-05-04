package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class KMMap extends KMType {
  public static final short ANY_MAP_LENGTH = 0x1000;
  private static final short MAP_HEADER_SIZE = 4;
  private static KMMap prototype;

  private KMMap() {
  }

  private static KMMap proto(short ptr) {
    if (prototype == null) {
      prototype = new KMMap();
    }
    instanceTable[KM_MAP_OFFSET] = ptr;
    return prototype;
  }

  public static short exp() {
    short ptr = instance(MAP_TYPE, MAP_HEADER_SIZE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), (short) 0);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), ANY_MAP_LENGTH);
    return ptr;
  }

  public static short instance(short length) {
    short ptr = KMType.instance(MAP_TYPE, (short) (MAP_HEADER_SIZE + (length * 4)));
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), (short) 0);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), length);
    return ptr;
  }

  public static short instance(short length, byte type) {
    short ptr = instance(length);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), type);
    return ptr;
  }

  public static KMMap cast(short ptr) {
    if (heap[ptr] != MAP_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public void add(short index, short keyPtr, short valPtr) {
    short len = length();
    if (index >= len) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    short keyIndex = (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + MAP_HEADER_SIZE + (short) (index * 4));
    Util.setShort(heap, keyIndex, keyPtr);
    Util.setShort(heap, (short) (keyIndex + 2), valPtr);
  }

  public short getKey(short index) {
    short len = length();
    if (index >= len) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    return Util.getShort(
      heap, (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + MAP_HEADER_SIZE + (short) (index * 4)));
  }

  public short getKeyValue(short index) {
    short len = length();
    if (index >= len) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    return Util.getShort(
      heap, (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + MAP_HEADER_SIZE + (short) (index * 4 + 2)));
  }

  public short containedType() {
    return Util.getShort(heap, (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE));
  }

  public short getStartOff() {
    return (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + MAP_HEADER_SIZE);
  }

  public short length() {
    return Util.getShort(heap, (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + 2));
  }

  public byte[] getBuffer() {
    return heap;
  }
}
