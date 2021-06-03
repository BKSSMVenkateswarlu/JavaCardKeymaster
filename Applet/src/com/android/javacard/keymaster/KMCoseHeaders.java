package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * KMCoseHeaders represents headers section from the Cose standard
 * https://datatracker.ietf.org/doc/html/rfc8152#section-3. The supported key types are
 * KMInteger, KMNInteger and the supported value types are KMInteger, KMNInteger, KMByteBlob,
 * KMCoseKey. It corresponds to a CBOR Map type. struct{byte TAG_TYPE; short length; short arrayPtr }  where
 * arrayPtr is a pointer to array with any KMTag subtype instances.
 */
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
    // CoseKey is internally an Array so evaluate it separately.
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

  private short getValueType(short key) {
    short index = 0;
    short len = length();
    short arr = getVals();
    short tagType;
    short valPtr = 0;
    short keyPtr;
    boolean found = false;
    while (index < len) {
      tagType = KMCoseKeyTypeValue.getTagValueType(KMArray.cast(arr).get(index));
      switch (tagType) {
        case KMType.COSE_KEY_TAG_BYTE_BLOB_VALUE_TYPE:
          keyPtr = KMCoseKeyByteBlobValue.cast(KMArray.cast(arr).get(index)).getKeyPtr();
          if (key == (byte) KMCoseKeyTypeValue.getKeyValueShort(keyPtr)) {
            valPtr = KMCoseKeyByteBlobValue.cast(KMArray.cast(arr).get(index)).getValuePtr();
            found = true;
          }
          break;
        case KMType.COSE_KEY_TAG_COSE_KEY_VALUE_TYPE:
          keyPtr = KMCoseKeyCoseKeyValue.cast(KMArray.cast(arr).get(index)).getKeyPtr();
          if (key == (byte) KMCoseKeyTypeValue.getKeyValueShort(keyPtr)) {
            valPtr = KMCoseKeyCoseKeyValue.cast(KMArray.cast(arr).get(index)).getValuePtr();
            found = true;
          }
          break;
        case KMType.COSE_KEY_TAG_INT_VALUE_TYPE:
          keyPtr = KMCoseKeyIntegerValue.cast(KMArray.cast(arr).get(index)).getKeyPtr();
          if (key == (byte) KMCoseKeyTypeValue.getKeyValueShort(keyPtr)) {
            valPtr = KMCoseKeyIntegerValue.cast(KMArray.cast(arr).get(index)).getValuePtr();
            found = true;
          }
          break;
        case KMType.COSE_KEY_TAG_NINT_VALUE_TYPE:
          keyPtr = KMCoseKeyNIntegerValue.cast(KMArray.cast(arr).get(index)).getKeyPtr();
          if (key == (byte) KMCoseKeyTypeValue.getKeyValueShort(keyPtr)) {
            valPtr = KMCoseKeyNIntegerValue.cast(KMArray.cast(arr).get(index)).getValuePtr();
            found = true;
          }
          break;
        default:
          break;
      }
      if (found)
        break;
      index++;
    }
    return valPtr;
  }

  public short getKeyIdentifier() {
    return getValueType(KMCose.COSE_LABEL_KEYID);
  }

  public short getCoseKey() {
    return getValueType(KMCose.COSE_LABEL_COSE_KEY);
  }

  public short getIV() {
    return getValueType(KMCose.COSE_LABEL_IV);
  }

  public short getAlgorithm() {
    return getValueType(KMCose.COSE_LABEL_ALGORITHM);
  }

  public boolean isDataValid(short alg, short keyIdPtr) {
    short[] headerTags = {
        KMCose.COSE_LABEL_ALGORITHM, alg,
        KMCose.COSE_LABEL_KEYID, keyIdPtr,
    };
    boolean valid = false;
    short value;
    short ptr;
    short tagIndex = 0;
    while (tagIndex < headerTags.length) {
      value = headerTags[(short) (tagIndex + 1)];
      if (value != KMType.INVALID_VALUE) {
        valid = false;
        ptr = getValueType(headerTags[tagIndex]);
        switch (KMType.getType(ptr)) {
          case KMType.BYTE_BLOB_TYPE:
            if ((KMByteBlob.cast(value).length() == KMByteBlob.cast(ptr).length()) &&
                (0 ==
                    Util.arrayCompare(KMByteBlob.cast(value).getBuffer(),
                        KMByteBlob.cast(value).getStartOff(),
                        KMByteBlob.cast(ptr).getBuffer(),
                        KMByteBlob.cast(ptr).getStartOff(),
                        KMByteBlob.cast(ptr).length()))) {
              valid = true;
            }
            break;
          case KMType.INTEGER_TYPE:
            if (value == KMInteger.cast(ptr).getShort()) {
              valid = true;
            }
            break;
          case KMType.NEG_INTEGER_TYPE:
            if ((byte) value == (byte) KMNInteger.cast(ptr).getShort()) {
              valid = true;
            }
            break;
          default:
            break;
        }
        if (!valid)
          break;
      }
      tagIndex += 2;
    }
    return valid;
  }


}
