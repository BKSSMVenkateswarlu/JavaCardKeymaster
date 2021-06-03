/*
 * Copyright(C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * KMCoseKeyByteBlobValue represents a key-value type, where key can be KMInteger or KMNInteger and value is
 * KMByteBlob type. struct{byte TAG_TYPE; short length; struct{short BYTE_BLOB_TYPE; short key; short value}}.
 */
public class KMCoseKeyByteBlobValue extends KMCoseKeyTypeValue {

  private static KMCoseKeyByteBlobValue prototype;

  public static final byte[][] keys = {
      {0, 0, 0, KMCose.COSE_KEY_PUBKEY_X},
      {0, 0, 0, KMCose.COSE_KEY_PUBKEY_Y},
      {0, 0, 0, KMCose.COSE_LABEL_IV},
      {0, 0, 0, KMCose.COSE_LABEL_KEYID},
      {0, 0, 0, KMCose.COSE_KEY_KEY_ID},
      KMCose.SUBJECT_PUBLIC_KEY,
      KMCose.KEY_USAGE
  };

  private KMCoseKeyByteBlobValue() {
  }

  private static KMCoseKeyByteBlobValue proto(short ptr) {
    if (prototype == null) {
      prototype = new KMCoseKeyByteBlobValue();
    }
    instanceTable[KM_COSE_KEY_BYTE_BLOB_VAL_OFFSET] = ptr;
    return prototype;
  }

  // pointer to an empty instance used as expression
  public static short exp() {
    short ptr = instance(COSE_KEY_TAG_TYPE, (short) 6);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), KMType.COSE_KEY_TAG_BYTE_BLOB_VALUE_TYPE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), KMType.INVALID_VALUE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 4), KMByteBlob.exp());
    return ptr;
  }

  public static short instance(short keyPtr, short valuePtr) {
    if (!isKeyValueValid(keyPtr)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (KMType.getType(valuePtr) != BYTE_BLOB_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short ptr = KMType.instance(COSE_KEY_TAG_TYPE, (short) 6);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), KMType.COSE_KEY_TAG_BYTE_BLOB_VALUE_TYPE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), keyPtr);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 4), valuePtr);
    return ptr;
  }

  public static KMCoseKeyByteBlobValue cast(short ptr) {
    byte[] heap = repository.getHeap();
    if (heap[ptr] != COSE_KEY_TAG_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Validate the value pointer.
    short valuePtr = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE + 4));
    if (KMType.getType(valuePtr) != BYTE_BLOB_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public short getValueType() {
    return BYTE_BLOB_TYPE;
  }

  @Override
  public short getKeyPtr() {
    return Util.getShort(heap, (short) (instanceTable[KM_COSE_KEY_BYTE_BLOB_VAL_OFFSET] + TLV_HEADER_SIZE + 2));
  }

  @Override
  public short getValuePtr() {
    return Util.getShort(heap, (short) (instanceTable[KM_COSE_KEY_BYTE_BLOB_VAL_OFFSET] + TLV_HEADER_SIZE + 4));
  }

  public static boolean isKeyValueValid(short keyPtr) {
    short type = KMType.getType(keyPtr);
    short offset = 0;
    if (type == INTEGER_TYPE) {
      offset = KMInteger.cast(keyPtr).getStartOff();
    } else if (type == NEG_INTEGER_TYPE) {
      offset = KMNInteger.cast(keyPtr).getStartOff();
    } else {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short index = 0;
    while (index < (short) keys.length) {
      if (0 == Util.arrayCompare(keys[index], (short) 0, heap, offset, (short) keys[index].length)) {
        return true;
      }
      index++;
    }
    return false;
  }

}
