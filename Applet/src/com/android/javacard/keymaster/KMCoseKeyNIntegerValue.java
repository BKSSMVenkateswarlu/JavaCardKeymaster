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
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), KMNInteger.exp());
    return ptr;
  }

  public static KMCoseKeyNIntegerValue cast(short ptr) {
    byte[] heap = repository.getHeap();
    if (heap[ptr] != COSE_KEY_TAG_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Validate the value ptr.
    short valuePtr = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2));
    if (NEG_INTEGER_TYPE != getType(valuePtr)) {
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

  @Override
  public short getKeyPtr() {
    return Util.getShort(heap, (short) (instanceTable[KM_COSE_KEY_NINT_VAL_OFFSET] + TLV_HEADER_SIZE));
  }

  @Override
  public short getValuePtr() {
    return Util.getShort(heap, (short) (instanceTable[KM_COSE_KEY_NINT_VAL_OFFSET] + TLV_HEADER_SIZE + 2));
  }

}