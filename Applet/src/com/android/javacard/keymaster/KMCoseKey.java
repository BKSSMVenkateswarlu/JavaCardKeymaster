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

public class KMCoseKey extends KMType {

  private static KMCoseKey prototype;

  private KMCoseKey() {
  }

  private static KMCoseKey proto(short ptr) {
    if (prototype == null) {
      prototype = new KMCoseKey();
    }
    instanceTable[KM_COSE_KEY_OFFSET] = ptr;
    return prototype;
  }

  public static short exp() {
    short arrPtr = KMArray.instance((short) 3);
    KMArray arr = KMArray.cast(arrPtr);
    arr.add((short) 0, KMCoseKeyIntegerValue.exp());
    arr.add((short) 1, KMCoseKeyNIntegerValue.exp());
    arr.add((short) 2, KMCoseKeyByteBlobValue.exp());
    return KMCoseKey.instance(arrPtr);
  }


  public static short instance(short vals) {
    short ptr = KMType.instance(COSE_KEY_TYPE, (short) 2);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), vals);
    return ptr;
  }

  public static KMCoseKey cast(short ptr) {
    if (heap[ptr] != COSE_KEY_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short arrPtr = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE));
    if (heap[arrPtr] != ARRAY_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public short getVals() {
    return Util.getShort(heap, (short) (instanceTable[KM_COSE_KEY_OFFSET] + TLV_HEADER_SIZE));
  }

  public short length() {
    short arrPtr = getVals();
    return KMArray.cast(arrPtr).length();
  }

}
