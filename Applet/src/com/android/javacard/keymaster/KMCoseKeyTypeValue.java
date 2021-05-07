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

//TODO Comments
public class KMCoseKeyTypeValue extends KMType {

  // TODO Comments
  public static final Object allowedKeyPairs[] = new Object[]{
      // Key type
      KMCose.COSE_KEY_KEY_TYPE, new byte[]{KMCose.COSE_KEY_TYPE_EC2, KMCose.COSE_KEY_TYPE_SYMMETRIC_KEY},
      // Algorithm
      KMCose.COSE_KEY_ALGORITHM, new byte[]{KMCose.COSE_ALG_AES_GCM_256, KMCose.COSE_ALG_HMAC_256,
      KMCose.COSE_ALG_ECDH_ES_HKDF_256, KMCose.COSE_ALG_ES256},
      // Key operations
      KMCose.COSE_KEY_KEY_OPS, new byte[]{KMCose.COSE_KEY_OP_SIGN, KMCose.COSE_KEY_OP_VERIFY,
      KMCose.COSE_KEY_OP_ENCRYPT, KMCose.COSE_KEY_OP_DECRYPT},
      // Curve
      KMCose.COSE_KEY_CURVE, new byte[]{KMCose.COSE_ECCURVE_256},
  };

  // TODO comments
  public static boolean isKeyPairValid(short key, short value) {
    short index = 0;
    short valueIdx;
    byte[] values;
    boolean valid = false;
    while (index < allowedKeyPairs.length) {
      valueIdx = 0;
      if ((short) allowedKeyPairs[index] == key) {
        values = (byte[]) allowedKeyPairs[(short) (index + 1)];
        while (valueIdx < values.length) {
          if (values[valueIdx] == value) {
            valid = true;
            break;
          }
          valueIdx++;
        }
      }
      index += (short)2;
    }
    return valid;
  }

  public static boolean isKeyTypeValid(short keyPtr) {
    short type = KMType.getType(keyPtr);
    boolean isValid = false;
    if (type == INTEGER_TYPE || type == NEG_INTEGER_TYPE) {
      isValid = true;
    }
    return isValid;
  }

  /*
   * This function returns the key from the key pointer.
   * Allowed key types are INTEGER_TYPE and NEG_INTEGER_TYPE.
   */
  public static short getKey(short keyPtr) {
    short type = KMType.getType(keyPtr);
    short value = 0;
    if (type == INTEGER_TYPE) {
      value = KMInteger.cast(keyPtr).getShort();
    } else if (type == NEG_INTEGER_TYPE) {
      value = KMNInteger.cast(keyPtr).getShort();
    } else {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return value;
  }

  public short getKeyPtr() {
    return Util.getShort(heap, (short) (instanceTable[COSE_KEY_TAG_TYPE] + TLV_HEADER_SIZE));
  }

  //TODO Remove if not used.
  public short getValuePtr() {
    return Util.getShort(heap, (short) (instanceTable[COSE_KEY_TAG_TYPE] + TLV_HEADER_SIZE + 2));
  }

  public static short getTagValueType(short exp) {
    short ptr = Util.getShort(heap, (short) (exp + TLV_HEADER_SIZE + 2));
    short tagValueType = 0;
    if (BYTE_BLOB_TYPE == KMType.getType(ptr)) {
      tagValueType = COSE_KEY_TAG_BYTE_BLOB_VALUE_TYPE;
    } else if (INTEGER_TYPE == KMType.getType(ptr)) {
      tagValueType = COSE_KEY_TAG_INT_VALUE_TYPE;
    } else if (NEG_INTEGER_TYPE == KMType.getType(ptr)) {
      tagValueType = COSE_KEY_TAG_NINT_VALUE_TYPE;
    } else {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return tagValueType;
  }
  // TODO validate the values based on the algorithm
  // This is has to be done when using the cose key to sign
  // or encrypt.
  // For example:
  // ECDSA
  //  key type mandatory and value should be EC2
  //  alg should be ES256
  //  key_ops should be sign, verify
  //  curve is 256
  // ECDH
  //  key type mandatory and value should be EC2
  //  alg should be ECDH_ES_HKDF
  // HMAC
  //  key type mandatory and value should be EC2
  //  alg should be SYMMETRIC
  //  key_ops should be sign, verify
}
