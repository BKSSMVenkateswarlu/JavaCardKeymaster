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

import javacard.framework.Util;

public class KMCose {
  //COSE SIGN1
  public static final byte COSE_SIGN1_ENTRY_COUNT = 4;
  public static final byte COSE_SIGN1_PROTECTED_PARAMS_OFFSET = 0;
  public static final short COSE_SIGN1_UNPROTECTED_PARAMS_OFFSET = 1;
  public static final short COSE_SIGN1_PAYLOAD_OFFSET = 2;
  public static final short COSE_SIGN1_SIGNATURE_OFFSET = 3;
  //COSE MAC0
  public static final short COSE_MAC0_ENTRY_COUNT = 4;
  public static final short COSE_MAC0_PROTECTED_PARAMS_OFFSET = 0;
  public static final short COSE_MAC0_UNPROTECTED_PARAMS_OFFSET = 1;
  public static final short COSE_MAC0_PAYLOAD_OFFSET = 2;
  public static final short COSE_MAC0_TAG_OFFSET = 3;
  //COSE ENCRYPT
  public static final short COSE_ENCRYPT_ENTRY_COUNT = 4;
  public static final short COSE_ENCRYPT_PROTECTED_PARAMS_OFFSET = 0;
  public static final short COSE_ENCRYPT_UNPROTECTED_PARAMS_OFFSET = 1;
  public static final short COSE_ENCRYPT_PAYLOAD_OFFSET = 2;
  public static final short COSE_ENCRYPT_RECIPIENTS_OFFSET = 3;

  //COSE Labels
  public static final byte COSE_LABEL_ALGORITHM = 1;
  public static final byte COSE_LABEL_KEYID = 4;
  public static final byte COSE_LABEL_IV = 5;
  public static final byte COSE_LABEL_COSE_KEY = (byte) 0xFF; // -1

  //COSE Algorithms
  public static final byte COSE_ALG_AES_GCM_256 = 3; //AES-GCM mode w/ 256-bit key, 128-bit tag.
  public static final byte COSE_ALG_HMAC_256 = 5; //HMAC w/ SHA-256
  public static final byte COSE_ALG_ES256 = (byte) 0xF9; // ECDSA w/ SHA-256; -7
  public static final byte COSE_ALG_ECDH_ES_HKDF_256 = (byte) 0xE7; // ECDH-EC+HKDF-256; -25

  //COSE P256 EC Curve
  public static final byte COSE_ECCURVE_256 = 1;

  //COSE key types
  public static final byte COSE_KEY_TYPE_EC2 = 2;
  public static final byte COSE_KEY_TYPE_SYMMETRIC_KEY = 4;

  //COSE Key Operations
  public static final byte COSE_KEY_OP_SIGN = 1;
  public static final byte COSE_KEY_OP_VERIFY = 2;
  public static final byte COSE_KEY_OP_ENCRYPT = 3;
  public static final byte COSE_KEY_OP_DECRYPT = 4;

  // AES GCM
  public static final short AES_GCM_NONCE_LENGTH = 12;
  public static final short AES_GCM_TAG_SIZE = 16;
  public static final short AES_GCM_KEY_SIZE = 32;
  public static final short AES_GCM_KEY_SIZE_BITS = 256;
  // Cose key parameters.
  public static final byte COSE_KEY_KEY_TYPE = 1;
  public static final byte COSE_KEY_KEY_ID = 2;
  public static final byte COSE_KEY_ALGORITHM = 3;
  public static final byte COSE_KEY_KEY_OPS = 4;
  public static final byte COSE_KEY_CURVE = -1;
  public static final byte COSE_KEY_PUBKEY_X = -2;
  public static final byte COSE_KEY_PUBKEY_Y = -3;
  public static final byte COSE_KEY_PRIV_KEY = -4;

  //Context strings
  private static final byte[] MAC_CONTEXT = {0x4d, 0x41, 0x43, 0x30}; // MAC0
  //Empty strings
  private static final byte[] EMPTY_MAC_KEY =
      {0x45, 0x6d, 0x70, 0x74, 0x79, 0x20, 0x4d, 0x41, 0x43, 0x20, 0x6b, 0x65, 0x79}; // "Empty MAC key"

  private short getIntegerInstance(byte value) {
    short ptr;
    if (value >= 0)
      ptr = KMInteger.uint_8(value);
    else
      ptr = KMNInteger.uint_8(value);

    return ptr;
  }

  //TODO Comments
  public void generateCoseMac0Mac(byte[] macKey, short macKeyOff, short macKeyLen, byte[] extAad, short extAadOff,
                                  short extAadLen, byte[] payload, short payloadOff, short payloadLen,
                                  byte[] out, short outOff) {
    //TODO Complete this function.
    if (macKeyLen == 0) {
      Util.arrayCopyNonAtomic(EMPTY_MAC_KEY, (short) 0, out, outOff, (short) EMPTY_MAC_KEY.length);
    }
    // Create MAC Structure and compute HMAC as per https://tools.ietf.org/html/rfc8152#section-6.3
    short arrPtr = KMArray.instance(COSE_MAC0_ENTRY_COUNT);
    KMArray.cast(arrPtr).add((short) 0, KMTextString.instance(MAC_CONTEXT, (short) 0, (short) MAC_CONTEXT.length));
    short mapPtr = KMMap.instance((short) 1);
    KMMap.cast(mapPtr).add((short) 0, getIntegerInstance(COSE_LABEL_ALGORITHM), getIntegerInstance(COSE_ALG_HMAC_256));
    KMMap.cast(mapPtr).canonicalize();
    KMArray.cast(arrPtr).add((short) 1, mapPtr);
    KMArray.cast(arrPtr).add((short) 2, KMByteBlob.instance(extAad, extAadOff, extAadLen));
    KMArray.cast(arrPtr).add((short) 3, KMByteBlob.instance(payload, payloadOff, payloadLen));
  }
}
