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
 * This class constructs the Cose messages like CoseKey, CoseMac0, MacStructure,
 * CoseSign1, SignStructure, CoseEncrypt, EncryptStructure and ReceipientStructures.
 */
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
  public static final byte[] COSE_TEST_KEY = {(byte) 0xFF, (byte) 0xFE, (byte) 0xEE, (byte) 0x90}; // -70000
  public static final short COSE_KEY_MAX_SIZE = 4;

  //Context strings
  public static final byte[] MAC_CONTEXT = {0x4d, 0x41, 0x43, 0x30}; // MAC0
  //Empty strings
  public static final byte[] EMPTY_MAC_KEY =
      {0x45, 0x6d, 0x70, 0x74, 0x79, 0x20, 0x4d, 0x41, 0x43, 0x20, 0x6b, 0x65, 0x79}; // "Empty MAC key"

  /**
   * Constructs the Cose MAC structure.
   *
   * @param protectedHeader Bstr pointer which holds the protected header.
   * @param extAad          Bstr pointer which holds the external Aad.
   * @param payload         Bstr pointer which holds the payload of the MAC structure.
   * @return KMArray instance of MAC structure.
   */
  public static short constructCoseMacStructure(short protectedHeader, short extAad, short payload) {
    // Create MAC Structure and compute HMAC as per https://tools.ietf.org/html/rfc8152#section-6.3
    //    MAC_structure = [
    //        context : "MAC" / "MAC0",
    //        protected : empty_or_serialized_map,
    //        external_aad : bstr,
    //        payload : bstr
    //   ]
    short arrPtr = KMArray.instance(KMCose.COSE_MAC0_ENTRY_COUNT);
    // 1 - Context
    KMArray.cast(arrPtr).add((short) 0, KMTextString.instance(KMCose.MAC_CONTEXT, (short) 0,
        (short) KMCose.MAC_CONTEXT.length));
    // 2 - Protected headers.
    KMArray.cast(arrPtr).add((short) 1, protectedHeader);
    // 3 - external aad
    KMArray.cast(arrPtr).add((short) 2, extAad);
    // 4 - payload.
    KMArray.cast(arrPtr).add((short) 3, payload);
    return arrPtr;
  }

  /**
   * Constructs the COSE_MAC0 object.
   *
   * @param protectedHeader Bstr pointer which holds the protected header.
   * @param payload         Bstr pointer which holds the payload of the MAC structure.
   * @param tag             Bstr pointer which holds the tag value.
   * @return KMArray instance of COSE_MAC0 object.
   */
  public static short constructCoseMac0(short protectedHeader, short payload, short tag) {
    // Construct Cose_MAC0
    //   COSE_Mac0 = [
    //      protectedHeader,
    //      unprotectedHeader,
    //      payload : bstr / nil,
    //      tag : bstr,
    //   ]
    short arrPtr = KMArray.instance(KMCose.COSE_MAC0_ENTRY_COUNT);
    // 1 - protected headers
    KMArray.cast(arrPtr).add((short) 0, protectedHeader);
    // 2 - unprotected headers
    KMArray.cast(arrPtr).add((short) 1, KMMap.instance((short) 0));
    // 2 - payload
    KMArray.cast(arrPtr).add((short) 2, payload);
    // 3 - tag
    KMArray.cast(arrPtr).add((short) 3, tag);
    // Do encode.
    return arrPtr;
  }

  /**
   * Constructs the instance of KMCoseKey*Value.
   *
   * @param key      value of the key.
   * @param valuePtr instance of one of KMType.
   * @return instance of KMCoseKey*Value object.
   */
  public static short buildCoseKeyTagValue(byte key, short valuePtr) {
    short type = KMType.getType(valuePtr);
    short keyPtr;
    if (key < 0) {
      keyPtr = KMNInteger.uint_8(key);
    } else {
      keyPtr = KMInteger.uint_8(key);
    }
    switch (type) {
      case KMType.INTEGER_TYPE:
        return KMCoseKeyIntegerValue.instance(keyPtr, valuePtr);
      case KMType.NEG_INTEGER_TYPE:
        return KMCoseKeyNIntegerValue.instance(keyPtr, valuePtr);
      case KMType.BYTE_BLOB_TYPE:
        return KMCoseKeyByteBlobValue.instance(keyPtr, valuePtr);
      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return 0;
    }
  }

  /**
   * Constructs the cose key based on input parameters supplied. All the parameters must be instantiated from
   * either KMInteger or KMNInteger or KMByteblob types.
   *
   * @param keyType  instance of one of KMType which holds key type value .
   * @param keyId    instance of one of KMType which holds key identifier value.
   * @param keyAlg   instance of one of KMType which holds key algorithm value.
   * @param keyOps   instance of one of KMType which holds key operations value.
   * @param curve    instance of one of KMType which holds EC curve.
   * @param pubX     instance of one of KMType which holds EC public key's x value.
   * @param pubY     instance of one of KMType which holds EC public key's y value.
   * @param testMode tells if the current key is for test mode or production mode.
   * @return instance of the KMCoseKey object.
   */
  public static short constructCoseKey(short keyType, short keyId, short keyAlg, short keyOps, short curve,
                                       short pubX, short pubY, boolean testMode) {
    short[] coseKeyTags = {
        KMCose.COSE_KEY_KEY_TYPE, keyType, KMType.INVALID_VALUE,
        KMCose.COSE_KEY_KEY_ID, keyId, KMType.INVALID_VALUE,
        KMCose.COSE_KEY_ALGORITHM, keyAlg, KMType.INVALID_VALUE,
        KMCose.COSE_KEY_KEY_OPS, keyOps, KMType.INVALID_VALUE,
        KMCose.COSE_KEY_CURVE, curve, KMType.INVALID_VALUE,
        KMCose.COSE_KEY_PUBKEY_X, pubX, KMType.INVALID_VALUE,
        KMCose.COSE_KEY_PUBKEY_Y, pubY, KMType.INVALID_VALUE,
    };
    short index = 0;
    // var is used to calculate the length of the array.
    short var = 0;
    while (index < coseKeyTags.length) {
      if (coseKeyTags[index + 1] != KMType.INVALID_VALUE) {
        coseKeyTags[(short) (index + 2)] =
            buildCoseKeyTagValue((byte) coseKeyTags[index], coseKeyTags[(short) (index + 1)]);
        var++;
      }
      index += 3;
    }
    if (testMode)
      var++;

    short arrPtr = KMArray.instance(var);
    index = 0;
    // var is used to index the array.
    var = 0;
    while (index < coseKeyTags.length) {
      if (coseKeyTags[index + 2] != KMType.INVALID_VALUE) {
        KMArray.cast(arrPtr).add(var++, coseKeyTags[index + 2]);
      }
      index += 3;
    }
    if (testMode) {
      short testKey =
          KMCoseKeySimpleValue.instance(KMNInteger.uint_32(KMCose.COSE_TEST_KEY, (short) 0),
              KMSimpleValue.instance(KMSimpleValue.NULL));
      KMArray.cast(arrPtr).add(var, testKey);
    }
    return KMCoseKey.instance(arrPtr);
  }
}
