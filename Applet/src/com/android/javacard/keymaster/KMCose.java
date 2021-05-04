package com.android.javacard.keymaster;

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
  public static final byte COSE_KEY_TYPE_OCTET_KEY_PAIR = 1;
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


}
