/*
 * Copyright(C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" (short)0IS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.HMACKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;

public class KMJCOPSimProvider implements KMSEProvider {
  // static final variables
  // --------------------------------------------------------------
  // P-256 Curve Parameters
  static final byte[] secp256r1_P = {
          (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
          (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
          (byte) 0xFF, (byte) 0xFF };

  static final byte[] secp256r1_A = {
          (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
          (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
          (byte) 0xFF, (byte) 0xFC };

  static final byte[] secp256r1_B = {
          (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA,
          (byte) 0x3A, (byte) 0x93, (byte) 0xE7, (byte) 0xB3, (byte) 0xEB,
          (byte) 0xBD, (byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86,
          (byte) 0xBC, (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0,
          (byte) 0xCC, (byte) 0x53, (byte) 0xB0, (byte) 0xF6, (byte) 0x3B,
          (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27, (byte) 0xD2,
          (byte) 0x60, (byte) 0x4B };

  static final byte[] secp256r1_S = {
          (byte) 0xC4, (byte) 0x9D, (byte) 0x36, (byte) 0x08, (byte) 0x86,
          (byte) 0xE7, (byte) 0x04, (byte) 0x93, (byte) 0x6A, (byte) 0x66,
          (byte) 0x78, (byte) 0xE1, (byte) 0x13, (byte) 0x9D, (byte) 0x26,
          (byte) 0xB7, (byte) 0x81, (byte) 0x9F, (byte) 0x7E, (byte) 0x90 };

  // Uncompressed form
  static final byte[] secp256r1_UCG = {
          (byte) 0x04, (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2,
          (byte) 0xE1, (byte) 0x2C, (byte) 0x42, (byte) 0x47, (byte) 0xF8,
          (byte) 0xBC, (byte) 0xE6, (byte) 0xE5, (byte) 0x63, (byte) 0xA4,
          (byte) 0x40, (byte) 0xF2, (byte) 0x77, (byte) 0x03, (byte) 0x7D,
          (byte) 0x81, (byte) 0x2D, (byte) 0xEB, (byte) 0x33, (byte) 0xA0,
          (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45, (byte) 0xD8,
          (byte) 0x98, (byte) 0xC2, (byte) 0x96, (byte) 0x4F, (byte) 0xE3,
          (byte) 0x42, (byte) 0xE2, (byte) 0xFE, (byte) 0x1A, (byte) 0x7F,
          (byte) 0x9B, (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A,
          (byte) 0x7C, (byte) 0x0F, (byte) 0x9E, (byte) 0x16, (byte) 0x2B,
          (byte) 0xCE, (byte) 0x33, (byte) 0x57, (byte) 0x6B, (byte) 0x31,
          (byte) 0x5E, (byte) 0xCE, (byte) 0xCB, (byte) 0xB6, (byte) 0x40,
          (byte) 0x68, (byte) 0x37, (byte) 0xBF, (byte) 0x51, (byte) 0xF5 };

  static final byte[] secp256r1_N = {
          (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF,
          (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
          (byte) 0xFF, (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD,
          (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84, (byte) 0xF3,
          (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, (byte) 0x63,
          (byte) 0x25, (byte) 0x51 };
  static final short secp256r1_H = 1;
  // --------------------------------------------------------------
  public static final short AES_GCM_TAG_LENGTH = 12;
  public static final short AES_GCM_NONCE_LENGTH = 12;
  public static final byte KEYSIZE_128_OFFSET = 0x00;
  public static final byte KEYSIZE_256_OFFSET = 0x01;
  public static final short TMP_ARRAY_SIZE = 256; // TODO
  public static final short AUTH_DATA_LEN = 650; // TODO
  public static final short MAX_RND_NUM_SIZE = 64;
  public static final short ENTROPY_POOL_SIZE = 16;
  public static final byte[] aesICV = {
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

  final byte[] CIPHER_ALGS = {
          Cipher.ALG_AES_BLOCK_128_CBC_NOPAD,
          Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, Cipher.ALG_DES_CBC_NOPAD,
          Cipher.ALG_DES_ECB_NOPAD, Cipher.ALG_AES_CTR, Cipher.ALG_RSA_PKCS1,// NoDigest
          Cipher.ALG_RSA_PKCS1_OAEP, // SHA256
          Cipher.ALG_RSA_NOPAD, // NoDigest
          // AEADCipher.ALG_AES_CCM,
          AEADCipher.ALG_AES_GCM };
  final byte[] SIG_ALGS = {
          // Signature.ALG_AES_CMAC_128,
          Signature.ALG_RSA_SHA_256_PKCS1, Signature.ALG_RSA_SHA_256_PKCS1_PSS,
          Signature.ALG_ECDSA_SHA_256, Signature.ALG_HMAC_SHA_256,
          KMRsa2048NoDigestSignature.ALG_RSA_SIGN_NOPAD,
          KMRsa2048NoDigestSignature.ALG_RSA_PKCS1_NODIGEST,
          KMEcdsa256NoDigestSignature.ALG_ECDSA_NODIGEST};

  // AESKey
  private AESKey aesKeys[];
  // DES3Key
  private DESKey triDesKey;
  // HMACKey
  private HMACKey hmacKey;
  // RSA Key Pair
  private KeyPair rsaKeyPair;
  // EC Key Pair.
  private KeyPair ecKeyPair;
  // Temporary array.
  public byte[] tmpArray;
  // public byte[] tmpAuthDataArray;
  private short tmpArrayIndex;
  // This is used for internal encryption/decryption operations.
  private static AEADCipher aesGcmCipher;
  // Cipher pool
  private Object[] cipherPool;
  // Signature pool
  private Object[] sigPool;
  // KMOperationImpl pool
  private Object[] operationPool;

  private static Signature kdf;

  private static Signature hmacSignature;

  // RNG
  private static byte[] rngCounter;
  private static AESKey aesRngKey;
  private static Cipher aesRngCipher;
  private static byte[] entropyPool;
  private static byte[] rndNum;

  private static KMJCOPSimProvider jcopProvider = null;

  public static KMJCOPSimProvider getInstance() {
    if (jcopProvider == null)
      jcopProvider = new KMJCOPSimProvider();
    return jcopProvider;
  }

  private KMJCOPSimProvider() {
    // Re-usable AES,DES and HMAC keys in persisted memory.
    aesKeys = new AESKey[2];
    aesKeys[KEYSIZE_128_OFFSET] = (AESKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
    aesKeys[KEYSIZE_256_OFFSET] = (AESKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
    triDesKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
            KeyBuilder.LENGTH_DES3_3KEY, false);
    hmacKey = (HMACKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_HMAC, (short) 512, false);
    rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
    initECKey();

    // Re-usable cipher and signature instances
    cipherPool = new Object[(short) (CIPHER_ALGS.length * 4)];
    sigPool = new Object[(short) (SIG_ALGS.length * 4)];
    operationPool = new Object[4];
    // Creates an instance of each cipher algorithm once.
    initializeCipherPool();
    // Creates an instance of each signature algorithm once.
    initializeSigPool();
    initializeOperationPool();

    kdf = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
    hmacSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);

    // Temporary transient array created to use locally inside functions.
    tmpArray = JCSystem.makeTransientByteArray(TMP_ARRAY_SIZE,
            JCSystem.CLEAR_ON_DESELECT);
    // tmpAuthDataArray = JCSystem.makeTransientByteArray(AUTH_DATA_LEN,
    // JCSystem.CLEAR_ON_DESELECT);

    // Random number generator initialisation.
    rndNum = JCSystem.makeTransientByteArray(MAX_RND_NUM_SIZE,
            JCSystem.CLEAR_ON_RESET);
    entropyPool = JCSystem.makeTransientByteArray(ENTROPY_POOL_SIZE,
            JCSystem.CLEAR_ON_RESET);
    rngCounter = JCSystem.makeTransientByteArray((short) 8,
            JCSystem.CLEAR_ON_RESET);
    initEntropyPool(entropyPool);
    try {
      aesRngCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD,
              false);
    } catch (CryptoException exp) {
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }
    aesRngKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
            KeyBuilder.LENGTH_AES_128, false);
  }

  public short alloc(short length) {
    if (((short) (tmpArrayIndex + length)) > tmpArray.length) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    tmpArrayIndex += length;
    return (short) (tmpArrayIndex - length);
  }

  public void clean() {
    Util.arrayFillNonAtomic(tmpArray, (short) 0, tmpArrayIndex, (byte) 0);
    tmpArrayIndex = 0;
  }

  private void initECKey() {
    ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    ECPrivateKey privKey = (ECPrivateKey) ecKeyPair.getPrivate();
    ECPublicKey pubkey = (ECPublicKey) ecKeyPair.getPublic();
    pubkey.setFieldFP(secp256r1_P, (short) 0, (short) secp256r1_P.length);
    pubkey.setA(secp256r1_A, (short) 0, (short) secp256r1_A.length);
    pubkey.setB(secp256r1_B, (short) 0, (short) secp256r1_B.length);
    pubkey.setG(secp256r1_UCG, (short) 0, (short) secp256r1_UCG.length);
    pubkey.setK(secp256r1_H);
    pubkey.setR(secp256r1_N, (short) 0, (short) secp256r1_N.length);

    privKey.setFieldFP(secp256r1_P, (short) 0, (short) secp256r1_P.length);
    privKey.setA(secp256r1_A, (short) 0, (short) secp256r1_A.length);
    privKey.setB(secp256r1_B, (short) 0, (short) secp256r1_B.length);
    privKey.setG(secp256r1_UCG, (short) 0, (short) secp256r1_UCG.length);
    privKey.setK(secp256r1_H);
    privKey.setR(secp256r1_N, (short) 0, (short) secp256r1_N.length);
  }

  private boolean isCipherAlgorithm(byte alg) {
    short index = 0;
    while (index < CIPHER_ALGS.length) {
      if (CIPHER_ALGS[index++] == alg) {
        return true;
      }
    }
    return false;
  }

  private boolean isSignerAlgorithm(byte alg) {
    short index = 0;
    while (index < SIG_ALGS.length) {
      if (SIG_ALGS[index++] == alg) {
        return true;
      }
    }
    return false;
  }

  private void initializeOperationPool() {
    short index = 0;
    while (index < 4) {
      operationPool[index] = new KMInstance();
      ((KMInstance) operationPool[index]).instanceCount = 1;
      ((KMInstance) operationPool[index]).object = new KMOperationImpl();
      ((KMInstance) operationPool[index]).reserved = 0;
      index++;
    }
  }

  // Create a signature instance of each algorithm once.
  private void initializeSigPool() {
    short index = 0;
    while (index < SIG_ALGS.length) {
      sigPool[index] = new KMInstance();
      ((KMInstance) sigPool[index]).instanceCount = 1;
      ((KMInstance) sigPool[index]).object = getSignatureInstance(SIG_ALGS[index]);// Signature.getInstance(SIG_ALGS[index],
                                                                                   // false);
      ((KMInstance) sigPool[index]).reserved = 0;
      index++;
    }
  }

  private Signature getSignatureInstance(byte alg) {
    if (KMRsa2048NoDigestSignature.ALG_RSA_SIGN_NOPAD == alg
            || KMRsa2048NoDigestSignature.ALG_RSA_PKCS1_NODIGEST == alg) {
      return new KMRsa2048NoDigestSignature(alg);
    } else if(KMEcdsa256NoDigestSignature.ALG_ECDSA_NODIGEST == alg) {
      return new KMEcdsa256NoDigestSignature(alg);
    } else {
      return Signature.getInstance(alg, false);
    }
  }

  private Cipher getCipherInstance(byte alg) {
    if (Cipher.ALG_RSA_PKCS1_OAEP == alg) {
      return Cipher.getInstance(Cipher.CIPHER_RSA,
              Cipher.PAD_PKCS1_OAEP_SHA256, false);
    } else {
      return Cipher.getInstance(alg, false);
    }
  }

  private byte getCipherAlgorithm(Cipher c) {
    if (0 == c.getAlgorithm()) {
      if (Cipher.PAD_PKCS1_OAEP_SHA256 == c.getPaddingAlgorithm()) {
        return Cipher.ALG_RSA_PKCS1_OAEP;
      } else {
        // TODO: What should we do here.
        KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
        return 0;
      }
    } else {
      return c.getAlgorithm();
    }
  }

  // Create a cipher instance of each algorithm once.
  private void initializeCipherPool() {
    short index = 0;
    while (index < CIPHER_ALGS.length) {
      cipherPool[index] = new KMInstance();
      ((KMInstance) cipherPool[index]).instanceCount = 1;
      ((KMInstance) cipherPool[index]).object = getCipherInstance(CIPHER_ALGS[index]);
      ((KMInstance) cipherPool[index]).reserved = 0;
      index++;
    }
  }

  private KMOperationImpl getOperationInstanceFromPool() {
    return (KMOperationImpl) getInstanceFromPool(operationPool, (byte) 0x00);
  }

  public void releaseOperationInstance(KMOperationImpl operation) {
    releaseInstance(operationPool, operation);
  }

  private Signature getSignatureInstanceFromPool(byte alg) {
    return (Signature) getInstanceFromPool(sigPool, alg);
  }

  public void releaseSignatureInstance(Signature signer) {
    releaseInstance(sigPool, signer);
  }

  private Cipher getCipherInstanceFromPool(byte alg) {
    return (Cipher) getInstanceFromPool(cipherPool, alg);
  }

  public void releaseCipherInstance(Cipher cipher) {
    releaseInstance(cipherPool, cipher);
  }

  // This pool implementation can create a maximum of total 4 instances per
  // algorithm.
  // This function returns the unreserved Cipher/Signature instance of type
  // algorithm from pool. If
  // there is no unreserved cipher/signature instance of algorithm type in the
  // pool and Cipher/Signature
  // algorithm instance count is less than 4 then it creates and returns a new
  // Cipher/Signature
  // instance of algorithm type. If there is no unreserved cipher/signature and
  // maximum instance
  // count reaches four it throws exception.
  private Object getInstanceFromPool(Object[] pool, byte alg) {
    short index = 0;
    short instanceCount = 0;
    Object object = null;
    boolean isCipher = isCipherAlgorithm(alg);
    boolean isSigner = isSignerAlgorithm(alg);
    short len = (short) pool.length;
    while (index < len) {
      if (null == pool[index]) {
        // No instance of cipher/signature with this algorithm is found
        if (instanceCount < 4) {
          pool[index] = new KMInstance();
          JCSystem.beginTransaction();
          ((KMInstance) pool[index]).instanceCount = (byte) (++instanceCount);
          if (isCipher)
            ((KMInstance) pool[index]).object = object = getCipherInstance(alg);
          else
            // Signature
            ((KMInstance) pool[index]).object = object = getSignatureInstance(alg);
          ((KMInstance) pool[index]).reserved = 1;
          JCSystem.commitTransaction();
          break;
        } else {
          // Cipher/Signature instance count reached its maximum limit.
          break;
        }
      }
      object = ((KMInstance) pool[index]).object;
      if ((isCipher && (alg == getCipherAlgorithm((Cipher) object)))
              || ((isSigner && (alg == ((Signature) object).getAlgorithm())))) {
        instanceCount = ((KMInstance) pool[index]).instanceCount;
        if (((KMInstance) pool[index]).reserved == 0) {
          JCSystem.beginTransaction();
          ((KMInstance) pool[index]).reserved = 1;
          JCSystem.commitTransaction();
          break;
        }
      } else {
        if (!isCipher && !isSigner) {
          // OperationImpl
          if (((KMInstance) pool[index]).reserved == 0) {
            JCSystem.beginTransaction();
            ((KMInstance) pool[index]).reserved = 1;
            JCSystem.commitTransaction();
            break;
          }
        }
      }
      object = null;
      index++;
    }
    return object;
  }

  private void releaseInstance(Object[] pool, Object object) {
    short index = 0;
    short len = (short) pool.length;
    while (index < len) {
      if (pool[index] != null) {
        if (object == ((KMInstance) pool[index]).object) {
          JCSystem.beginTransaction();
          ((KMInstance) pool[index]).reserved = 0;
          JCSystem.commitTransaction();
          break;
        }
      } else {
        // Reached end.
        break;
      }
      index++;
    }
  }

  public AESKey createAESKey(short keysize) {
    newRandomNumber(tmpArray, (short) 0, (short) (keysize / 8));
    return createAESKey(tmpArray, (short) 0, (short) (keysize / 8));
  }

  public AESKey createAESKey(byte[] buf, short startOff, short length) {
    AESKey key = null;
    short keysize = (short) (length * 8);
    if (keysize == 128) {
      key = (AESKey) aesKeys[KEYSIZE_128_OFFSET];
      key.setKey(buf, (short) startOff);
    } else if (keysize == 256) {
      key = (AESKey) aesKeys[KEYSIZE_256_OFFSET];
      key.setKey(buf, (short) startOff);
    }
    return key;
  }

  public DESKey createTDESKey() {
    newRandomNumber(tmpArray, (short) 0,
            (short) (KeyBuilder.LENGTH_DES3_3KEY / 8));
    return createTDESKey(tmpArray, (short) 0,
            (short) (KeyBuilder.LENGTH_DES3_3KEY / 8));
  }

  public DESKey createTDESKey(byte[] secretBuffer, short secretOff,
          short secretLength) {
    triDesKey.setKey(secretBuffer, secretOff);
    return triDesKey;
  }

  public HMACKey createHMACKey(short keysize) {
    if ((keysize % 8 != 0) || !(keysize >= 64 && keysize <= 512)) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    newRandomNumber(tmpArray, (short) 0, (short) (keysize / 8));
    return createHMACKey(tmpArray, (short) 0, (short) (keysize / 8));
  }

  public HMACKey createHMACKey(byte[] secretBuffer, short secretOff,
          short secretLength) {
    hmacKey.setKey(secretBuffer, secretOff, secretLength);
    return hmacKey;
  }

  public KeyPair createRsaKeyPair() {
    rsaKeyPair.genKeyPair();
    return rsaKeyPair;
  }

  public RSAPrivateKey createRsaKey(byte[] modBuffer, short modOff,
          short modLength, byte[] privBuffer, short privOff, short privLength) {
    RSAPrivateKey privKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
    privKey.setExponent(privBuffer, privOff, privLength);
    privKey.setModulus(modBuffer, modOff, modLength);
    return privKey;
  }

  public KeyPair createECKeyPair() {
    ecKeyPair.genKeyPair();
    return ecKeyPair;
  }

  public ECPrivateKey createEcKey(byte[] privBuffer, short privOff,
          short privLength) {
    ECPrivateKey privKey = (ECPrivateKey) ecKeyPair.getPrivate();
    privKey.setS(privBuffer, privOff, privLength);
    return privKey;
  }

  @Override
  public short createSymmetricKey(byte alg, short keysize, byte[] buf,
          short startOff) {
    switch (alg) {
    case KMType.AES:
      AESKey aesKey = createAESKey(keysize);
      return aesKey.getKey(buf, startOff);
    case KMType.DES:
      DESKey desKey = createTDESKey();
      return desKey.getKey(buf, startOff);
    case KMType.HMAC:
      HMACKey hmacKey = createHMACKey(keysize);
      return hmacKey.getKey(buf, startOff);
    default:
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
      break;
    }
    return 0;
  }

  @Override
  public void createAsymmetricKey(byte alg, byte[] privKeyBuf,
          short privKeyStart, short privKeyLength, byte[] pubModBuf,
          short pubModStart, short pubModLength, short[] lengths) {
    switch (alg) {
    case KMType.RSA:
      KeyPair rsaKey = createRsaKeyPair();
      RSAPrivateKey privKey = (RSAPrivateKey) rsaKey.getPrivate();
      lengths[0] = privKey.getExponent(privKeyBuf, privKeyStart);
      lengths[1] = privKey.getModulus(pubModBuf, pubModStart);
      if (lengths[0] > privKeyLength || lengths[1] > pubModLength) {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
      break;
    case KMType.EC:
      KeyPair ecKey = createECKeyPair();
      ECPublicKey ecPubKey = (ECPublicKey) ecKey.getPublic();
      ECPrivateKey ecPrivKey = (ECPrivateKey) ecKey.getPrivate();
      lengths[0] = ecPrivKey.getS(privKeyBuf, privKeyStart);
      lengths[1] = ecPubKey.getW(pubModBuf, pubModStart);
      if (lengths[0] > privKeyLength || lengths[1] > pubModLength) {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
      break;
    default:
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
      break;
    }
  }

  @Override
  public boolean importSymmetricKey(byte alg, short keysize, byte[] buf,
          short startOff, short length) {
    switch (alg) {
    case KMType.AES:
      createAESKey(buf, startOff, length);
      break;
    case KMType.DES:
      createTDESKey(buf, startOff, length);
      break;
    case KMType.HMAC:
      createHMACKey(buf, startOff, length);
      break;
    default:
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
      break;
    }
    return true;
  }

  /*
   * @Override public boolean importAsymmetricKey(byte alg, byte[] buf, short
   * start, short length, byte[] privKeyBuf, short privKeyStart, short
   * privKeyLength, byte[] pubModBuf, short pubModStart, short pubModLength) {
   * return false; }
   */

  @Override
  public boolean importAsymmetricKey(byte alg, byte[] privKeyBuf,
          short privKeyStart, short privKeyLength, byte[] pubModBuf,
          short pubModStart, short pubModLength) {
    switch (alg) {
    case KMType.RSA:
      createRsaKey(pubModBuf, pubModStart, pubModLength, privKeyBuf,
              privKeyStart, privKeyLength);
      break;
    case KMType.EC:
      createEcKey(privKeyBuf, privKeyStart, privKeyLength);
      break;
    default:
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
      break;
    }
    return true;
  }

  private void initEntropyPool(byte[] pool) {
    byte index = 0;
    RandomData trng;
    while (index < rngCounter.length) {
      rngCounter[index++] = 0;
    }
    try {
      trng = RandomData.getInstance(RandomData.ALG_TRNG);
      trng.nextBytes(pool, (short) 0, (short) pool.length);
    } catch (CryptoException exp) {
      if (exp.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
        // TODO change this when possible
        // simulator does not support TRNG algorithm. So, PRNG algorithm
        // (deprecated) is used.
        trng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        trng.nextBytes(pool, (short) 0, (short) pool.length);
      } else {
        // TODO change this to proper error code
        ISOException.throwIt(ISO7816.SW_UNKNOWN);
      }
    }
  }

  // Generate a secure random number from existing entropy pool. This uses aes
  // cbc algorithm with
  // 8 byte rngCounter and 16 byte block size.
  @Override
  public void newRandomNumber(byte[] num, short startOff, short length) {
    KMRepository repository = KMRepository.instance();
    byte[] bufPtr = repository.getHeap();
    short countBufInd = repository.alloc(KMKeymasterApplet.AES_BLOCK_SIZE);
    short randBufInd = repository.alloc(KMKeymasterApplet.AES_BLOCK_SIZE);
    short len = KMKeymasterApplet.AES_BLOCK_SIZE;
    aesRngKey.setKey(entropyPool, (short) 0);
    aesRngCipher.init(aesRngKey, Cipher.MODE_ENCRYPT, aesICV, (short) 0,
            (short) 16);
    while (length > 0) {
      if (length < len)
        len = length;
      // increment rngCounter by one
      incrementCounter();
      // copy the 8 byte rngCounter into the 16 byte rngCounter buffer.
      Util.arrayCopy(rngCounter, (short) 0, bufPtr, countBufInd,
              (short) rngCounter.length);
      // encrypt the rngCounter buffer with existing entropy which forms the aes
      // key.
      aesRngCipher.doFinal(bufPtr, countBufInd,
              KMKeymasterApplet.AES_BLOCK_SIZE, bufPtr, randBufInd);
      // copy the encrypted rngCounter block to buffer passed in the argument
      Util.arrayCopy(bufPtr, randBufInd, num, startOff, len);
      length = (short) (length - len);
      startOff = (short) (startOff + len);
    }
  }

  // increment 8 byte rngCounter by one
  private void incrementCounter() {
    // start with least significant byte
    short index = (short) (rngCounter.length - 1);
    while (index >= 0) {
      // if the msb of current byte is set then it will be negative
      if (rngCounter[index] < 0) {
        // then increment the rngCounter
        rngCounter[index]++;
        // is the msb still set? i.e. no carry over
        if (rngCounter[index] < 0)
          break; // then break
        else
          index--; // else go to the higher order byte
      } else {
        // if msb is not set then increment the rngCounter
        rngCounter[index]++;
        break;
      }
    }
  }

  @Override
  public void addRngEntropy(byte[] num, short offset, short length) {
    // Maximum length can be 256 bytes. But currently we support max 32 bytes
    // seed.
    // Get existing entropy pool.
    if (length > 32)
      length = 32;
    // Create new temporary pool.
    // Populate the new pool with the entropy which is derived from current
    // entropy pool.
    newRandomNumber(rndNum, (short) 0, (short) entropyPool.length);
    // Copy the entropy to the current pool - updates the entropy pool.
    Util.arrayCopy(rndNum, (short) 0, entropyPool, (short) 0,
            (short) entropyPool.length);
    short index = 0;
    short randIndex = 0;
    // XOR the seed received from the master in the entropy pool - 16 bytes
    // (entPool.length).
    // at a time.
    while (index < length) {
      entropyPool[randIndex] = (byte) (entropyPool[randIndex] ^ num[(short) (offset + index)]);
      randIndex++;
      index++;
      if (randIndex >= entropyPool.length) {
        randIndex = 0;
      }
    }
  }

  /*
   * @Override public byte[] getTrueRandomNumber(short len) { //TODO ignore the
   * size as simulator only supports 128 bit entropy return entropyPool; }
   */
  @Override
  public short aesGCMEncrypt(byte[] aesKey, short aesKeyStart, short aesKeyLen,
          byte[] secret, short secretStart, short secretLen, byte[] encSecret,
          short encSecretStart, byte[] nonce, short nonceStart, short nonceLen,
          byte[] authData, short authDataStart, short authDataLen,
          byte[] authTag, short authTagStart, short authTagLen) {

    if (authTagLen != AES_GCM_TAG_LENGTH) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    if (nonceLen != AES_GCM_NONCE_LENGTH) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if (aesGcmCipher == null) {
      aesGcmCipher = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM,
              false);
    }
    AESKey key = createAESKey(aesKey, aesKeyStart, aesKeyLen);
    try {
      aesGcmCipher.init(key, Cipher.MODE_ENCRYPT, nonce, nonceStart, nonceLen);
    } catch (CryptoException exp) {
      KMException.throwIt(exp.getReason());
    }
    aesGcmCipher.updateAAD(authData, authDataStart, authDataLen);
    short ciphLen = aesGcmCipher.doFinal(secret, secretStart, secretLen,
            encSecret, encSecretStart);
    // TODO if this retrieveTag fails, then allocate
    // The tag buffer must be exact size otherwise simulator returns 0 tag.
    aesGcmCipher.retrieveTag(authTag, authTagStart, authTagLen);
    return ciphLen;
  }

  @Override
  public boolean aesGCMDecrypt(byte[] aesKey, short aesKeyStart,
          short aesKeyLen, byte[] encSecret, short encSecretStart,
          short encSecretLen, byte[] secret, short secretStart, byte[] nonce,
          short nonceStart, short nonceLen, byte[] authData,
          short authDataStart, short authDataLen, byte[] authTag,
          short authTagStart, short authTagLen) {
    // TODO Test and remove unnecessary trasientArrays.
    if (aesGcmCipher == null) {
      aesGcmCipher = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM,
              false);
    }
    // allocate aad buffer of exact size - otherwise simulator throws exception
    // byte[] aad = JCSystem.makeTransientByteArray(authDataLen,
    // JCSystem.CLEAR_ON_RESET);

    // Util.arrayCopyNonAtomic(authData, authDataStart, tmpAuthDataArray,
    // (short) 0,
    // authDataLen);
    // allocate tag of exact size.
    // byte[] tag = JCSystem.makeTransientByteArray(AES_GCM_TAG_LENGTH,
    // JCSystem.CLEAR_ON_RESET);
    // Util.arrayCopyNonAtomic(authTag, authTagStart, tmpArray, (short) 0,
    // authTagLen);
    boolean verification = false;
    AESKey key = createAESKey(aesKey, aesKeyStart, aesKeyLen);
    try {
      aesGcmCipher.init(key, Cipher.MODE_DECRYPT, nonce, nonceStart, nonceLen);
      aesGcmCipher.updateAAD(authData, authDataStart, authDataLen);
      // byte[] plain = JCSystem.makeTransientByteArray(encSecretLen,
      // JCSystem.CLEAR_ON_RESET);
      // encrypt the secret
      aesGcmCipher.doFinal(encSecret, encSecretStart, encSecretLen, secret,
              secretStart);
      verification = aesGcmCipher.verifyTag(authTag, authTagStart, (short) 12,
              (short) 12);
    } catch (CryptoException exp) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    return verification;
  }

  public HMACKey cmacKdf(byte[] keyMaterial, short keyMaterialStart,
          short keyMaterialLen, byte[] label, short labelStart, short labelLen,
          byte[] context, short contextStart, short contextLength) {
    // This is hardcoded to requirement - 32 byte output with two concatenated
    // 16 bytes K1 and K2.
    final byte n = 2; // hardcoded
    final byte[] L = {
            0, 0, 1, 0 }; // [L] 256 bits - hardcoded 32 bits as per
                          // reference impl in keymaster.
    final byte[] zero = {
      0 }; // byte
    short iBufLen = 4;
    short keyOutLen = n * 16;
    // [i] counter - 32 bits
    Util.arrayFillNonAtomic(tmpArray, (short) 0, iBufLen, (byte) 0);
    // byte[] iBuf = new byte[] { 0, 0, 0, 0 }; // [i] counter - 32 bits
    // byte[] keyOut = new byte[(short) (n * 16)];
    Util.arrayFillNonAtomic(tmpArray, (short) iBufLen, keyOutLen, (byte) 0);
    // Signature prf = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
    aesKeys[KEYSIZE_256_OFFSET].setKey(keyMaterial, (short) keyMaterialStart);
    // AESKey key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
    // KeyBuilder.LENGTH_AES_256, false);
    // key.setKey(keyMaterial, (short) 0);
    kdf.init(aesKeys[KEYSIZE_256_OFFSET], Signature.MODE_SIGN);
    byte i = 1;
    short pos = 0;
    while (i <= n) {
      tmpArray[3] = i;
      kdf.update(tmpArray, (short) 0, (short) iBufLen); // 4 bytes of iBuf with
                                                        // counter in
      // it
      kdf.update(label, labelStart, (short) labelLen); // label
      kdf.update(zero, (short) 0, (short) 1); // 1 byte of 0x00
      kdf.update(context, contextStart, contextLength); // context
      pos = kdf
              .sign(L, (short) 0, (short) 4, tmpArray, (short) (iBufLen + pos)); // 4
                                                                                 // bytes
                                                                                 // of
                                                                                 // L
                                                                                 // -
      // signature of 16
      // bytes
      i++;
    }
    return createHMACKey(tmpArray, (short) iBufLen, (short) keyOutLen);
  }

  public short hmacSign(HMACKey key, byte[] data, short dataStart,
          short dataLength, byte[] mac, short macStart) {
    hmacSignature.init(key, Signature.MODE_SIGN);
    return hmacSignature.sign(data, dataStart, dataLength, mac, macStart);
  }

  public boolean hmacVerify(HMACKey key, byte[] data, short dataStart,
          short dataLength, byte[] mac, short macStart, short macLength) {
    hmacSignature.init(key, Signature.MODE_VERIFY);
    return hmacSignature.verify(data, dataStart, dataLength, mac, macStart,
            macLength);
  }

  @Override
  public short hmacSign(byte[] keyBuf, short keyStart, short keyLength,
          byte[] data, short dataStart, short dataLength, byte[] mac,
          short macStart) {
    HMACKey key = createHMACKey(keyBuf, keyStart, keyLength);
    return hmacSign(key, data, dataStart, dataLength, mac, macStart);
  }

  @Override
  public boolean hmacVerify(byte[] keyBuf, short keyStart, short keyLength,
          byte[] data, short dataStart, short dataLength, byte[] mac,
          short macStart, short macLength) {
    HMACKey key = createHMACKey(keyBuf, keyStart, keyLength);
    return hmacVerify(key, data, dataStart, dataLength, mac, macStart,
            macLength);
  }

  @Override
  public short rsaDecipherOAEP256(byte[] secret, short secretStart,
          short secretLength, byte[] modBuffer, short modOff, short modLength,
          byte[] inputDataBuf, short inputDataStart, short inputDataLength,
          byte[] outputDataBuf, short outputDataStart) {
    Cipher.OneShot cipher = null;
    RSAPrivateKey key = (RSAPrivateKey) rsaKeyPair.getPrivate();
    key.setExponent(secret, secretStart, secretLength);
    key.setModulus(modBuffer, modOff, modLength);
    try {
      cipher = Cipher.OneShot.open(Cipher.CIPHER_RSA,
              Cipher.PAD_PKCS1_OAEP_SHA256);
      cipher.init(key, Cipher.MODE_DECRYPT);
      return cipher.doFinal(inputDataBuf, inputDataStart, inputDataLength,
              outputDataBuf, (short) outputDataStart);

    } catch (SecurityException e) {
      KMException.throwIt(KMError.SECURE_HW_ACCESS_DENIED);
    } catch (CryptoException e) {
      KMException.throwIt(e.getReason());
    } finally {
      if (cipher != null)
        cipher.close();
    }
    return 0;
  }

  @Override
  public short rsaSignPKCS1256(byte[] secret, short secretStart,
          short secretLength, byte[] modBuffer, short modOff, short modLength,
          byte[] inputDataBuf, short inputDataStart, short inputDataLength,
          byte[] outputDataBuf, short outputDataStart) {
    Signature.OneShot signer = null;
    RSAPrivateKey key = (RSAPrivateKey) rsaKeyPair.getPrivate();
    key.setExponent(secret, secretStart, secretLength);
    key.setModulus(modBuffer, modOff, modLength);
    try {
      signer = Signature.OneShot.open(MessageDigest.ALG_SHA_256,
              Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1);
      signer.init(key, Signature.MODE_SIGN);
      return signer.sign(inputDataBuf, inputDataStart, inputDataLength,
              outputDataBuf, outputDataStart);
    } finally {
      signer.close();
    }
  }

  private byte mapPurpose(short purpose) {
    switch (purpose) {
    case KMType.ENCRYPT:
      return Cipher.MODE_ENCRYPT;
    case KMType.DECRYPT:
      return Cipher.MODE_DECRYPT;
    case KMType.SIGN:
      return Signature.MODE_SIGN;
    case KMType.VERIFY:
      return Signature.MODE_VERIFY;
    }
    return -1;
  }

  private byte mapSignature256Alg(byte alg, byte padding, byte digest) {
    switch (alg) {
    case KMType.RSA:
      switch (padding) {
      case KMType.RSA_PKCS1_1_5_SIGN: {
        if (digest == KMType.DIGEST_NONE)
          return KMRsa2048NoDigestSignature.ALG_RSA_PKCS1_NODIGEST;
        else
          return Signature.ALG_RSA_SHA_256_PKCS1;
      }
      case KMType.RSA_PSS:
        return Signature.ALG_RSA_SHA_256_PKCS1_PSS;
      case KMType.PADDING_NONE:
        return KMRsa2048NoDigestSignature.ALG_RSA_SIGN_NOPAD;
      }
      break;
    case KMType.EC:
      if (digest == KMType.DIGEST_NONE)
        return KMEcdsa256NoDigestSignature.ALG_ECDSA_NODIGEST;
      else
        return Signature.ALG_ECDSA_SHA_256;
    case KMType.HMAC:
      return Signature.ALG_HMAC_SHA_256;
    }
    return -1;
  }

  private byte mapCipherAlg(byte alg, byte padding, byte blockmode) {
    switch (alg) {
    case KMType.AES:
      switch (blockmode) {
      case KMType.ECB:
        return Cipher.ALG_AES_BLOCK_128_ECB_NOPAD;
      case KMType.CBC:
        return Cipher.ALG_AES_BLOCK_128_CBC_NOPAD;
      case KMType.CTR:
        return Cipher.ALG_AES_CTR;
      case KMType.GCM:
        return AEADCipher.ALG_AES_GCM;
      }
      break;
    case KMType.DES:
      switch (blockmode) {
      case KMType.ECB:
        return Cipher.ALG_DES_ECB_NOPAD;
      case KMType.CBC:
        return Cipher.ALG_DES_CBC_NOPAD;
      }
      break;
    case KMType.RSA:
      switch (padding) {
      case KMType.PADDING_NONE:
        return Cipher.ALG_RSA_NOPAD;
      case KMType.RSA_PKCS1_1_5_ENCRYPT:
        return Cipher.ALG_RSA_PKCS1;
      case KMType.RSA_OAEP:
        return Cipher.ALG_RSA_PKCS1_OAEP;
      }
      break;
    }
    return -1;
  }

  public Cipher createSymmetricCipher(short alg, short purpose,
          short blockMode, short padding, byte[] secret, short secretStart,
          short secretLength, byte[] ivBuffer, short ivStart, short ivLength) {
    Key key = null;
    Cipher symmCipher = null;
    switch (secretLength) {
    case 32:
      key = aesKeys[KEYSIZE_256_OFFSET];
      ((AESKey) key).setKey(secret,secretStart);
      break;
    case 16:
      key = aesKeys[KEYSIZE_128_OFFSET];
      ((AESKey) key).setKey(secret,secretStart);
      break;
    case 24:
      key = triDesKey;
      ((DESKey) key).setKey(secret,secretStart);
      break;
    default:
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      break;
    }
    short cipherAlg = mapCipherAlg((byte) alg, (byte) padding, (byte) blockMode);
    symmCipher = getCipherInstanceFromPool((byte) cipherAlg);
    switch (cipherAlg) {
    case Cipher.ALG_AES_BLOCK_128_CBC_NOPAD:
    case Cipher.ALG_AES_CTR:
      symmCipher.init(key, mapPurpose(purpose), ivBuffer, ivStart, ivLength);
      break;
    case Cipher.ALG_AES_BLOCK_128_ECB_NOPAD:
    case Cipher.ALG_DES_ECB_NOPAD:
      symmCipher.init(key, mapPurpose(purpose));
      break;
    case Cipher.ALG_DES_CBC_NOPAD:
      // TODO Consume only 8 bytes of iv. the random number for iv is of 16
      // bytes.
      // While sending back the iv send only 8 bytes.
      symmCipher.init(key, mapPurpose(purpose), ivBuffer, ivStart, (short) 8);
      break;
    case AEADCipher.ALG_AES_GCM:
      ((AEADCipher) symmCipher).init(key, mapPurpose(purpose), ivBuffer,
              ivStart, ivLength);
      break;
    default:// This should never happen
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
      break;
    }
    return symmCipher;
  }

  public Signature createHmacSignerVerifier(short purpose, short digest,
          byte[] secret, short secretStart, short secretLength) {
    byte alg = Signature.ALG_HMAC_SHA_256;
    if (digest != KMType.SHA2_256)
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    Signature hmacSignerVerifier = getSignatureInstanceFromPool(alg);
    HMACKey key = createHMACKey(secret, secretStart, secretLength);
    hmacSignerVerifier.init(key, (byte) mapPurpose(purpose));
    return hmacSignerVerifier;
  }

  @Override
  public KMOperation initSymmetricOperation(byte purpose, byte alg,
          byte digest, byte padding, byte blockMode, byte[] keyBuf,
          short keyStart, short keyLength, byte[] ivBuf, short ivStart,
          short ivLength, short macLength) {
    KMOperationImpl opr = null;
    switch (alg) {
    case KMType.AES:
    case KMType.DES:
      Cipher cipher = createSymmetricCipher(alg, purpose, blockMode, padding,
              keyBuf, keyStart, keyLength, ivBuf, ivStart, ivLength);
      opr = getOperationInstanceFromPool();
      // Convert macLength to bytes
      macLength = (short) (macLength / 8);
      JCSystem.beginTransaction();
      opr.setCipher(cipher);
      opr.setCipherAlgorithm(alg);
      opr.setBlockMode(blockMode);
      opr.setPaddingAlgorithm(padding);
      opr.setMode(purpose);
      opr.setMacLength(macLength);
      JCSystem.commitTransaction();
      break;
    case KMType.HMAC:
      Signature signerVerifier = createHmacSignerVerifier(purpose, digest,
              keyBuf, keyStart, keyLength);
      opr = getOperationInstanceFromPool();
      JCSystem.beginTransaction();
      opr.setSignature(signerVerifier);
      JCSystem.commitTransaction();
      break;
    default:
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
      break;
    }
    return opr;
  }

  public Signature createRsaSigner(short digest, short padding, byte[] secret,
          short secretStart, short secretLength, byte[] modBuffer,
          short modOff, short modLength) {
    byte alg = mapSignature256Alg(KMType.RSA, (byte) padding, (byte) digest);
    byte opMode;
    if (padding == KMType.PADDING_NONE
            || (padding == KMType.RSA_PKCS1_1_5_SIGN && digest == KMType.DIGEST_NONE)) {
      // return createNoDigestSigner(padding,secret, secretStart, secretLength,
      // modBuffer, modOff, modLength);
      opMode = Cipher.MODE_DECRYPT;
    } else {
      opMode = Signature.MODE_SIGN;
    }
    Signature rsaSigner = getSignatureInstanceFromPool(alg);
    RSAPrivateKey key = (RSAPrivateKey) rsaKeyPair.getPrivate();
    key.setExponent(secret, secretStart, secretLength);
    key.setModulus(modBuffer, modOff, modLength);
    rsaSigner.init(key, opMode);
    return rsaSigner;
  }

  public Signature createRsaVerifier(short digest, short padding,
          byte[] modBuffer, short modOff, short modLength) {
    byte alg = mapSignature256Alg(KMType.RSA, (byte) padding, (byte) digest);
    if (digest == KMType.DIGEST_NONE || padding == KMType.PADDING_NONE)
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);

    Signature rsaVerifier = getSignatureInstanceFromPool(alg);
    RSAPublicKey key = (RSAPublicKey) rsaKeyPair.getPublic();
    // setExponent
    Util.setShort(tmpArray, (short) 0, (short) 0x0001);
    Util.setShort(tmpArray, (short) 2, (short) 0x0001);
    // byte[] exponent = new byte[] { 0x01, 0x00, 0x01 };
    key.setExponent(tmpArray, (short) 0, (short) 4);
    key.setModulus(modBuffer, modOff, modLength);
    rsaVerifier.init(key, Signature.MODE_VERIFY);
    return rsaVerifier;
  }

  // TODO Remove commented code.
  /*
   * private Signature createNoDigestSigner(short padding, byte[] secret, short
   * secretStart, short secretLength, byte[] modBuffer, short modOff, short
   * modLength) { Cipher rsaCipher =
   * getCipherInstanceFromPool(Cipher.ALG_RSA_NOPAD
   * );//Cipher.getInstance(Cipher.ALG_RSA_NOPAD,false); RSAPrivateKey key =
   * (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,
   * KeyBuilder.LENGTH_RSA_2048, false);
   * key.setExponent(secret,secretStart,secretLength); key.setModulus(modBuffer,
   * modOff, modLength); rsaCipher.init(key,Cipher.MODE_DECRYPT);
   * KMRsa2048NoDigestSignature inst = new
   * KMRsa2048NoDigestSignature(rsaCipher,(byte)padding,
   * modBuffer,modOff,modLength); return inst; }
   */

  public Cipher createRsaCipher(short padding, short digest, byte[] modBuffer,
          short modOff, short modLength) {
    byte cipherAlg = mapCipherAlg(KMType.RSA, (byte) padding, (byte) 0);
    // TODO: Implement from NXP.
    /*
     * if (cipherAlg == Cipher.ALG_RSA_PKCS1_OAEP) { //TODO: Implement from NXP.
     * KMException.throwIt(KMError.UNIMPLEMENTED); }
     */
    Cipher rsaCipher = getCipherInstanceFromPool(cipherAlg);
    RSAPublicKey key = (RSAPublicKey) rsaKeyPair.getPublic();
    // setExponent
    Util.setShort(tmpArray, (short) 0, (short) 0x0001);
    Util.setShort(tmpArray, (short) 2, (short) 0x0001);
    // byte[] exponent = new byte[] { 0x01, 0x00, 0x01 };
    key.setExponent(tmpArray, (short) 0, (short) 4);
    key.setModulus(modBuffer, modOff, modLength);
    rsaCipher.init(key, Cipher.MODE_ENCRYPT);
    return rsaCipher;
  }

  public Cipher createRsaDecipher(short padding, short digest, byte[] secret,
          short secretStart, short secretLength, byte[] modBuffer,
          short modOff, short modLength) {
    byte cipherAlg = mapCipherAlg(KMType.RSA, (byte) padding, (byte) 0);
    /*
     * if (cipherAlg == Cipher.ALG_RSA_PKCS1_OAEP) { //TODO: Implement from NXP.
     * KMException.throwIt(KMError.UNIMPLEMENTED); }
     */
    Cipher rsaCipher = getCipherInstanceFromPool(cipherAlg);
    RSAPrivateKey key = (RSAPrivateKey) rsaKeyPair.getPrivate();
    key.setExponent(secret, secretStart, secretLength);
    key.setModulus(modBuffer, modOff, modLength);
    rsaCipher.init(key, Cipher.MODE_DECRYPT);
    return rsaCipher;
  }

  public Signature createEcSigner(short digest, byte[] secret,
          short secretStart, short secretLength) {
    byte alg = mapSignature256Alg(KMType.EC, (byte) 0, (byte) digest);
    Signature ecSigner = null;
    ECPrivateKey key = (ECPrivateKey) ecKeyPair.getPrivate();
    key.setS(secret, secretStart, secretLength);
    ecSigner = getSignatureInstanceFromPool(alg);
    ecSigner.init(key, Signature.MODE_SIGN);
    return ecSigner;
  }

  public Signature createEcVerifier(short digest, byte[] pubKey,
          short pubKeyStart, short pubKeyLength) {
    byte alg = mapSignature256Alg(KMType.EC, (byte) 0, (byte) digest);
    Signature ecVerifier = null;
    // if(msgDigestAlg == MessageDigest.ALG_NULL)
    // CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    if (digest == KMType.DIGEST_NONE) {
      // TODO: Implement from NXP.
      KMException.throwIt(KMError.UNIMPLEMENTED);
    } else {
      ECPublicKey key = (ECPublicKey) ecKeyPair.getPublic();
      key.setW(pubKey, pubKeyStart, pubKeyLength);
      ecVerifier = getSignatureInstanceFromPool(alg);
      ecVerifier.init(key, Signature.MODE_VERIFY);
    }
    return ecVerifier;
  }

  @Override
  public KMOperation initAsymmetricOperation(byte purpose, byte alg,
          byte padding, byte digest, byte[] privKeyBuf, short privKeyStart,
          short privKeyLength, byte[] pubModBuf, short pubModStart,
          short pubModLength) {
    KMOperationImpl opr = null;
    if (alg == KMType.RSA) {
      switch (purpose) {
      case KMType.SIGN:
        Signature signer = createRsaSigner(digest, padding, privKeyBuf,
                privKeyStart, privKeyLength, pubModBuf, pubModStart,
                pubModLength);
        opr = getOperationInstanceFromPool();
        JCSystem.beginTransaction();
        opr.setSignature(signer);
        opr.setCipherAlgorithm(alg);
        opr.setPaddingAlgorithm(padding);
        opr.setMode(purpose);
        JCSystem.commitTransaction();
        break;
      case KMType.VERIFY:
        Signature verifier = createRsaVerifier(digest, padding, pubModBuf,
                pubModStart, pubModLength);
        opr = getOperationInstanceFromPool();
        JCSystem.beginTransaction();
        opr.setSignature(verifier);
        opr.setCipherAlgorithm(alg);
        opr.setPaddingAlgorithm(padding);
        opr.setMode(purpose);
        JCSystem.commitTransaction();
        break;
      case KMType.ENCRYPT:
        Cipher cipher = createRsaCipher(padding, digest, pubModBuf,
                pubModStart, pubModLength);
        opr = getOperationInstanceFromPool();
        JCSystem.beginTransaction();
        opr.setCipher(cipher);
        opr.setCipherAlgorithm(alg);
        opr.setPaddingAlgorithm(padding);
        opr.setMode(purpose);
        JCSystem.commitTransaction();
        break;
      case KMType.DECRYPT:
        Cipher decipher = createRsaDecipher(padding, digest, privKeyBuf,
                privKeyStart, privKeyLength, pubModBuf, pubModStart,
                pubModLength);
        opr = getOperationInstanceFromPool();
        JCSystem.beginTransaction();
        opr.setCipher(decipher);
        opr.setCipherAlgorithm(alg);
        opr.setPaddingAlgorithm(padding);
        opr.setMode(purpose);
        JCSystem.commitTransaction();
        break;
      default:
        break;
      }
    } else if (alg == KMType.EC) {
      switch (purpose) {
      case KMType.SIGN:
        Signature signer = createEcSigner(digest, privKeyBuf, privKeyStart,
                privKeyLength);
        opr = getOperationInstanceFromPool();
        JCSystem.beginTransaction();
        opr.setSignature(signer);
        JCSystem.commitTransaction();
        break;
      case KMType.VERIFY:
        Signature verifier = createEcVerifier(digest, pubModBuf, pubModStart,
                pubModLength);
        opr = getOperationInstanceFromPool();
        JCSystem.beginTransaction();
        opr.setSignature(verifier);
        JCSystem.commitTransaction();
        break;
      }
    } else {
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }
    return opr;

  }

  @Override
  public KMAttestationCert getAttestationCert(boolean rsaCert) {
    return KMAttestationCertImpl.instance(rsaCert);
  }

  @Override
  public short aesCCMSign(byte[] bufIn, short bufInStart, short buffInLength,
          byte[] masterKeySecret, short masterKeyStart, short masterKeyLen,
          byte[] bufOut, short bufStart) {
    if (masterKeyLen > 16) {
      return -1;
    }
    aesKeys[KEYSIZE_128_OFFSET].setKey(masterKeySecret, (short) masterKeyStart);
    kdf.init(aesKeys[KEYSIZE_128_OFFSET], Signature.MODE_SIGN);
    return kdf.sign(bufIn, bufInStart, buffInLength, bufOut, bufStart);
  }

  @Override
  public boolean isBackupRestoreSupported() {
    // TODO Auto-generated method stub
    return false;
  }

  @Override
  public void backup(byte[] buf, short start, short len) {
    // TODO Auto-generated method stub

  }

  @Override
  public short restore(byte[] buf, short start) {
    // TODO Auto-generated method stub
    return 0;
  }

  @Override
  public void getTrueRandomNumber(byte[] buf, short start, short length) {
    Util.arrayCopy(entropyPool, (short) 0, buf, start, length);
  }

  @Override
  public short cmacKdf(byte[] keyMaterial, short keyMaterialStart,
          short keyMaterialLen, byte[] label, short labelStart, short labelLen,
          byte[] context, short contextStart, short contextLength,
          byte[] keyBuf, short keyStart) {
    HMACKey key = cmacKdf(keyMaterial, keyMaterialStart, keyMaterialLen, label,
            labelStart, labelLen, context, contextStart, contextLength);
    return key.getKey(keyBuf, keyStart);
  }

}
