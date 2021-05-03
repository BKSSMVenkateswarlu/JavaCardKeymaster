package com.android.javacard.keymaster;

import javacard.framework.JCSystem;
import javacard.framework.Util;

interface KMBaseOperationState {
  short getHandle();
  void setPurpose(byte purpose);

  void persist();

  void setKeySize(short keySize);
  short getKeySize();
  void reset();
  void release();
  short getPurpose();


  void setOperation(KMOperation opr);

  KMOperation getOperation();

  boolean isAuthPerOperationReqd();
  boolean isAuthTimeoutValidated();

  boolean isSecureUserIdReqd();

  short getAuthTime();

  void setAuthTime(byte[] timeBuf, short start);

  void setOneTimeAuthReqd(boolean flag);

  void setAuthTimeoutValidated(boolean flag);
  void setAuthPerOperationReqd(boolean flag);

  byte getAlgorithm();

  void setAlgorithm(byte algorithm);

  byte getPadding();

  void setPadding(byte padding);

  byte getBlockMode();
  void setBlockMode(byte blockMode);

  byte getDigest();

  void setDigest(byte digest);

  boolean isAesGcmUpdateAllowed();
  void setAesGcmUpdateComplete();

  void setAesGcmUpdateStart();

  void setMacLength(short length);

  short getMacLength();
}
