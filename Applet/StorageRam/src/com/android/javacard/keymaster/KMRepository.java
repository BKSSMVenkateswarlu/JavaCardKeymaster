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
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.javacard.keymaster;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * KMRepository class manages persistent and volatile memory usage by the applet. Note the
 * repository is only used by applet and it is not intended to be used by seProvider.
 */
public class KMRepsitory extends KMBaseRepository {

  // Data table configuration
  public static final short OPERATION_HANDLE_SIZE = 8; /* 8 bytes */
  private static final short OPERATION_HANDLE_STATUS_OFFSET = 0;
  private static final short OPERATION_HANDLE_STATUS_SIZE = 1;
  private static final short OPERATION_HANDLE_OFFSET = 1;
  private static final short OPERATION_HANDLE_ENTRY_SIZE =
      OPERATION_HANDLE_SIZE + OPERATION_HANDLE_STATUS_SIZE;

  // Class Attributes
  private Object[] operationStateTable;

  // Operation table.
  private static final short OPER_TABLE_DATA_OFFSET = 0;
  private static final short OPER_TABLE_OPR_OFFSET = 1;
  private static final short OPER_DATA_LEN = OPERATION_HANDLE_ENTRY_SIZE + KMOperationState.MAX_DATA;
  private static final short DATA_ARRAY_LENGTH = MAX_OPS * OPER_DATA_LEN;


  // Singleton instance
  private static KMRepsitory repository;

  public static KMRepsitory instance() {
    return repository;
  }

  public KMRepsitory(boolean isUpgrading) {
    super(isUpgrading);

    operationStateTable = new Object[2];
    operationStateTable[0] = JCSystem.makeTransientByteArray(DATA_ARRAY_LENGTH, JCSystem.CLEAR_ON_RESET);
    operationStateTable[1] = JCSystem.makeTransientObjectArray(MAX_OPS, JCSystem.CLEAR_ON_RESET);
    repository = this;
  }

  @Override
  public void getOperationHandle(short oprHandle, byte[] buf, short off, short len) {
    if (KMInteger.cast(oprHandle).length() != OPERATION_HANDLE_SIZE) {
      KMException.throwIt(KMError.INVALID_OPERATION_HANDLE);
    }
    KMInteger.cast(oprHandle).getValue(buf, off, len);
  }

  @Override
  public KMOperationState findOperation(byte[] buf, short off, short len) {
    short index = 0;
    byte[] oprTableData;
    short offset = 0;
    oprTableData = (byte[]) operationStateTable[OPER_TABLE_DATA_OFFSET];
    Object[] operations = (Object[]) operationStateTable[OPER_TABLE_OPR_OFFSET];
    while (index < MAX_OPS) {
      offset = (short) (index * OPER_DATA_LEN);
      if (0 == Util.arrayCompare(buf, off, oprTableData, (short) (offset + OPERATION_HANDLE_OFFSET), len)) {
        return KMOperationState.read(oprTableData, (short) (offset + OPERATION_HANDLE_OFFSET), oprTableData,
            (short) (offset + OPERATION_HANDLE_ENTRY_SIZE),
            operations[index]);
      }
      index++;
    }
    return null;
  }

  /* operationHandle is a KMInteger */
  @Override
  public KMOperationState findOperation(short operationHandle) {
    short buf = KMByteBlob.instance(OPERATION_HANDLE_SIZE);
    getOperationHandle(
        operationHandle,
        KMByteBlob.cast(buf).getBuffer(),
        KMByteBlob.cast(buf).getStartOff(),
        KMByteBlob.cast(buf).length());
    return findOperation(
        KMByteBlob.cast(buf).getBuffer(),
        KMByteBlob.cast(buf).getStartOff(),
        KMByteBlob.cast(buf).length());
  }

  /* opHandle is a KMInteger */
  @Override
  public KMOperationState reserveOperation(short opHandle) {
    short index = 0;
    byte[] oprTableData = (byte[]) operationStateTable[OPER_TABLE_DATA_OFFSET];
    short offset = 0;
    while (index < MAX_OPS) {
      offset = (short) (index * OPER_DATA_LEN);
      /* Check for unreserved operation state */
      if (oprTableData[(short) (offset + OPERATION_HANDLE_STATUS_OFFSET)] == 0) {
        return KMOperationState.instance(opHandle);
      }
      index++;
    }
    return null;
  }

  @Override
  public void persistOperation(byte[] data, short opHandle, KMOperation op) {
    short index = 0;
    byte[] oprTableData = (byte[]) operationStateTable[OPER_TABLE_DATA_OFFSET];
    Object[] operations = (Object[]) operationStateTable[OPER_TABLE_OPR_OFFSET];
    short offset = 0;
    short buf = KMByteBlob.instance(OPERATION_HANDLE_SIZE);
    getOperationHandle(
        opHandle,
        KMByteBlob.cast(buf).getBuffer(),
        KMByteBlob.cast(buf).getStartOff(),
        KMByteBlob.cast(buf).length());
    //Update an existing operation state.
    while (index < MAX_OPS) {
      offset = (short) (index * OPER_DATA_LEN);
      if ((1 == oprTableData[(short) (offset + OPERATION_HANDLE_STATUS_OFFSET)])
          && (0 == Util.arrayCompare(
          oprTableData,
          (short) (offset + OPERATION_HANDLE_OFFSET),
          KMByteBlob.cast(buf).getBuffer(),
          KMByteBlob.cast(buf).getStartOff(),
          KMByteBlob.cast(buf).length()))) {
        Util.arrayCopy(data, (short) 0, oprTableData, (short) (offset + OPERATION_HANDLE_ENTRY_SIZE),
            KMOperationState.MAX_DATA);
        operations[index] = op;
        return;
      }
      index++;
    }

    index = 0;
    //Persist a new operation.
    while (index < MAX_OPS) {
      offset = (short) (index * OPER_DATA_LEN);
      if (0 == oprTableData[(short) (offset + OPERATION_HANDLE_STATUS_OFFSET)]) {
        oprTableData[(short) (offset + OPERATION_HANDLE_STATUS_OFFSET)] = 1;/*reserved */
        Util.arrayCopy(
            KMByteBlob.cast(buf).getBuffer(),
            KMByteBlob.cast(buf).getStartOff(),
            oprTableData,
            (short) (offset + OPERATION_HANDLE_OFFSET),
            OPERATION_HANDLE_SIZE);
        Util.arrayCopy(data, (short) 0, oprTableData, (short) (offset + OPERATION_HANDLE_ENTRY_SIZE),
            KMOperationState.MAX_DATA);
        operations[index] = op;
        break;
      }
      index++;
    }
  }

  @Override
  public void releaseOperation(KMOperationState op) {
    short index = 0;
    byte[] oprTableData = (byte[]) operationStateTable[OPER_TABLE_DATA_OFFSET];
    Object[] operations = (Object[]) operationStateTable[OPER_TABLE_OPR_OFFSET];
    short offset = 0;
    short buf = KMByteBlob.instance(OPERATION_HANDLE_SIZE);
    getOperationHandle(
        op.getHandle(),
        KMByteBlob.cast(buf).getBuffer(),
        KMByteBlob.cast(buf).getStartOff(),
        KMByteBlob.cast(buf).length());
    while (index < MAX_OPS) {
      offset = (short) (index * OPER_DATA_LEN);
      if ((oprTableData[(short) (offset + OPERATION_HANDLE_STATUS_OFFSET)] == 1) &&
          (0 == Util.arrayCompare(oprTableData,
              (short) (offset + OPERATION_HANDLE_OFFSET),
              KMByteBlob.cast(buf).getBuffer(),
              KMByteBlob.cast(buf).getStartOff(),
              KMByteBlob.cast(buf).length()))) {
        Util.arrayFillNonAtomic(oprTableData, offset, OPER_DATA_LEN, (byte) 0);
        op.release();
        operations[index] = null;
        break;
      }
      index++;
    }
  }

  @Override
  public void releaseAllOperations() {
    short index = 0;
    byte[] oprTableData = (byte[]) operationStateTable[OPER_TABLE_DATA_OFFSET];
    Object[] operations = (Object[]) operationStateTable[OPER_TABLE_OPR_OFFSET];
    short offset = 0;
    while (index < MAX_OPS) {
      offset = (short) (index * OPER_DATA_LEN);
      if (oprTableData[(short) (offset + OPERATION_HANDLE_STATUS_OFFSET)] == 1) {
        Util.arrayFillNonAtomic(oprTableData, offset, OPER_DATA_LEN, (byte) 0);
        if (operations[index] != null) {
          ((KMOperation) operations[index]).abort();
          operations[index] = null;
        }
      }
      index++;
    }
  }
}
