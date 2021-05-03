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
public class KMRepository extends KMBaseRepository {

  private static final short OPERATION_HANDLE_STATUS_OFFSET = 0;
  private static final short OPERATION_HANDLE_STATUS_SIZE = 1;
  private static final short OPERATION_HANDLE_OFFSET = 1;
  private static final short OPERATION_HANDLE_ENTRY_SIZE =
    KMBaseRepository.OPERATION_HANDLE_SIZE + OPERATION_HANDLE_STATUS_SIZE;

  // Class Attributes
  private Object[] operationStateTable;

  public KMRepository(boolean isUpgrading) {
    super(isUpgrading);
    operationStateTable = new Object[MAX_OPS];
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
  public KMBaseOperationState findOperation(byte[] buf, short off, short len) {
    short index = 0;
    byte[] opId;
    while (index < MAX_OPS) {
      opId = ((byte[]) ((Object[]) operationStateTable[index])[0]);
      if (0 == Util.arrayCompare(buf, off, opId, OPERATION_HANDLE_OFFSET, len)) {
        return KMOperationState
            .read(opId, OPERATION_HANDLE_OFFSET,
                (Object[]) ((Object[]) operationStateTable[index])[1]);
      }
      index++;
    }

    return null;
  }

  /* operationHandle is a KMInteger */
  @Override
  public KMBaseOperationState findOperation(short operationHandle) {
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
  public KMBaseOperationState reserveOperation(short opHandle) {
    short index = 0;
    byte[] opId;
    while (index < MAX_OPS) {
      opId = (byte[]) ((Object[]) operationStateTable[index])[0];
      /* Check for unreserved operation state */
      if (opId[OPERATION_HANDLE_STATUS_OFFSET] == 0) {
        return KMOperationState
            .instance(opHandle, (Object[]) ((Object[]) operationStateTable[index])[1]);
      }
      index++;
    }
    return null;
  }

  @Override
  public void persistOperation(byte[] data, short opHandle, KMOperation op) {
    short index = 0;
    byte[] opId;
    short buf = KMByteBlob.instance(OPERATION_HANDLE_SIZE);
    getOperationHandle(
        opHandle,
        KMByteBlob.cast(buf).getBuffer(),
        KMByteBlob.cast(buf).getStartOff(),
        KMByteBlob.cast(buf).length());
    //Update an existing operation state.
    while (index < MAX_OPS) {
      opId = (byte[]) ((Object[]) operationStateTable[index])[0];
      if ((1 == opId[OPERATION_HANDLE_STATUS_OFFSET])
          && (0 == Util.arrayCompare(
          opId,
          OPERATION_HANDLE_OFFSET,
          KMByteBlob.cast(buf).getBuffer(),
          KMByteBlob.cast(buf).getStartOff(),
          KMByteBlob.cast(buf).length()))) {
        Object[] slot = (Object[]) ((Object[]) operationStateTable[index])[1];
        JCSystem.beginTransaction();
        Util.arrayCopy(data, (short) 0, (byte[]) slot[0], (short) 0,
            (short) ((byte[]) slot[0]).length);
        Object[] ops = ((Object[]) slot[1]);
        ops[0] = op;
        JCSystem.commitTransaction();
        return;
      }
      index++;
    }

    index = 0;
    //Persist a new operation.
    while (index < MAX_OPS) {
      opId = (byte[]) ((Object[]) operationStateTable[index])[0];
      if (0 == opId[OPERATION_HANDLE_STATUS_OFFSET]) {
        Object[] slot = (Object[]) ((Object[]) operationStateTable[index])[1];
        JCSystem.beginTransaction();
        opId[OPERATION_HANDLE_STATUS_OFFSET] = 1;/*reserved */
        Util.arrayCopy(
            KMByteBlob.cast(buf).getBuffer(),
            KMByteBlob.cast(buf).getStartOff(),
            opId,
            OPERATION_HANDLE_OFFSET,
            OPERATION_HANDLE_SIZE);
        Util.arrayCopy(data, (short) 0, (byte[]) slot[0], (short) 0,
            (short) ((byte[]) slot[0]).length);
        Object[] ops = ((Object[]) slot[1]);
        ops[0] = op;
        JCSystem.commitTransaction();
        break;
      }
      index++;
    }
  }

  @Override
  public void releaseOperation(KMBaseOperationState opBase) {
    short index = 0;
    byte[] oprHandleBuf;
    KMOperationState op = (KMOperationState) opBase;
    short buf = KMByteBlob.instance(OPERATION_HANDLE_SIZE);
    getOperationHandle(
        op.getHandle(),
        KMByteBlob.cast(buf).getBuffer(),
        KMByteBlob.cast(buf).getStartOff(),
        KMByteBlob.cast(buf).length());
    while (index < MAX_OPS) {
      oprHandleBuf = ((byte[]) ((Object[]) operationStateTable[index])[0]);
      if ((oprHandleBuf[OPERATION_HANDLE_STATUS_OFFSET] == 1) &&
          (0 == Util.arrayCompare(oprHandleBuf,
              OPERATION_HANDLE_OFFSET,
              KMByteBlob.cast(buf).getBuffer(),
              KMByteBlob.cast(buf).getStartOff(),
              KMByteBlob.cast(buf).length()))) {
        JCSystem.beginTransaction();
        Util.arrayFillNonAtomic(oprHandleBuf, (short) 0, (short) oprHandleBuf.length, (byte) 0);
        JCSystem.commitTransaction();
        op.release();
        break;
      }
      index++;
    }
  }

  @Override
  public void releaseAllOperations() {
    short index = 0;
    byte[] oprHandleBuf;
    while (index < MAX_OPS) {
      oprHandleBuf = ((byte[]) ((Object[]) operationStateTable[index])[0]);
      if (oprHandleBuf[OPERATION_HANDLE_STATUS_OFFSET] == 1) {
        Object[] slot = (Object[]) ((Object[]) operationStateTable[index])[1];
        Object[] ops = ((Object[]) slot[1]);
        ((KMOperation) ops[0]).abort();
        JCSystem.beginTransaction();
        Util.arrayFillNonAtomic((byte[]) slot[0], (short) 0,
                (short) ((byte[]) slot[0]).length, (byte) 0);
        Util.arrayFillNonAtomic(oprHandleBuf, (short) 0, (short) oprHandleBuf.length, (byte) 0);
        ops[0] = null;
        JCSystem.commitTransaction();
      }
      index++;
    }
  }

}
