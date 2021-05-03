package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import org.globalplatform.upgrade.Element;

public abstract class KMBaseRepository implements KMUpgradable {

  // Data table configuration
  public static final short OPERATION_HANDLE_SIZE = 8; /* 8 bytes */
  public static final short DATA_INDEX_SIZE = 22;
  public static final short DATA_INDEX_ENTRY_SIZE = 4;
  public static final short DATA_MEM_SIZE = 2048;
  public static final short HEAP_SIZE = 10000;
  public static final short DATA_INDEX_ENTRY_LENGTH = 0;
  public static final short DATA_INDEX_ENTRY_OFFSET = 2;

  // Data table offsets
  public static final byte COMPUTED_HMAC_KEY = 8;
  public static final byte HMAC_NONCE = 9;
  public static final byte ATT_ID_BRAND = 0;
  public static final byte ATT_ID_DEVICE = 1;
  public static final byte ATT_ID_PRODUCT = 2;
  public static final byte ATT_ID_SERIAL = 3;
  public static final byte ATT_ID_IMEI = 4;
  public static final byte ATT_ID_MEID = 5;
  public static final byte ATT_ID_MANUFACTURER = 6;
  public static final byte ATT_ID_MODEL = 7;
  public static final byte CERT_ISSUER = 10;
  public static final byte CERT_EXPIRY_TIME = 11;
  public static final byte BOOT_OS_VERSION = 12;
  public static final byte BOOT_OS_PATCH = 13;
  public static final byte VENDOR_PATCH_LEVEL = 14;
  public static final byte BOOT_PATCH_LEVEL = 15;
  public static final byte BOOT_VERIFIED_BOOT_KEY = 16;
  public static final byte BOOT_VERIFIED_BOOT_HASH = 17;
  public static final byte BOOT_VERIFIED_BOOT_STATE = 18;
  public static final byte BOOT_DEVICE_LOCKED_STATUS = 19;
  public static final byte DEVICE_LOCKED_TIME = 20;
  public static final byte DEVICE_LOCKED = 21;

  // Data Item sizes
  public static final short MASTER_KEY_SIZE = 16;
  public static final short SHARED_SECRET_KEY_SIZE = 32;
  public static final short HMAC_SEED_NONCE_SIZE = 32;
  public static final short COMPUTED_HMAC_KEY_SIZE = 32;
  public static final short OS_VERSION_SIZE = 4;
  public static final short OS_PATCH_SIZE = 4;
  public static final short VENDOR_PATCH_SIZE = 4;
  public static final short BOOT_PATCH_SIZE = 4;
  public static final short DEVICE_LOCK_TS_SIZE = 8;
  public static final short DEVICE_LOCK_FLAG_SIZE = 1;
  public static final short BOOT_STATE_SIZE = 1;
  public static final short MAX_OPS = 4;
  public static final byte BOOT_KEY_MAX_SIZE = 32;
  public static final byte BOOT_HASH_MAX_SIZE = 32;

  // Class Attributes
  private byte[] heap;
  private short[] heapIndex;
  private byte[] dataTable;
  private short dataIndex;
  private short[] reclaimIndex;

  protected static KMBaseRepository repository;

  public static KMBaseRepository instance() {
    return repository;
  }

  KMBaseRepository(boolean isUpgrading) {
    heap = JCSystem.makeTransientByteArray(HEAP_SIZE, JCSystem.CLEAR_ON_RESET);
    heapIndex = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
    reclaimIndex = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
    heapIndex[0] = (short) 0;
    //Set the reset flags
    resetHeapEndIndex();

    newDataTable(isUpgrading);
    //Initialize the device locked status
    if (!isUpgrading) {
      setDeviceLock(false);
      setDeviceLockPasswordOnly(false);
    }
  }

  public void resetHeapEndIndex() {
    reclaimIndex[0] = HEAP_SIZE;
  }

  // This function should only be called before processing any of the APUs.
  // Once we start processing the APDU the reclainIndex[0] will change to
  // a lesser value than HEAP_SIZE
  public boolean isResetEventOccurred() {
    if (reclaimIndex[0] == HEAP_SIZE) {
      return false;
    }
    return true;
  }

  public abstract void getOperationHandle(short oprHandle, byte[] buf, short off, short len);

  public abstract KMBaseOperationState findOperation(byte[] buf, short off, short len);

  /* operationHandle is a KMInteger */
  public abstract KMBaseOperationState findOperation(short operationHandle);

  /* opHandle is a KMInteger */
  public abstract KMBaseOperationState reserveOperation(short opHandle);

  public abstract void persistOperation(byte[] data, short opHandle, KMOperation op);

  public abstract void releaseOperation(KMBaseOperationState op);

  public abstract void releaseAllOperations();

  public void initComputedHmac(byte[] key, short start, short len) {
    if (len != COMPUTED_HMAC_KEY_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(COMPUTED_HMAC_KEY, key, start, len);
  }

  public void initHmacNonce(byte[] nonce, short offset, short len) {
    if (len != HMAC_SEED_NONCE_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(HMAC_NONCE, nonce, offset, len);
  }

  public void clearHmacNonce() {
    clearDataEntry(HMAC_NONCE);
  }

  public void clearComputedHmac() {
    clearDataEntry(COMPUTED_HMAC_KEY);
  }

  public void onUninstall() {
    // Javacard Runtime environment cleans up the data.

  }

  public void onProcess() {
    // When card reset happens reclaimIndex[0] will be equal to 0.
    // So make sure the reclaimIndex[0] is always equal to HEAP_SIZE
    resetHeapEndIndex();
  }

  public void clean() {
    Util.arrayFillNonAtomic(heap, (short) 0, heapIndex[0], (byte) 0);
    heapIndex[0] = (short) 0;
    resetHeapEndIndex();
  }

  public void onDeselect() {
  }

  public void onSelect() {
    // If write through caching is implemented then this method will restore the data into cache
  }

  // This function uses memory from the back of the heap(transient memory). Call
  // reclaimMemory function immediately after the use.
  public short allocReclaimableMemory(short length) {
    if ((((short) (reclaimIndex[0] - length)) <= heapIndex[0])
      || (length >= HEAP_SIZE / 2)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    reclaimIndex[0] -= length;
    return reclaimIndex[0];
  }

  // Reclaims the memory back.
  public void reclaimMemory(short length) {
    if (reclaimIndex[0] < heapIndex[0]) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    reclaimIndex[0] += length;
  }

  public short allocAvailableMemory() {
    if (heapIndex[0] >= heap.length) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short index = heapIndex[0];
    heapIndex[0] = (short) heap.length;
    return index;
  }

  public short alloc(short length) {
    if ((((short) (heapIndex[0] + length)) > heap.length) ||
      (((short) (heapIndex[0] + length)) > reclaimIndex[0])) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    heapIndex[0] += length;
    return (short) (heapIndex[0] - length);
  }

  private short dataAlloc(short length) {
    if (((short) (dataIndex + length)) > dataTable.length) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    dataIndex += length;
    return (short) (dataIndex - length);
  }


  private void newDataTable(boolean isUpgrading) {
    if (!isUpgrading) {
      if (dataTable == null) {
        dataTable = new byte[DATA_MEM_SIZE];
        dataIndex = (short) (DATA_INDEX_SIZE * DATA_INDEX_ENTRY_SIZE);
      }
    }
  }

  public void restoreData(short blob) {
    JCSystem.beginTransaction();
    Util.arrayCopy(
      KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff(), dataTable,
      (short) 0,
      KMByteBlob.cast(blob).length()
    );
    JCSystem.commitTransaction();
  }

  public byte[] getDataTable() {
    return dataTable;
  }

  private void clearDataEntry(short id) {
    JCSystem.beginTransaction();
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    short dataLen = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
    if (dataLen != 0) {
      short dataPtr = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET));
      Util.arrayFillNonAtomic(dataTable, dataPtr, dataLen, (byte) 0);
    }
    JCSystem.commitTransaction();
  }

  private void writeDataEntry(short id, byte[] buf, short offset, short len) {
    JCSystem.beginTransaction();
    short dataPtr;
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    short dataLen = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
    if (dataLen == 0) {
      dataPtr = dataAlloc(len);
      Util.setShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET), dataPtr);
      Util.setShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH), len);
      Util.arrayCopyNonAtomic(buf, offset, dataTable, dataPtr, len);
    } else {
      if (len != dataLen) {
        KMException.throwIt(KMError.UNKNOWN_ERROR);
      }
      dataPtr = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET));
      Util.arrayCopyNonAtomic(buf, offset, dataTable, dataPtr, len);
    }
    JCSystem.commitTransaction();
  }

  private short readDataEntry(short id, byte[] buf, short offset) {
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    short len = Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
    if (len != 0) {
      Util.arrayCopyNonAtomic(
        dataTable,
        Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_OFFSET)),
        buf,
        offset,
        len);
    }
    return len;
  }

  private short dataLength(short id) {
    id = (short) (id * DATA_INDEX_ENTRY_SIZE);
    return Util.getShort(dataTable, (short) (id + DATA_INDEX_ENTRY_LENGTH));
  }

  public byte[] getHeap() {
    return heap;
  }

  public short getHmacNonce() {
    return readData(HMAC_NONCE);
  }

  public short getComputedHmacKey() {
    return readData(COMPUTED_HMAC_KEY);
  }

  public void persistAttId(byte id, byte[] buf, short start, short len) {
    writeDataEntry(id, buf, start, len);
  }

  public short getAttId(byte id) {
    return readData(id);
  }

  public void deleteAttIds() {
    clearDataEntry(ATT_ID_BRAND);
    clearDataEntry(ATT_ID_MEID);
    clearDataEntry(ATT_ID_DEVICE);
    clearDataEntry(ATT_ID_IMEI);
    clearDataEntry(ATT_ID_MODEL);
    clearDataEntry(ATT_ID_PRODUCT);
    clearDataEntry(ATT_ID_SERIAL);
    clearDataEntry(ATT_ID_MANUFACTURER);
  }

  public short getIssuer() {
    return readData(CERT_ISSUER);
  }

  public short readData(short id) {
    short blob = KMByteBlob.instance(dataLength(id));
    if (readDataEntry(id, KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff())
      == 0) {
      return 0;
    }
    return blob;
  }

  public void setIssuer(byte[] buf, short start, short len) {
    writeDataEntry(CERT_ISSUER, buf, start, len);
  }


  public short getCertExpiryTime() {
    return readData(CERT_EXPIRY_TIME);
  }

  public void setCertExpiryTime(byte[] buf, short start, short len) {
    writeDataEntry(CERT_EXPIRY_TIME, buf, start, len);
  }

  private static final byte[] zero = {0, 0, 0, 0, 0, 0, 0, 0};

  public short getOsVersion() {
    short blob = readData(BOOT_OS_VERSION);
    if (blob != 0) {
      return KMInteger.uint_32(
        KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
    } else {
      return KMInteger.uint_32(zero, (short) 0);
    }
  }

  public short getVendorPatchLevel() {
    short blob = readData(VENDOR_PATCH_LEVEL);
    if (blob != 0) {
      return KMInteger.uint_32(
        KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
    } else {
      return KMInteger.uint_32(zero, (short) 0);
    }
  }

  public short getBootPatchLevel() {
    short blob = readData(BOOT_PATCH_LEVEL);
    if (blob != 0) {
      return KMInteger.uint_32(
        KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
    } else {
      return KMInteger.uint_32(zero, (short) 0);
    }
  }

  public short getOsPatch() {
    short blob = readData(BOOT_OS_PATCH);
    if (blob != 0) {
      return KMInteger.uint_32(
        KMByteBlob.cast(blob).getBuffer(), KMByteBlob.cast(blob).getStartOff());
    } else {
      return KMInteger.uint_32(zero, (short) 0);
    }
  }

  public short readROT() {
    short totalLength = 0;
    short length = dataLength(BOOT_VERIFIED_BOOT_KEY);
    if (length == 0) {
      return KMType.INVALID_VALUE;
    }
    totalLength += length;
    if ((length = dataLength(BOOT_VERIFIED_BOOT_HASH)) == 0) {
      return KMType.INVALID_VALUE;
    }
    totalLength += length;
    if ((length = dataLength(BOOT_VERIFIED_BOOT_STATE)) == 0) {
      return KMType.INVALID_VALUE;
    }
    totalLength += length;
    if ((length = dataLength(BOOT_DEVICE_LOCKED_STATUS)) == 0) {
      return KMType.INVALID_VALUE;
    }
    totalLength += length;

    short blob = KMByteBlob.instance(totalLength);
    length = readDataEntry(BOOT_VERIFIED_BOOT_KEY, KMByteBlob.cast(blob)
      .getBuffer(), KMByteBlob.cast(blob).getStartOff());

    length += readDataEntry(BOOT_VERIFIED_BOOT_HASH, KMByteBlob.cast(blob)
        .getBuffer(),
      (short) (KMByteBlob.cast(blob).getStartOff() + length));

    length += readDataEntry(BOOT_VERIFIED_BOOT_STATE, KMByteBlob.cast(blob)
        .getBuffer(),
      (short) (KMByteBlob.cast(blob).getStartOff() + length));

    readDataEntry(BOOT_DEVICE_LOCKED_STATUS, KMByteBlob.cast(blob)
        .getBuffer(),
      (short) (KMByteBlob.cast(blob).getStartOff() + length));
    return blob;
  }

  public short getVerifiedBootKey() {
    return readData(BOOT_VERIFIED_BOOT_KEY);
  }

  public short getVerifiedBootHash() {
    return readData(BOOT_VERIFIED_BOOT_HASH);
  }

  public boolean getBootLoaderLock() {
    short blob = readData(BOOT_DEVICE_LOCKED_STATUS);
    return (byte) ((getHeap())[KMByteBlob.cast(blob).getStartOff()] & 0xFE) != 0;
  }

  public byte getBootState() {
    short blob = readData(BOOT_VERIFIED_BOOT_STATE);
    return (getHeap())[KMByteBlob.cast(blob).getStartOff()];
  }

  public boolean getDeviceLock() {
    short blob = readData(DEVICE_LOCKED);
    return (byte) ((getHeap())[KMByteBlob.cast(blob).getStartOff()] & 0xFE) != 0;
  }

  public boolean getDeviceLockPasswordOnly() {
    short blob = readData(DEVICE_LOCKED);
    return (byte) ((getHeap())[KMByteBlob.cast(blob).getStartOff()] & 0xFD) != 0;
  }

  public short getDeviceTimeStamp() {
    short blob = readData(DEVICE_LOCKED_TIME);
    if (blob != 0) {
      return KMInteger.uint_64(KMByteBlob.cast(blob).getBuffer(),
        KMByteBlob.cast(blob).getStartOff());
    } else {
      return KMInteger.uint_64(zero, (short) 0);
    }
  }

  public void setOsVersion(byte[] buf, short start, short len) {
    if (len != OS_VERSION_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(BOOT_OS_VERSION, buf, start, len);
  }

  public void setVendorPatchLevel(byte[] buf, short start, short len) {
    if (len != VENDOR_PATCH_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(VENDOR_PATCH_LEVEL, buf, start, len);
  }

  public void setBootPatchLevel(byte[] buf, short start, short len) {
    if (len != BOOT_PATCH_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(BOOT_PATCH_LEVEL, buf, start, len);
  }

  public void setBootloaderLocked(boolean flag) {
    short start = alloc(DEVICE_LOCK_FLAG_SIZE);
    if (flag) {
      (getHeap())[start] = (byte) ((getHeap())[start] | 0x01);
    } else {
      (getHeap())[start] = (byte) ((getHeap())[start] & 0xFE);
    }
    writeDataEntry(BOOT_DEVICE_LOCKED_STATUS, getHeap(), start, DEVICE_LOCK_FLAG_SIZE);
  }

  public void setDeviceLock(boolean flag) {
    short start = alloc(DEVICE_LOCK_FLAG_SIZE);
    if (flag) {
      (getHeap())[start] = (byte) ((getHeap())[start] | 0x01);
    } else {
      (getHeap())[start] = (byte) ((getHeap())[start] & 0xFE);
    }
    writeDataEntry(DEVICE_LOCKED, getHeap(), start, DEVICE_LOCK_FLAG_SIZE);
  }

  public void setDeviceLockPasswordOnly(boolean flag) {
    short start = alloc(DEVICE_LOCK_FLAG_SIZE);
    if (flag) {
      (getHeap())[start] = (byte) ((getHeap())[start] | 0x02);
    } else {
      (getHeap())[start] = (byte) ((getHeap())[start] & 0xFD);
    }
    writeDataEntry(DEVICE_LOCKED, getHeap(), start, DEVICE_LOCK_FLAG_SIZE);
  }

  public void setDeviceLockTimestamp(byte[] buf, short start, short len) {
    if (len != DEVICE_LOCK_TS_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(DEVICE_LOCKED_TIME, buf, start, len);
  }

  public void clearDeviceLockTimeStamp() {
    clearDataEntry(DEVICE_LOCKED_TIME);
  }

  public void setOsPatch(byte[] buf, short start, short len) {
    if (len != OS_PATCH_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(BOOT_OS_PATCH, buf, start, len);
  }

  public void setVerifiedBootKey(byte[] buf, short start, short len) {
    if (len > BOOT_KEY_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(BOOT_VERIFIED_BOOT_KEY, buf, start, len);
  }


  public void setVerifiedBootHash(byte[] buf, short start, short len) {
    if (len > BOOT_HASH_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    writeDataEntry(BOOT_VERIFIED_BOOT_HASH, buf, start, len);
  }

  public void setBootState(byte state) {
    short start = alloc(BOOT_STATE_SIZE);
    (getHeap())[start] = state;
    writeDataEntry(BOOT_VERIFIED_BOOT_STATE, getHeap(), start, BOOT_STATE_SIZE);
  }

  @Override
  public void onSave(Element ele) {
    ele.write(dataIndex);
    ele.write(dataTable);
  }

  @Override
  public void onRestore(Element ele) {
    dataIndex = ele.readShort();
    dataTable = (byte[]) ele.readObject();
  }

  @Override
  public short getBackupPrimitiveByteCount() {
    // dataIndex
    return (short) 2;
  }

  @Override
  public short getBackupObjectCount() {
    // dataTable
    return (short) 1;
  }
}
