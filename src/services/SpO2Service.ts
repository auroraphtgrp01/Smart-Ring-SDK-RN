import { Device } from 'react-native-ble-plx';
import * as base64 from 'base64-js';
import { Alert } from 'react-native';
import {
  SERVICE_UUID,
  NOTIFY_UUID,
  BLOOD_OXYGEN_VISIBLE_MIN,
  BLOOD_OXYGEN_VISIBLE_MAX,
  SPO2_PREPARE_COMMAND,
  SPO2_START_COMMAND,
  SPO2_STOP_COMMAND
} from '../constants';

import {
  MeasurementParams,
  sendMeasurementCommand,
  stopMeasurement,
  setupBasicNotification,
  isCompletionNotification,
  isValueInRange
} from './BaseMeasureService';

export const sendSpO2Commands = async (
  device: Device | null,
  logCallback: (message: string) => void
): Promise<boolean> => {
  if (!device) {
    logCallback(" Chưa kết nối với thiết bị!");
    return false;
  }
  
  try {
    const prepareSuccess = await sendMeasurementCommand(
      device,
      SPO2_PREPARE_COMMAND,
      logCallback,
      " Đã gửi lệnh chuẩn bị đo SpO2 (Prepare SpO2)"
    );
    
    if (!prepareSuccess) {
      return false;
    }
    await new Promise(resolve => setTimeout(resolve, 500));

    const startSuccess = await sendMeasurementCommand(
      device,
      SPO2_START_COMMAND,
      logCallback,
      " Đã gửi lệnh bắt đầu đo SpO2 (Start SpO2)"
    );
    
    return startSuccess;
  } catch (error) {
    logCallback(` Lỗi khi gửi lệnh đo SpO2: ${error}`);
    return false;
  }
};

export const stopSpO2Measurement = async (
  device: Device | null,
  measuring: boolean,
  notificationSubscription: any,
  setNotificationSubscription: (subscription: any) => void,
  pollingIntervalId: NodeJS.Timeout | null,
  setPollingIntervalId: (id: NodeJS.Timeout | null) => void,
  setMeasuring: (measuring: boolean) => void,
  spo2Value: number | null,
  addLog: (message: string) => void
) => {
  if (pollingIntervalId) {
    clearInterval(pollingIntervalId);
    setPollingIntervalId(null);
    addLog(" ✅ Đã hủy polling interval");
  }
  
  const params: MeasurementParams = {
    device,
    notificationSubscription,
    setNotificationSubscription,
    setMeasuring,
    addLog
  };
  
  await stopMeasurement(
    params, 
    SPO2_STOP_COMMAND,
    " 🔴 Đang dừng đo SpO2..."
  );
  
  if (spo2Value) {
    addLog(` 📊 Kết quả đo SpO2: ${spo2Value}%`);
    Alert.alert(
      "Kết quả đo SpO2",
      `Nồng độ oxy trong máu của bạn: ${spo2Value}%`,
      [{ text: "OK" }]
    );
  } else {
    addLog(" ⚠️ Không có kết quả SpO2");
    Alert.alert(
      "Không có kết quả",
      "Không thể đo được SpO2. Vui lòng thử lại.",
      [{ text: "OK" }]
    );
  }
};

export const handleData = (
  data: number[], 
  setSpo2Value: (value: number | null) => void,
  setPrValue: (value: number | null) => void,
  setDataBuffer: (buffer: number[][]) => void,
  dataBuffer: number[][],
  addLog: (message: string) => void,
  setMeasuring?: (measuring: boolean) => void
) => {
  const hexData = data.map(b => b.toString(16).padStart(2, '0')).join(' ');
  addLog(` 📊 Nhận dữ liệu: ${hexData}`);
  
  if (isCompletionNotification(data)) {
    addLog(" 🔔 Phát hiện gói thông báo KẾT THÚC đo với mã 0x040E (1038)");
    
    if (setMeasuring) {
      addLog(" ✅ Đã nhận thông báo kết thúc đo, tự động dừng");
      setMeasuring(false);
    }
    
    return;
  }
  
  if (data.length >= 6 && data[0] === 0x06 && data[1] === 0x02) {
    const spo2Value = data[4];
    if (isValueInRange(spo2Value, BLOOD_OXYGEN_VISIBLE_MIN, BLOOD_OXYGEN_VISIBLE_MAX)) {
      addLog(` 💧 SpO2: ${spo2Value}%`);
      setSpo2Value(spo2Value);
      if (data.length >= 7) {
        const prValue = data[5];
        if (prValue > 0 && prValue < 200) {
          addLog(` 💓 PR: ${prValue} BPM`);
          setPrValue(prValue);
        }
      }
      const newBuffer = [...dataBuffer, data];
      if (newBuffer.length > 100) {
        newBuffer.shift();
      }
      setDataBuffer(newBuffer);
    } else {
      addLog(` ⚠️ Giá trị SpO2 không hợp lệ: ${spo2Value}`);
    }
    return;
  }
  
  if (data.length >= 5 && data[0] === 0x06) {
    const potentialSpo2Value = data[4];
    
    if (isValueInRange(potentialSpo2Value, BLOOD_OXYGEN_VISIBLE_MIN, BLOOD_OXYGEN_VISIBLE_MAX)) {
      addLog(` 💧 SpO2 (loại khác): ${potentialSpo2Value}%`);
      setSpo2Value(potentialSpo2Value);
      
      const newBuffer = [...dataBuffer, data];
      if (newBuffer.length > 100) {
        newBuffer.shift(); 
      }
      setDataBuffer(newBuffer);
    }
  }
};

export const setupPollingMechanism = (
  device: Device, 
  measuring: boolean,
  setSpo2Value: (value: number | null) => void,
  setPrValue: (value: number | null) => void,
  setDataBuffer: (buffer: number[][]) => void,
  dataBuffer: number[][],
  addLog: (message: string) => void,
  setPollingIntervalId: (id: NodeJS.Timeout | null) => void,
  setMeasuring?: (measuring: boolean) => void
) => {
  const intervalId = setInterval(() => {
    if (!measuring) {
      clearInterval(intervalId);
      setPollingIntervalId(null);
      return;
    }
    
    pollData(device, measuring, setSpo2Value, setPrValue, setDataBuffer, dataBuffer, addLog, setMeasuring);
  }, 1000); 
  setPollingIntervalId(intervalId);
  addLog(" ✅ Đã thiết lập polling mechanism");
};

export const pollData = async (
  device: Device | null,
  measuring: boolean,
  setSpo2Value: (value: number | null) => void,
  setPrValue: (value: number | null) => void,
  setDataBuffer: (buffer: number[][]) => void,
  dataBuffer: number[][],
  addLog: (message: string) => void,
  setMeasuring?: (measuring: boolean) => void
) => {
  if (!device || !measuring) return;
  
  try {
    const characteristic = await device.readCharacteristicForService(
      SERVICE_UUID,
      NOTIFY_UUID
    );
    
    if (characteristic && characteristic.value) {
      const data = base64.toByteArray(characteristic.value);
      
      handleData(
        Array.from(data),
        setSpo2Value,
        setPrValue,
        setDataBuffer,
        dataBuffer,
        addLog,
        setMeasuring
      );
    }
  } catch (error) {
    addLog(` ⚠️ Lỗi khi poll dữ liệu: ${error}`);
  }
};

export const startSpO2Measurement = async (
  device: Device | null,
  notificationSubscription: any,
  setNotificationSubscription: (subscription: any) => void,
  setMeasuring: (measuring: boolean) => void,
  setSpo2Value: (value: number | null) => void,
  setPrValue: (value: number | null) => void,
  setDataBuffer: (buffer: number[][]) => void,
  dataBuffer: number[][],
  addLog: (message: string) => void,
  setPollingIntervalId: (id: NodeJS.Timeout | null) => void
): Promise<boolean> => {
  if (!device) {
    addLog(" ❌ Không có thiết bị kết nối");
    return false;
  }
  
  try {
    const isConnected = await device.isConnected();
    if (!isConnected) {
      addLog(" ❌ Thiết bị đã ngắt kết nối");
      return false;
    }
    
    setNotificationSubscription(null);

    if (notificationSubscription) {
      try {
        addLog(" Hủy đăng ký thông báo trước khi bắt đầu đo mới...");
        if (typeof notificationSubscription.remove === 'function') {
          notificationSubscription.remove();
          addLog(" ✅ Đã hủy đăng ký thông báo trước đó");
        } else {
          addLog(" ⚠️ Lưu ý: notificationSubscription.remove không phải là hàm");
        }
      } catch (error) {
        addLog(` ⚠️ Không thể hủy thông báo cũ: ${error}`);
      }
    }
    
    setSpo2Value(null);
    setPrValue(null);
    
    setMeasuring(true);
    
    const setupSuccess = await setupBasicNotification(
      device,
      handleData,
      setNotificationSubscription,
      addLog,
      setSpo2Value,
      setPrValue,
      setDataBuffer,
      dataBuffer,
      addLog,
      setMeasuring
    );
    
    if (!setupSuccess) {
      addLog(" ❌ Không thể thiết lập callback");
      setMeasuring(false);
      return false;
    }
    
    setupPollingMechanism(
      device,
      true,
      setSpo2Value,
      setPrValue,
      setDataBuffer,
      dataBuffer,
      addLog,
      setPollingIntervalId,
      setMeasuring
    );
    
    addLog(" Gửi lệnh bắt đầu đo SpO2...");
    await sendSpO2Commands(device, addLog);
    
    addLog(" ✅ Đã bắt đầu đo SpO2");
    Alert.alert(
      "Đo SpO2",
      "Đang đo nồng độ oxy trong máu của bạn. Vui lòng giữ nguyên nhẫn trên ngón tay và chờ kết quả.",
      [{ text: "OK" }]
    );
    
    return true;
  } catch (error) {
    addLog(` ❌ Lỗi khi bắt đầu đo SpO2: ${error}`);
    setMeasuring(false);
    return false;
  }
};
