// SpO2ServiceRefactored.ts - Tập trung logic đo SpO2 sử dụng BaseMeasureService
import { Device } from 'react-native-ble-plx';
import * as base64 from 'base64-js';
import { Alert } from 'react-native';
import {
  SERVICE_UUID,
  WRITE_UUID,
  NOTIFY_UUID,
  BLOOD_OXYGEN_VISIBLE_MIN,
  BLOOD_OXYGEN_VISIBLE_MAX,
  SPO2_PREPARE_COMMAND,
  SPO2_START_COMMAND,
  SPO2_STOP_COMMAND
} from './constants';

import {
  MeasurementParams,
  setupRealDataCallback,
  sendMeasurementCommand,
  stopMeasurement,
  setupBasicNotification,
  isCompletionNotification,
  isValueInRange
} from './BaseMeasureService';

// Gửi lệnh đo SpO2
export const sendSpO2Commands = async (
  device: Device | null,
  logCallback: (message: string) => void
): Promise<boolean> => {
  if (!device) {
    logCallback(" Chưa kết nối với thiết bị!");
    return false;
  }
  
  try {
    // 1. Gửi lệnh chuẩn bị đo SpO2
    const prepareSuccess = await sendMeasurementCommand(
      device,
      SPO2_PREPARE_COMMAND,
      logCallback,
      " Đã gửi lệnh chuẩn bị đo SpO2 (Prepare SpO2)"
    );
    
    if (!prepareSuccess) {
      return false;
    }

    // Chờ một chút
    await new Promise(resolve => setTimeout(resolve, 500));

    // 2. Gửi lệnh bắt đầu đo SpO2
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

// Dừng đo SpO2
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
  // Hủy polling interval nếu có
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
  
  // Hiển thị kết quả nếu có
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

// Xử lý dữ liệu nhận được từ thiết bị
export const handleData = (
  data: number[], 
  setSpo2Value: (value: number | null) => void,
  setPrValue: (value: number | null) => void,
  setDataBuffer: (buffer: number[][]) => void,
  dataBuffer: number[][],
  addLog: (message: string) => void,
  setMeasuring?: (measuring: boolean) => void
) => {
  // Hiển thị dữ liệu dưới dạng hex để debug
  const hexData = data.map(b => b.toString(16).padStart(2, '0')).join(' ');
  addLog(` 📊 Nhận dữ liệu: ${hexData}`);
  
  // Kiểm tra nếu là thông báo kết thúc đo
  if (isCompletionNotification(data)) {
    addLog(" 🔔 Phát hiện gói thông báo KẾT THÚC đo với mã 0x040E (1038)");
    
    // Tự động dừng đo khi nhận được thông báo kết thúc
    if (setMeasuring) {
      addLog(" ✅ Đã nhận thông báo kết thúc đo, tự động dừng");
      setMeasuring(false);
    }
    
    return;
  }
  
  // Mẫu dữ liệu SpO2: 06 02 08 00 XX YY ZZ - với XX là giá trị SpO2, YY là PR
  if (data.length >= 6 && data[0] === 0x06 && data[1] === 0x02) {
    // Lấy giá trị SpO2 từ byte thứ 5 (index 4)
    const spo2Value = data[4];
    
    // Kiểm tra xem giá trị có nằm trong khoảng hợp lệ không
    if (isValueInRange(spo2Value, BLOOD_OXYGEN_VISIBLE_MIN, BLOOD_OXYGEN_VISIBLE_MAX)) {
      addLog(` 💧 SpO2: ${spo2Value}%`);
      setSpo2Value(spo2Value);
      
      // Lấy giá trị nhịp mạch (PR) từ byte thứ 6 (index 5)
      if (data.length >= 7) {
        const prValue = data[5];
        if (prValue > 0 && prValue < 200) {
          addLog(` 💓 PR: ${prValue} BPM`);
          setPrValue(prValue);
        }
      }
      
      // Thêm vào buffer để vẽ đồ thị
      const newBuffer = [...dataBuffer, data];
      if (newBuffer.length > 100) {
        newBuffer.shift(); // Giới hạn kích thước buffer
      }
      setDataBuffer(newBuffer);
    } else {
      addLog(` ⚠️ Giá trị SpO2 không hợp lệ: ${spo2Value}`);
    }
    return;
  }
  
  // Kiểm tra các loại gói dữ liệu khác có thể chứa SpO2
  if (data.length >= 5 && data[0] === 0x06) {
    const potentialSpo2Value = data[4];
    
    if (isValueInRange(potentialSpo2Value, BLOOD_OXYGEN_VISIBLE_MIN, BLOOD_OXYGEN_VISIBLE_MAX)) {
      addLog(` 💧 SpO2 (loại khác): ${potentialSpo2Value}%`);
      setSpo2Value(potentialSpo2Value);
      
      // Thêm vào buffer để vẽ đồ thị
      const newBuffer = [...dataBuffer, data];
      if (newBuffer.length > 100) {
        newBuffer.shift(); // Giới hạn kích thước buffer
      }
      setDataBuffer(newBuffer);
    }
  }
};

// Thiết lập polling mechanism (alternative to notifications)
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
  // Thiết lập polling interval
  const intervalId = setInterval(() => {
    if (!measuring) {
      clearInterval(intervalId);
      setPollingIntervalId(null);
      return;
    }
    
    // Đọc dữ liệu từ characteristic
    pollData(device, measuring, setSpo2Value, setPrValue, setDataBuffer, dataBuffer, addLog, setMeasuring);
  }, 1000); // Poll mỗi giây
  
  setPollingIntervalId(intervalId);
  addLog(" ✅ Đã thiết lập polling mechanism");
};

// Polling để đọc dữ liệu SpO2
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
    // Đọc giá trị từ characteristic
    const characteristic = await device.readCharacteristicForService(
      SERVICE_UUID,
      NOTIFY_UUID
    );
    
    if (characteristic && characteristic.value) {
      const data = base64.toByteArray(characteristic.value);
      
      // Xử lý dữ liệu
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

// Bắt đầu đo SpO2
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
    // Kiểm tra kết nối
    const isConnected = await device.isConnected();
    if (!isConnected) {
      addLog(" ❌ Thiết bị đã ngắt kết nối");
      return false;
    }
    
    // Hủy bỏ các subscription hiện tại nếu có
    // Đặt lại subscription để tránh lỗi khi đo lại
    setNotificationSubscription(null);
    
    // Sau đó mới thử hủy subscription cũ nếu có
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
        // Vẫn tiếp tục vì đây có thể chỉ là cảnh báo, không phải lỗi
      }
    }
    
    // Đặt lại giá trị SpO2 và PR
    setSpo2Value(null);
    setPrValue(null);
    
    // Thiết lập trạng thái đo
    setMeasuring(true);
    
    // Thiết lập callback cơ bản
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
    
    // Thiết lập polling mechanism như một phương pháp dự phòng
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
    
    // Gửi lệnh đo
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
