import { Device } from 'react-native-ble-plx';
import * as base64 from 'base64-js';
import { Alert } from 'react-native';
import {
  SERVICE_UUID,
  WRITE_UUID,
  HEART_RATE_VISIBLE_MIN,
  HEART_RATE_VISIBLE_MAX,
  HEART_RATE_PREPARE_COMMAND,
  HEART_RATE_START_COMMAND,
  HEART_RATE_STOP_COMMAND,
  HEART_RATE_NOTIFY_UUID,
  RESET_COMMAND_HR
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

export const sendHeartRateCommands = async (
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
      HEART_RATE_PREPARE_COMMAND,
      logCallback,
      " Đã gửi lệnh chuẩn bị đo nhịp tim (Prepare Heart Rate)"
    );
    
    if (!prepareSuccess) {
      return false;
    }

    await new Promise(resolve => setTimeout(resolve, 500));

    const startSuccess = await sendMeasurementCommand(
      device,
      HEART_RATE_START_COMMAND,
      logCallback,
      " Đã gửi lệnh bắt đầu đo nhịp tim (Start Heart Rate)"
    );
    
    return startSuccess;
  } catch (error) {
    logCallback(` Lỗi khi gửi lệnh đo nhịp tim: ${error}`);
    return false;
  }
};

export const stopHeartRateMeasurement = async (
  device: Device | null,
  notificationSubscription: any,
  setNotificationSubscription: (subscription: any) => void,
  setMeasuring: (measuring: boolean) => void,
  hrValue: number | null,
  addLog: (message: string) => void
) => {
  const params: MeasurementParams = {
    device,
    notificationSubscription,
    setNotificationSubscription,
    setMeasuring,
    addLog
  };
  
  await stopMeasurement(
    params, 
    HEART_RATE_STOP_COMMAND,
    " 🔴 Đang dừng đo nhịp tim..."
  );
  
  if (hrValue) {
    addLog(` 📊 Kết quả đo nhịp tim: ${hrValue} BPM`);
    Alert.alert(
      "Kết quả đo nhịp tim",
      `Nhịp tim của bạn: ${hrValue} BPM`,
      [{ text: "OK" }]
    );
  } else {
    addLog(" ⚠️ Không có kết quả nhịp tim");
    Alert.alert(
      "Không có kết quả",
      "Không thể đo được nhịp tim. Vui lòng thử lại.",
      [{ text: "OK" }]
    );  
  }
};

export const handleData = (
  data: number[], 
  setHrValue: (value: number | null) => void,
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
  
  if (data.length >= 5 && data[0] === 0x06 && data[1] === 0x01) {
    const hrValue = data[4];
    if (isValueInRange(hrValue, HEART_RATE_VISIBLE_MIN, HEART_RATE_VISIBLE_MAX)) {
      addLog(` ❤️ Nhịp tim: ${hrValue} BPM`);
      setHrValue(hrValue);
      
      const newBuffer = [...dataBuffer, data];
      if (newBuffer.length > 100) {
        newBuffer.shift(); 
      }
      setDataBuffer(newBuffer);
    } else {
      addLog(` ⚠️ Giá trị nhịp tim không hợp lệ: ${hrValue}`);
    }
    return;
  }
  
  if (data.length >= 5 && data[0] === 0x06) {
    const potentialHrValue = data[4];
    
    if (isValueInRange(potentialHrValue, HEART_RATE_VISIBLE_MIN, HEART_RATE_VISIBLE_MAX)) {
      addLog(` ❤️ Nhịp tim (loại khác): ${potentialHrValue} BPM`);
      setHrValue(potentialHrValue);
      
      const newBuffer = [...dataBuffer, data];
      if (newBuffer.length > 100) {
        newBuffer.shift();
      }
      setDataBuffer(newBuffer);
    }
  }
};

export const startHeartRateMeasurement = async (
  device: Device | null,
  notificationSubscription: any,
  setNotificationSubscription: (subscription: any) => void,
  setMeasuring: (measuring: boolean) => void,
  setHrValue: (value: number | null) => void,
  setDataBuffer: (buffer: number[][]) => void,
  dataBuffer: number[][],
  addLog: (message: string) => void
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
    
    setHrValue(null);
    
    setMeasuring(true);
    
    try {
      const resetCommand = RESET_COMMAND_HR
      
      addLog(" Gửi lệnh làm sạch trạng thái trước khi đo...");
      await device.writeCharacteristicWithResponseForService(
        SERVICE_UUID,
        WRITE_UUID,
        base64.fromByteArray(new Uint8Array(resetCommand))
      );
      
      await new Promise(resolve => setTimeout(resolve, 500));
    } catch (error) {
      addLog(` ⚠️ Lưu ý khi gửi lệnh reset: ${error}`);
    }
    
    const setupSuccess = await setupBasicNotification(
      device,
      handleData,
      setNotificationSubscription,
      addLog,
      setHrValue,
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
    
    try {
      device.monitorCharacteristicForService(
        SERVICE_UUID,
        HEART_RATE_NOTIFY_UUID,
        (error, characteristic) => {
          if (error) {
            addLog(` Lỗi nhận thông báo từ HEART_RATE_NOTIFY_UUID: ${error.message}`);
            return;
          }
          
          if (characteristic?.value) {
            const data = base64.toByteArray(characteristic.value);
            addLog(` Dữ liệu từ HEART_RATE_NOTIFY_UUID: ${Array.from(data).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);
            
            handleData(
              Array.from(data),
              setHrValue,
              setDataBuffer,
              dataBuffer,
              addLog,
              setMeasuring
            );
          }
        }
      );
      
      addLog(" ✅ Đã đăng ký thêm kênh nhịp tim");
    } catch (error) {
      addLog(` ⚠️ Không thể đăng ký kênh nhịp tim phụ: ${error}`);
    }
    
    addLog(" Gửi lệnh bắt đầu đo nhịp tim...");
    await sendHeartRateCommands(device, addLog);
    
    addLog(" ✅ Đã bắt đầu đo nhịp tim");
    Alert.alert(
      "Đo nhịp tim",
      "Đang đo nhịp tim của bạn. Vui lòng giữ nguyên nhẫn trên ngón tay và chờ kết quả.",
      [{ text: "OK" }]
    );
    
    return true;
  } catch (error) {
    addLog(` ❌ Lỗi khi bắt đầu đo nhịp tim: ${error}`);
    setMeasuring(false);
    return false;
  }
};
