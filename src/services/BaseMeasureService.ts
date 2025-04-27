import { Device } from 'react-native-ble-plx';
import * as base64 from 'base64-js';
import { SERVICE_UUID, NOTIFY_UUID } from '../constants';

export interface MeasurementParams {
  device: Device | null;
  notificationSubscription: any;
  setNotificationSubscription: (subscription: any) => void;
  setMeasuring: (measuring: boolean) => void;
  addLog: (message: string) => void;
}

export const setupRealDataCallback = async (
  device: Device | null,
  handleData: (data: number[], setMeasuring?: (measuring: boolean) => void) => void,
  logCallback: (message: string) => void,
  setMeasuring?: (measuring: boolean) => void,
  specificNotifyUUID?: string
): Promise<any[]> => {
  if (!device) return [];
  
  const additionalSubscriptions: any[] = [];
  
  logCallback(" Đăng ký callback nhận dữ liệu trực tiếp...");
  
  try {
    const mainSubscription = device.monitorCharacteristicForService(
      SERVICE_UUID,
      NOTIFY_UUID,
      (error, characteristic) => {
        if (error) {
          logCallback(` Lỗi nhận thông báo từ NOTIFY_UUID: ${error.message}`);
          return;
        }
        
        if (characteristic?.value) {
          const data = base64.toByteArray(characteristic.value);
          logCallback(` Dữ liệu từ NOTIFY_UUID: ${Array.from(data).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);
          
          handleData(Array.from(data), setMeasuring);
        }
      }
    );
    
    additionalSubscriptions.push(mainSubscription);
    logCallback(" Đã đăng ký lắng nghe với NOTIFY_UUID chính");
    
    if (specificNotifyUUID) {
      try {
        const specificSubscription = device.monitorCharacteristicForService(
          SERVICE_UUID,
          specificNotifyUUID,
          (error, characteristic) => {
            if (error) {
              logCallback(` Lỗi nhận thông báo từ ${specificNotifyUUID}: ${error.message}`);
              return;
            }
            
            if (characteristic?.value) {
              const data = base64.toByteArray(characteristic.value);
              logCallback(` Dữ liệu từ ${specificNotifyUUID}: ${Array.from(data).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);
              
              handleData(Array.from(data), setMeasuring);
            }
          }
        );
        
        additionalSubscriptions.push(specificSubscription);
        logCallback(` Đã đăng ký lắng nghe với UUID đặc biệt: ${specificNotifyUUID}`);
      } catch (error) {
        logCallback(` Không thể đăng ký với UUID đặc biệt ${specificNotifyUUID}: ${error}`);
      }
    }
    
    const characteristics = await device.characteristicsForService(SERVICE_UUID);
    
    if (characteristics.length > 0) {
      logCallback(` Tìm thấy ${characteristics.length} characteristics trong service`);
      
      for (const char of characteristics) {
        if (char.uuid === NOTIFY_UUID || char.uuid === specificNotifyUUID) continue;
        
        logCallback(` Thử đăng ký lắng nghe với characteristic: ${char.uuid}`);
        
        try {
          const additionalSubscription = device.monitorCharacteristicForService(
            SERVICE_UUID,
            char.uuid,
            (error, characteristic) => {
              if (error) {
                logCallback(` Lỗi nhận thông báo từ ${char.uuid}: ${error.message}`);
                return;
              }
              
              if (characteristic?.value) {
                const data = base64.toByteArray(characteristic.value);
                logCallback(` Dữ liệu từ ${char.uuid}: ${Array.from(data).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);
                
                handleData(Array.from(data), setMeasuring);
              }
            }
          );
          
          additionalSubscriptions.push(additionalSubscription);
          logCallback(` Đã đăng ký lắng nghe với characteristic: ${char.uuid}`);
        } catch (error) {
          logCallback(` Không thể đăng ký với characteristic ${char.uuid}: ${error}`);
        }
      }
    }
  } catch (error) {
    logCallback(` Lỗi khi thiết lập real data callback: ${error}`);
  }
  
  return additionalSubscriptions;
};

export const sendMeasurementCommand = async (
  device: Device | null,
  commandBytes: number[],
  logCallback: (message: string) => void,
  logMessage: string
): Promise<boolean> => {
  if (!device) {
    logCallback(" Chưa kết nối với thiết bị!");
    return false;
  }
  
  try {
    logCallback(logMessage);
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      NOTIFY_UUID,
      base64.fromByteArray(new Uint8Array(commandBytes))
    );
    return true;
  } catch (error) {
    logCallback(` Lỗi khi gửi lệnh: ${error}`);
    return false;
  }
};

export const stopMeasurement = async (
  params: MeasurementParams,
  stopCommand: number[],
  stopMessage: string
): Promise<void> => {
  const { device, notificationSubscription, setNotificationSubscription, setMeasuring, addLog } = params;
  
  addLog(stopMessage);
  setMeasuring(false);
  
  setNotificationSubscription(null);
  
  if (notificationSubscription) {
    try {
      if (typeof notificationSubscription.remove === 'function') {
        notificationSubscription.remove();
        addLog(" ✅ Đã hủy đăng ký notifications chính");
      } else {
        addLog(" ⚠️ Lưu ý: notificationSubscription.remove không phải là hàm");
      }
    } catch (error) {
      addLog(` ⚠️ Lỗi khi hủy subscription chính: ${error}`);
    }
  }
  
  if (!device) {
    addLog(" ⚠️ Không có thiết bị kết nối, không thể gửi lệnh dừng");
    return;
  }
  
  try {
    addLog(" Gửi lệnh dừng đo...");
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      NOTIFY_UUID,
      base64.fromByteArray(new Uint8Array(stopCommand))
    );
    addLog(" ✅ Đã gửi lệnh dừng đo thành công");
  } catch (error) {
    addLog(` ⚠️ Lỗi khi gửi lệnh dừng: ${error}`);
  }
};

export const setupBasicNotification = async (
  device: Device | null,
  handleData: (...args: any[]) => void,
  setNotificationSubscription: (subscription: any) => void,
  addLog: (message: string) => void,
  ...handleDataArgs: any[]
): Promise<boolean> => {
  if (!device) {
    addLog(" ⚠️ Không có thiết bị kết nối");
    return false;
  }
  
  try {
    const subscription = device.monitorCharacteristicForService(
      SERVICE_UUID,
      NOTIFY_UUID,
      (error, characteristic) => {
        if (error) {
          addLog(` Lỗi khi nhận dữ liệu: ${error.message}`);
          return;
        }
        
        if (characteristic?.value) {
          const data = base64.toByteArray(characteristic.value);
          
          handleData(Array.from(data), ...handleDataArgs);
        }
      }
    );
    
    addLog(" ✅ Đã đăng ký callback chính");
    setNotificationSubscription(subscription);
    return true;
  } catch (error) {
    addLog(` ❌ Lỗi khi thiết lập thông báo: ${error}`);
    return false;
  }
};

export const isCompletionNotification = (data: number[]): boolean => {
  return data.length >= 4 && data[0] === 0x04 && data[1] === 0x0E;
};

export const isValueInRange = (value: number, min: number, max: number): boolean => {
  return value >= min && value <= max;
};
