// BaseMeasureService.ts - Tập trung logic đo lường cơ bản dùng chung cho các loại đo
import { Device, Characteristic } from 'react-native-ble-plx';
import * as base64 from 'base64-js';
import { SERVICE_UUID, NOTIFY_UUID } from './constants';

// Interface cho các tham số đo lường
export interface MeasurementParams {
  device: Device | null;
  notificationSubscription: any;
  setNotificationSubscription: (subscription: any) => void;
  setMeasuring: (measuring: boolean) => void;
  addLog: (message: string) => void;
}

// Tạo đăng ký callback để nhận dữ liệu đo lường trực tiếp
export const setupRealDataCallback = async (
  device: Device | null,
  handleData: (data: number[], setMeasuring?: (measuring: boolean) => void) => void,
  logCallback: (message: string) => void,
  setMeasuring?: (measuring: boolean) => void,
  specificNotifyUUID?: string // UUID đặc biệt cho một số loại đo (nếu có)
): Promise<any[]> => {
  if (!device) return [];
  
  const additionalSubscriptions: any[] = [];
  
  logCallback(" Đăng ký callback nhận dữ liệu trực tiếp...");
  
  try {
    // Đăng ký với uuid chính
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
          
          // Xử lý dữ liệu
          handleData(Array.from(data), setMeasuring);
        }
      }
    );
    
    additionalSubscriptions.push(mainSubscription);
    logCallback(" Đã đăng ký lắng nghe với NOTIFY_UUID chính");
    
    // Đăng ký với UUID đặc biệt nếu có
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
              
              // Xử lý dữ liệu từ UUID đặc biệt
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
    
    // Liệt kê tất cả các đặc tính (characteristics) của service
    const characteristics = await device.characteristicsForService(SERVICE_UUID);
    
    if (characteristics.length > 0) {
      logCallback(` Tìm thấy ${characteristics.length} characteristics trong service`);
      
      // Đăng ký lắng nghe với tất cả các đặc tính có thể notification/indication
      for (const char of characteristics) {
        // Bỏ qua các UUID đã đăng ký ở trên
        if (char.uuid === NOTIFY_UUID || char.uuid === specificNotifyUUID) continue;
        
        logCallback(` Thử đăng ký lắng nghe với characteristic: ${char.uuid}`);
        
        try {
          // Đăng ký với tất cả characteristic, không chỉ những cái isNotifiable
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
                
                // Xử lý dữ liệu từ các đặc tính khác
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

// Gửi lệnh đo lường cơ bản
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

// Dừng đo lường cơ bản
export const stopMeasurement = async (
  params: MeasurementParams,
  stopCommand: number[],
  stopMessage: string
): Promise<void> => {
  const { device, notificationSubscription, setNotificationSubscription, setMeasuring, addLog } = params;
  
  // Đảm bảo dừng trạng thái đo ngay lập tức
  addLog(stopMessage);
  setMeasuring(false);
  
  // Đặt lại subscription trước để tránh lỗi khi đo lại
  setNotificationSubscription(null);
  
  // Hủy đăng ký tất cả các subscription để tránh lỗi khi đo lại
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
    // Gửi lệnh dừng đo
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

// Thiết lập thông báo cơ bản cho đo lường
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
    // Thiết lập callback để nhận dữ liệu từ thiết bị
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
          
          // Xử lý dữ liệu nhận được
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

// Kiểm tra xem dữ liệu có phải là thông báo kết thúc đo không
export const isCompletionNotification = (data: number[]): boolean => {
  return data.length >= 4 && data[0] === 0x04 && data[1] === 0x0E;
};

// Kiểm tra giá trị đo có nằm trong khoảng hợp lệ không
export const isValueInRange = (value: number, min: number, max: number): boolean => {
  return value >= min && value <= max;
};
