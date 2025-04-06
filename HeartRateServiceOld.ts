// HeartRateService.ts - Tập trung logic đo nhịp tim cho ứng dụng
import { Device, Characteristic } from 'react-native-ble-plx';
import * as base64 from 'base64-js';
import { Alert } from 'react-native';
import {
  SERVICE_UUID,
  WRITE_UUID,
  NOTIFY_UUID,
  HEART_RATE_VISIBLE_MIN,
  HEART_RATE_VISIBLE_MAX,
  HEART_RATE_PREPARE_COMMAND,
  HEART_RATE_START_COMMAND,
  HEART_RATE_STOP_COMMAND,
  HEART_RATE_NOTIFY_UUID,
  CMD_APP_START_MEASUREMENT,
  HEART_RATE_MEASURE_TYPE,
  convertDataTypeToCommandType,
  SPO2_STOP_COMMAND
} from './constants';

// Tạo đăng ký callback để nhận dữ liệu nhịp tim trực tiếp
export const setupRealDataCallback = async (
  device: Device | null,
  handleData: (data: number[], setMeasuring?: (measuring: boolean) => void) => void,
  logCallback: (message: string) => void,
  setMeasuring?: (measuring: boolean) => void
): Promise<any[]> => {
  if (!device) return [];
  
  const additionalSubscriptions: any[] = [];
  
  logCallback(" Đăng ký callback nhận dữ liệu nhịp tim trực tiếp...");
  
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
    
    // Liệt kê tất cả các đặc tính (characteristics) của service
    const characteristics = await device.characteristicsForService(SERVICE_UUID);
    
    if (characteristics.length > 0) {
      logCallback(` Tìm thấy ${characteristics.length} characteristics trong service`);
      
      // Đăng ký lắng nghe với tất cả các đặc tính có thể notification/indication
      for (const char of characteristics) {
        if (char.uuid === NOTIFY_UUID) continue; // Bỏ qua NOTIFY_UUID vì đã lắng nghe ở trên
        
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

// Phương pháp thay thế - gửi lệnh đo nhịp tim
const sendAlternativeHeartRateCommands = async (
  device: Device | null,
  logCallback: (message: string) => void
): Promise<boolean> => {
  if (!device) return false;

  try {
    // Phương pháp 1: Sử dụng appStartMeasurement với loại = 0 cho nhịp tim
    // Dựa vào Constants.Common.HeartRateAlarm = 0 từ mã Java
    const commandData1 = [3, 47, 8, 0, 1, 0, 13, 57]; // type=0 cho Heart Rate
    
    logCallback(" Phương pháp thay thế 1: appStartMeasurement với type=0");
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(new Uint8Array(commandData1))
    );
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Phương pháp 2: Sử dụng phương thức appSensorSwitchControl (dataType 802)
    // Dựa vào phân tích mã Java - điều khiển cảm biến PPG
    const commandData2 = [3, 18, 2, 0, 1, 1, 255, 252]; // Bật cảm biến PPG (type=1)
    
    logCallback(" Phương pháp thay thế 2: appSensorSwitchControl (802) với sensor=1");
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(new Uint8Array(commandData2))
    );
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Phương pháp 3: Sử dụng settingHeartMonitor (268)
    // Dựa trên phương thức YCBTClient.settingHeartMonitor từ mã Java
    const commandData3 = [3, 12, 2, 0, 1, 30, 255, 242]; // Bật heart monitor với khoảng thời gian 30s
    
    logCallback(" Phương pháp thay thế 3: settingHeartMonitor (268) với interval=30s");
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(new Uint8Array(commandData3))
    );
    
    return true;
  } catch (error) {
    logCallback(` Lỗi khi gửi lệnh thay thế: ${error}`);
    return false;
  }
};

// Gửi lệnh đo nhịp tim dựa trên FRIDA debug logs
export const sendHeartRateCommands = async (
  device: Device | null,
  logCallback: (message: string) => void
): Promise<boolean> => {
  if (!device) {
    logCallback(" Chưa kết nối với thiết bị!");
    return false;
  }
  
  try {
    // Tiến hành theo chuỗi lệnh chính xác từ FRIDA debug logs
    logCallback(" 🔍 Tuân thủ chuỗi lệnh chính xác từ debug logs...");
    
    // 1. Dừng các đo lường đang chạy
    logCallback(" Dừng các đo lường đang chạy...");
    
    // Dừng đo SpO2 nếu đang chạy
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(new Uint8Array(SPO2_STOP_COMMAND))
    );
    logCallback(` Đã gửi lệnh dừng SpO2: [${SPO2_STOP_COMMAND.join(', ')}]`);
    
    // Dừng đo nhịp tim nếu đang chạy
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(new Uint8Array(HEART_RATE_STOP_COMMAND))
    );
    logCallback(` Đã gửi lệnh dừng nhịp tim: [${HEART_RATE_STOP_COMMAND.join(', ')}]`);
    
    // Chờ device xử lý
    await new Promise(resolve => setTimeout(resolve, 1000));

    // 2. Gửi lệnh chuẩn bị (03 09 09 00 00 00 02 90 e9)
    logCallback(" Gửi lệnh chuẩn bị màu xanh lá cảm biến...");
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(new Uint8Array(HEART_RATE_PREPARE_COMMAND))
    );
    logCallback(` Đã gửi lệnh chuẩn bị: [${HEART_RATE_PREPARE_COMMAND.join(', ')}]`);

    // Chờ device trả về ACK (03 09 07 00 00 39 89)
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // 3. Gửi lệnh bắt đầu đo nhịp tim (03 2f 08 00 01 00 4f 1b)
    // QUAN TRỌNG: phải sử dụng byte chính xác từ debug logs, đặc biệt là byte thứ 5 = 0 (khác với code cũ)
    logCallback(" Gửi lệnh bắt đầu đo nhịp tim...");
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(new Uint8Array(HEART_RATE_START_COMMAND))
    );
    logCallback(` Đã gửi lệnh START nhịp tim: [${HEART_RATE_START_COMMAND.join(', ')}]`);
    
    // 4. Đăng ký lắng nghe dữ liệu trên các UUID
    try {
      // Đăng ký lắng nghe trên NOTIFY_UUID chính (cho thông báo hoàn thành 04 0E...)
      logCallback(" Đăng ký lắng nghe trên kênh chính (NOTIFY_UUID)...");
      const mainNotification = device.monitorCharacteristicForService(
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
            
            // Xử lý thông báo hoàn thành đo lường
            if (data.length >= 3 && data[0] === 0x04 && data[1] === 0x0E) {
              logCallback(" ✅ Nhận thông báo hoàn thành đo nhịp tim!");
            }
          }
        },
        // Sử dụng transaction ID để có thể hủy bỏ sau này
        'heartRateMainNotification'
      );
      
      // Đăng ký lắng nghe trên HEART_RATE_NOTIFY_UUID - UUID này trả về dữ liệu nhịp tim
      // Mẫu từ debug: 06 01 07 00 50 58 75 - với 0x50 (80) là giá trị nhịp tim
      logCallback(" Đăng ký lắng nghe trên kênh nhịp tim (HEART_RATE_NOTIFY_UUID)...");
      const hrNotification = device.monitorCharacteristicForService(
        SERVICE_UUID,
        HEART_RATE_NOTIFY_UUID,
        (error, characteristic) => {
          if (error) {
            logCallback(` Lỗi nhận thông báo từ HEART_RATE_NOTIFY_UUID: ${error.message}`);
            return;
          }
          
          if (characteristic?.value) {
            const data = base64.toByteArray(characteristic.value);
            logCallback(` Dữ liệu từ HEART_RATE_NOTIFY_UUID: ${Array.from(data).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);
            
            // Xử lý dữ liệu nhịp tim
            if (data.length >= 5 && data[0] === 0x06 && data[1] === 0x01) {
              const hrValue = data[4] & 0xFF;
              if (hrValue >= HEART_RATE_VISIBLE_MIN && hrValue <= HEART_RATE_VISIBLE_MAX) {
                logCallback(` ❤️ Đã nhận giá trị nhịp tim: ${hrValue} BPM`);
              }
            }
          }
        },
        // Sử dụng transaction ID để có thể hủy bỏ sau này
        'heartRateSpecialNotification'
      );
    } catch (error) {
      logCallback(` Lỗi khi đăng ký lắng nghe: ${error}`);
    }
    
    // Chờ để cảm biến hoạt động (cần >= 3 giây để đèn xanh lá sáng)
    logCallback(" Đang chờ cảm biến nhịp tim hoạt động... (LED xanh lá sẽ sáng lên)");
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Gửi lệnh bắt đầu lần nữa để đảm bảo cảm biến được kích hoạt
    logCallback(" Gửi lại lệnh bắt đầu để đảm bảo cảm biến được kích hoạt...");
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(new Uint8Array(HEART_RATE_START_COMMAND))
    );
    
    logCallback(" ✅ Hoàn tất chuỗi lệnh đo nhịp tim, đang chờ kết quả...");
    return true;
  } catch (error) {
    logCallback(` ❌ Lỗi khi gửi lệnh đo nhịp tim: ${error}`);
    return false;
  }
};

// Dừng đo nhịp tim dựa trên FRIDA debug logs
export const stopHeartRateMeasurement = async (
  device: Device | null,
  notificationSubscription: any,
  setNotificationSubscription: (subscription: any) => void,
  setMeasuring: (measuring: boolean) => void,
  hrValue: number | null,
  addLog: (message: string) => void
) => {
  // Đảm bảo dừng trạng thái đo ngay lập tức
  addLog(" 🔴 Đang dừng đo nhịp tim...");
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
    addLog(" ❌ Không có thiết bị để dừng đo!");
    return;
  }
  
  try {
    // Kiểm tra xem thiết bị có thực sự được kết nối không
    let isConnected = false;
    try {
      isConnected = await device.isConnected();
    } catch (error) {
      addLog(` ❌ Thiết bị đã mất kết nối khi cố gắng dừng đo: ${error}`);
      return;
    }
    
    if (!isConnected) {
      addLog(" ❌ Thiết bị không còn kết nối khi dừng đo");
      return;
    }
    
    // 1. Gửi lệnh dừng đo chính xác từ debug logs: 03 2f 07 00 00 ee 99
    addLog(" Gửi lệnh dừng đo nhịp tim...");
    addLog(` Lệnh dừng: [${HEART_RATE_STOP_COMMAND.join(', ')}]`);
    
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(new Uint8Array(HEART_RATE_STOP_COMMAND))
    );
    
    // Chờ thiết bị xử lý
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // 2. Gửi thêm một lệnh prepare đặc biệt để làm sạch trạng thái của thiết bị
    // Dựa trên debug logs: 03 09 09 00 01 00 02 a0 de
    // Command này được thấy sau khi hoàn tất đo lường trong log
    const resetCommand = [3, 9, 9, 0, 1, 0, 2, 0xa0, 0xde];
    
    addLog(" Gửi lệnh làm sạch trạng thái thiết bị...");
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(new Uint8Array(resetCommand))
    );
    
    await new Promise(resolve => setTimeout(resolve, 500));
    
    try {
      // 3. Hủy các subscription từ thiết bị để tránh xung đột khi đo lại
      // Trong react-native-ble-plx, chúng ta chỉ cần dừng sử dụng các subscription
      // và gửi lệnh reset để đảm bảo thiết bị sạch
      addLog(" Hủy đăng ký lắng nghe trên các kênh...");
      
      // Gửi thêm lệnh disable characteristics trên cả hai kênh để đảm bảo sạch
      // Sử dụng disable notification command: 03 20 01 00 ee 99
      const disableNotifyCmd = [0x03, 0x20, 0x01, 0x00, 0xee, 0x99];
      
      // Tắt thông báo trên kênh chính
      await device.writeCharacteristicWithResponseForService(
        SERVICE_UUID,
        WRITE_UUID,
        base64.fromByteArray(new Uint8Array(disableNotifyCmd))
      ).catch((error: Error) => {
        addLog(` ⚠️ Lỗi khi tắt thông báo chính: ${error.message}`);
      });
      
      await new Promise(resolve => setTimeout(resolve, 300));
      
      // Tắt thông báo trên kênh nhịp tim
      // Sử dụng disable heart rate notification command: 03 2f 01 00 ee 99
      const disableHRNotifyCmd = [0x03, 0x2f, 0x01, 0x00, 0xee, 0x99];
      
      await device.writeCharacteristicWithResponseForService(
        SERVICE_UUID,
        WRITE_UUID,
        base64.fromByteArray(new Uint8Array(disableHRNotifyCmd))
      ).catch((error: Error) => {
        addLog(` ⚠️ Lỗi khi tắt thông báo nhịp tim: ${error.message}`);
      });
    } catch (error) {
      // Không gây lỗi nếu không thực hiện được
      addLog(` ⚠️ Lưu ý khi hủy notifications: ${error}`);
    }
    
    addLog(" ✅ Đã dừng đo nhịp tim thành công!");
    
    // Hiển thị kết quả nếu có
    if (hrValue !== null) {
      addLog(` Kết quả đo nhịp tim: ${hrValue} BPM`);
      Alert.alert(
        "Kết quả đo nhịp tim",
        `Nhịp tim của bạn là: ${hrValue} BPM`,
        [{ text: "OK" }]
      );
    }
  } catch (error) {
    addLog(` ❌ Lỗi khi dừng đo nhịp tim: ${error}`);
  }
};

// Xử lý dữ liệu nhận được từ thiết bị
export const handleData = (
  data: number[], 
  setHrValue: (value: number | null) => void,
  setDataBuffer: (buffer: number[][]) => void,
  dataBuffer: number[][],
  addLog: (message: string) => void,
  setMeasuring?: (measuring: boolean) => void
) => {
  if (!data || data.length === 0) {
    addLog(" Dữ liệu rỗng!");
    return;
  }

  // Ghi lại dữ liệu nhận được để phân tích
  const hexData = Array.from(data).map(b => b.toString(16).padStart(2, '0')).join(' ');
  addLog(` Nhận dữ liệu: ${hexData}`);
  
  // Thêm dữ liệu vào buffer để phân tích
  const newBuffer = [...dataBuffer, data];
  if (newBuffer.length > 20) newBuffer.shift(); // Giữ tối đa 20 gói tin
  setDataBuffer(newBuffer);

  // Kiểm tra mã thông báo dữ liệu nhịp tim - RealDataResponse với mã 1537
  // Theo phân tích Java code, dữ liệu nhịp tim đến với mã 1537 (0x0601) và key "heartValue"
  if (data.length >= 5 && data[0] === 0x06 && data[1] === 0x01) {
    addLog(" ✅ Phát hiện gói dữ liệu nhịp tim với mã 0x0601 (1537)");
    
    // Theo phân tích mã Java, độ dài gói tin là 7 và giá trị nhịp tim nằm ở byte thứ 5 (index 4)
    if (data.length >= 5 && data[2] === 0x07) {
      const hrValue = data[4]; // byte thứ 5 (index 4) chứa giá trị nhịp tim
      
      if (hrValue >= HEART_RATE_VISIBLE_MIN && hrValue <= HEART_RATE_VISIBLE_MAX) {
        addLog(` ✅ Phát hiện dữ liệu nhịp tim: ${hrValue} BPM`);
        setHrValue(hrValue);
        
        // Tự động dừng đo khi nhận được dữ liệu hợp lệ
        if (setMeasuring) setMeasuring(false);
        Alert.alert("Kết quả đo nhịp tim", `Nhịp tim của bạn là: ${hrValue} BPM`);
        return;
      } else {
        addLog(` ⚠️ Dữ liệu nhịp tim không hợp lệ: ${hrValue}`);
      }
    } else {
      // Nếu không đúng độ dài gói tin nhưng vẫn là mã 0x0601, tìm trong các vị trí khác
      for (let i = 2; i < data.length; i++) {
        const value = data[i] & 0xFF;
        if (value >= HEART_RATE_VISIBLE_MIN && value <= HEART_RATE_VISIBLE_MAX) {
          addLog(` Phát hiện giá trị nhịp tim ở vị trí khác trong gói 0x0601: byte[${i}]=${value} BPM`);
          setHrValue(value);
          if (setMeasuring) setMeasuring(false);
          Alert.alert("Kết quả đo nhịp tim", `Nhịp tim của bạn là: ${value} BPM`);
          return;
        }
      }
    }
  }

  // TRƯỞNG HỢP ĐẶC BIỆT: Nếu chỉ nhận được 1 byte duy nhất
  if (data.length === 1) {
    const hrValue = data[0];

    if (hrValue >= HEART_RATE_VISIBLE_MIN && hrValue <= HEART_RATE_VISIBLE_MAX) {
      addLog(` Phát hiện dữ liệu nhịp tim 1 byte: ${hrValue} BPM`);
      setHrValue(hrValue);
      // Auto-stop measurement when valid data is received
      if (setMeasuring) setMeasuring(false);
      Alert.alert("Kết quả đo nhịp tim", `Nhịp tim của bạn là: ${hrValue} BPM`);
      return;
    } else {
      addLog(` Nhận được 1 byte dữ liệu không hợp lệ: ${hrValue}`);
    }
  }

  // Kiểm tra xem đây có phải là gói phản hồi kết thúc với dataType = 1038 (0x040E) không
  // Theo phân tích Java code và debug logs, khi đo xong, thiết bị gửi thông báo với dataType = 1038
  if (data.length >= 4 && data[0] === 0x04 && data[1] === 0x0E) {
    addLog(" 🔔 Phát hiện gói thông báo KẾT THÚC đo với mã 0x040E (1038)");
    
    // Tự động dừng đo khi nhận được thông báo kết thúc
    if (setMeasuring) {
      addLog(" ✅ Đã nhận thông báo kết thúc đo, tự động dừng");
      setMeasuring(false);
    }
    
    // Kiểm tra xem đây có phải là gói dữ liệu nhịp tim không (byte[4] = 0x00/0x01 = HeartRate)
    let measurementType = 0;
    if (data.length >= 5) {
      measurementType = data[4]; // byte 5 (index 4) chứa loại đo lường
      addLog(` Loại đo lường: byte[4] = ${measurementType}`);
    }
    
    // Debug: hiển thị tất cả các byte của gói tin
    addLog(` Tất cả byte: ${data.map((b, i) => `byte[${i}]=${b}`).join(', ')}`);
    
    // Phân tích mã Java cho thấy byte[6] thường chứa giá trị nhịp tim trong gói kết thúc
    if (data.length >= 7) {
      // Kiểm tra cả byte[5] và byte[6] vì có thể chứa giá trị nhịp tim
      const potentialValues = [data[5], data[6]];
      
      for (let i = 0; i < potentialValues.length; i++) {
        const value = potentialValues[i] & 0xFF;
        const index = i + 5; // Vị trí thực trong mảng (5 hoặc 6)
        
        if (value >= HEART_RATE_VISIBLE_MIN && value <= HEART_RATE_VISIBLE_MAX) {
          addLog(` ❤️ Giá trị nhịp tim từ gói kết thúc 0x040E, byte[${index}]: ${value} BPM`);
          setHrValue(value);
          
          // Hiển thị kết quả
          Alert.alert("Kết quả đo nhịp tim", `Nhịp tim của bạn là: ${value} BPM`);
          return;
        }
      }
    }
    
    // Ngay cả khi không tìm thấy giá trị nhịp tim, vẫn dừng đo vì đã nhận được thông báo kết thúc
    // Đây là quan trọng để tránh lỗi khi đo lại
    return;
  }

  // Trường hợp 1: Kiểm tra gói dữ liệu Real-time Heart Rate (3, 61, ...)
  if (data.length >= 3 && data[0] === 3 && data[1] === 61) { // 0x3D = 61 cho Heart Rate
    addLog(" Nhận được gói dữ liệu Real-time Heart Rate (3, 61, ...)");
    const hrValue = data[2] & 0xFF; // Lấy byte đầu tiên của dữ liệu

    if (hrValue >= HEART_RATE_VISIBLE_MIN && hrValue <= HEART_RATE_VISIBLE_MAX) {
      addLog(` Giá trị nhịp tim nhận được từ gói Real-time: ${hrValue} BPM`);
      setHrValue(hrValue);
      // Auto-stop measurement when valid data is received
      if (setMeasuring) setMeasuring(false);
      Alert.alert("Kết quả đo nhịp tim", `Nhịp tim của bạn là: ${hrValue} BPM`);
      return;
    } else {
      addLog(` Giá trị nhịp tim không hợp lệ từ gói Real-time: ${hrValue}`);
    }
  }

  // Trường hợp 2: Kiểm tra gói phản hồi lệnh đo lường (3, 47, ...)
  if (data.length >= 6 && data[0] === 3 && data[1] === 47) {
    addLog(" Đã nhận gói ACK từ lệnh StartMeasurement (3, 47, ...)");
    // Chỉ là xác nhận lệnh, không có giá trị
    return;
  }
  
  // DEBUG: Kiểm tra tất cả các byte tìm giá trị nhịp tim hợp lệ 
  // (chỉ sử dụng khi các trường hợp ở trên không phát hiện được)
  for (let i = 0; i < data.length; i++) {
    const value = data[i] & 0xFF;
    if (value >= HEART_RATE_VISIBLE_MIN && value <= HEART_RATE_VISIBLE_MAX) {
      addLog(` 🔍 Tìm thấy giá trị có thể là nhịp tim tại byte[${i}]: ${value} BPM`);
    }
  }
};

// Bắt đầu đo nhịp tim
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
    addLog(" ❌ Không có thiết bị để đo nhịp tim!");
    return false;
  }
  
  try {
    // Kiểm tra xem thiết bị có được kết nối không
    let isConnected = false;
    try {
      isConnected = await device.isConnected();
    } catch (error) {
      addLog(` ❌ Thiết bị mất kết nối: ${error}`);
      return false;
    }
    
    if (!isConnected) {
      addLog(" ❌ Thiết bị không được kết nối!");
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
    
    // Đặt lại giá trị nhịp tim
    setHrValue(null);
    
    // Thiết lập trạng thái đo
    setMeasuring(true);
    
    // Gửi thêm lệnh refresh trước khi bắt đầu đo
    try {
      // Sử dụng lệnh reset thông báo: 03 09 09 00 01 00 02 a0 de
      const resetCommand = [3, 9, 9, 0, 1, 0, 2, 0xa0, 0xde];
      
      addLog(" Gửi lệnh làm sạch trạng thái trước khi đo...");
      await device.writeCharacteristicWithResponseForService(
        SERVICE_UUID,
        WRITE_UUID,
        base64.fromByteArray(new Uint8Array(resetCommand))
      );
      
      await new Promise(resolve => setTimeout(resolve, 500));
    } catch (error) {
      addLog(` ⚠️ Lưu ý khi gửi lệnh reset: ${error}`);
      // Vẫn tiếp tục, đây chỉ là bước dự phòng
    }
    
    // Thiết lập các callback để nhận dữ liệu
    addLog(" Thiết lập callback nhận dữ liệu nhịp tim...");
    
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
    
    addLog(" ✅ Đã đăng ký callback chính");
    setNotificationSubscription(subscription);
    
    // Không gọi setupRealDataCallback trực tiếp nữa để tránh xung đột subscription
    // Nếu cần, hãy đăng ký thêm kênh HEART_RATE_NOTIFY_UUID
    try {
      // Một subscription riêng cho kênh nhịp tim
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
            
            // Xử lý dữ liệu nhịp tim
            handleData(
              Array.from(data),
              setHrValue,
              setDataBuffer,
              dataBuffer,
              addLog,
              setMeasuring
            );
          }
        },
        // Bỏ transactionId để nó không gây xung đột với các subscription khác
      );
      
      addLog(" ✅ Đã đăng ký thêm kênh nhịp tim");
    } catch (error) {
      addLog(` ⚠️ Không thể đăng ký kênh nhịp tim phụ: ${error}`);
      // Vẫn tiếp tục vì đây chỉ là extra monitoring
    }
    
    // Gửi lệnh đo
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
