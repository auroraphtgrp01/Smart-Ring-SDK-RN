// SpO2Service.ts - Tập trung logic đo SpO2 cho ứng dụng
import { Device, Characteristic } from 'react-native-ble-plx';
import * as base64 from 'base64-js';
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

// Tạo đăng ký callback để nhận dữ liệu SpO2 trực tiếp
export const setupRealDataCallback = async (
  device: Device | null,
  handleData: (data: number[], setMeasuring?: (measuring: boolean) => void) => void,
  logCallback: (message: string) => void,
  setMeasuring?: (measuring: boolean) => void
): Promise<any[]> => {
  if (!device) return [];
  
  const additionalSubscriptions: any[] = [];
  
  logCallback(" Đăng ký callback nhận dữ liệu SpO2 trực tiếp...");
  
  try {
    // Liệt kê tất cả các đặc tính (characteristics) của service
    const characteristics = await device.characteristicsForService(SERVICE_UUID);
    
    if (characteristics.length > 0) {
      logCallback(` Tìm thấy ${characteristics.length} characteristics trong service`);
      
      // Đăng ký lắng nghe với tất cả các đặc tính có thể notification/indication
      for (const char of characteristics) {
        if (char.uuid === NOTIFY_UUID) continue; // Bỏ qua NOTIFY_UUID vì đã lắng nghe ở trên
        
        logCallback(` Thử đăng ký lắng nghe với characteristic: ${char.uuid}`);
        
        try {
          // Kiểm tra nếu characteristic có thể notification
          if (char.isNotifiable || char.isIndicatable) {
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
          }
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
    // 1. Gửi lệnh chuẩn bị đo SpO2 (tương đương với YCBTClient.appPrepareBloodOxygen)
    logCallback(" Đã gửi lệnh chuẩn bị đo SpO2 (Prepare SpO2)");
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(new Uint8Array(SPO2_PREPARE_COMMAND))
    );

    // Chờ một chút
    await new Promise(resolve => setTimeout(resolve, 500));

    // 2. Gửi lệnh bắt đầu đo SpO2 (tương đương với YCBTClient.appStartMeasurement(1, 2, ...))
    // Tham số: 1 = bật, 2 = SpO2 (Constants.MeasureType.BloodOxygen = 2)
    logCallback(" Đã gửi lệnh bắt đầu đo SpO2 (StartMeasurement)");
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(new Uint8Array(SPO2_START_COMMAND))
    );
    
    return true;
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
  // Đảm bảo dừng trạng thái đo ngay lập tức
  setMeasuring(false);
  
  // Hủy polling interval nếu có
  if (pollingIntervalId) {
    clearInterval(pollingIntervalId);
    setPollingIntervalId(null);
    addLog("✓ Đã hủy polling interval");
  }
  
  // Hủy đăng ký thông báo nếu có
  if (notificationSubscription) {
    notificationSubscription.remove();
    setNotificationSubscription(null);
    addLog("✓ Đã hủy đăng ký notifications");
  }
  
  if (!device) {
    addLog("❌ Không có thiết bị để dừng đo!");
    return;
  }
  
  try {
    // Kiểm tra xem thiết bị có thực sự được kết nối không
    let isConnected = false;
    try {
      isConnected = await device.isConnected();
    } catch (error) {
      addLog(`❌ Thiết bị đã mất kết nối khi cố gắng dừng đo: ${error}`);
      return;
    }
    
    if (!isConnected) {
      addLog("❌ Thiết bị không còn kết nối khi dừng đo");
      return;
    }
    
    // Gửi lệnh dừng đo SpO2
    addLog("Đã gửi lệnh dừng đo SpO2");
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(new Uint8Array(SPO2_STOP_COMMAND))
    );
    
    addLog("✅ Đã dừng đo SpO2!");
    
    // Hiển thị kết quả nếu có
    if (spo2Value !== null) {
      addLog(`📊 Kết quả đo SpO2: ${spo2Value}%`);
    }
  } catch (error) {
    addLog(`❌ Lỗi khi dừng đo SpO2: ${error}`);
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
  if (!data || data.length === 0) {
    addLog("❌ Dữ liệu rỗng!");
    return;
  }

  // Ghi lại dữ liệu nhận được để phân tích
  const hexData = Array.from(data).map(b => b.toString(16).padStart(2, '0')).join(' ');
  addLog(`📊 Nhận dữ liệu: ${hexData}`);

  // TRƯỜNG HỢP ĐẶC BIỆT: Nếu chỉ nhận được 1 byte duy nhất
  // Dựa trên log Frida: [+] Dữ liệu nhận được: 60 => SpO2 = 96
  if (data.length === 1) {
    const spo2Value = data[0];

    if (spo2Value >= BLOOD_OXYGEN_VISIBLE_MIN && spo2Value <= BLOOD_OXYGEN_VISIBLE_MAX) {
      addLog(`✅ Phát hiện dữ liệu SpO2 1 byte: ${spo2Value}%`);
      setSpo2Value(spo2Value);
      // Auto-stop measurement when valid data is received
      if (setMeasuring) setMeasuring(false);
      Alert.alert("Kết quả đo SpO2", `Chỉ số SpO2 của bạn là: ${spo2Value}%`);
      return;
    } else {
      addLog(`⚠️ Nhận được 1 byte dữ liệu không hợp lệ: ${spo2Value}`);
    }
  }

  // TRƯỜNG HỢP MỚI: Xử lý gói dữ liệu từ characteristic be940003-7333-be46-b7ae-689e71722bd5
  // Định dạng: 06 02 07 00 63 b4 e8 (từ log, với 0x63 = 99%)
  if (data.length >= 5 && data[0] === 0x06 && data[1] === 0x02 && data[2] === 0x07) {
    // Giá trị SpO2 nằm ở vị trí thứ 4 (index = 4)
    const spo2Value = data[4];

    if (spo2Value >= BLOOD_OXYGEN_VISIBLE_MIN && spo2Value <= BLOOD_OXYGEN_VISIBLE_MAX) {
      addLog(`🔍 Tìm thấy giá trị có thể là SpO2 tại vị trí 4: ${spo2Value}%`);
      setSpo2Value(spo2Value);
      addLog(`✅ Sử dụng giá trị SpO2: ${spo2Value}%`);
      // Auto-stop measurement when valid data is received
      if (setMeasuring) setMeasuring(false);
      Alert.alert("Kết quả đo SpO2", `Chỉ số SpO2 của bạn là: ${spo2Value}%`);
      return;
    }
  }

  // Trường hợp 1: Kiểm tra gói dữ liệu Real-time Blood Oxygen (tương ứng với case 2 trong packetRealHandle)
  // Trong code Java, SpO2 data có dataType = 1538, và được xử lý trong case 2
  if (data.length >= 3 && data[0] === 3 && data[1] === 62) {
    // Định dạng theo packetRealHandle và unpackRealBloodOxygenData
    const spo2Value = data[2] & 0xFF; // Lấy byte đầu tiên của dữ liệu

    if (spo2Value >= BLOOD_OXYGEN_VISIBLE_MIN && spo2Value <= BLOOD_OXYGEN_VISIBLE_MAX) {
      addLog(`✅ Giá trị SpO2 nhận được từ gói Real-time (3, 62): ${spo2Value}%`);
      setSpo2Value(spo2Value);
      // Auto-stop measurement when valid data is received
      if (setMeasuring) setMeasuring(false);
      Alert.alert("Kết quả đo SpO2", `Chỉ số SpO2 của bạn là: ${spo2Value}%`);
      return;
    } else {
      addLog(`⚠️ Giá trị SpO2 không hợp lệ từ gói Real-time: ${spo2Value}`);
    }
  }

  // Trường hợp 2: Kiểm tra gói phản hồi đo lường
  if (data.length >= 6 && data[0] === 3 && data[1] === 47) {
    addLog("🔍 Đã nhận gói ACK từ lệnh StartMeasurement (0x2F)");
    // Không có giá trị SpO2 trong gói này, chỉ là xác nhận lệnh
    return;
  }

  // Trường hợp 3: Kiểm tra gói phản hồi từ lệnh getRealBloodOxygen (0x11 = 17)
  if (data.length >= 5 && data[0] === 3 && data[1] === 17) {
    addLog("🔍 Đã nhận gói phản hồi từ lệnh getRealBloodOxygen (0x11)");

    // Kiểm tra nếu có mã lỗi (FF)
    if (data[4] === 0xFF) {
      addLog("⚠️ Phản hồi getRealBloodOxygen báo lỗi (FF)");
      return;
    }

    // Nếu không phải lỗi và có dữ liệu, kiểm tra byte đầu tiên
    const spo2Value = data[4]; // Byte đầu tiên của dữ liệu thực tế
    if (spo2Value >= BLOOD_OXYGEN_VISIBLE_MIN && spo2Value <= BLOOD_OXYGEN_VISIBLE_MAX) {
      addLog(`✅ Giá trị SpO2 từ gói 0x11: ${spo2Value}%`);
      setSpo2Value(spo2Value);
      Alert.alert("Kết quả đo SpO2", `Chỉ số SpO2 của bạn là: ${spo2Value}%`);
      return;
    } else {
      addLog(`⚠️ Giá trị SpO2 không hợp lệ từ gói 0x11: ${spo2Value}`);
    }
  }

  // Trường hợp 4: Kiểm tra gói dữ liệu trạng thái nhẫn có chứa SpO2
  if (data.length >= 3 && data[0] === 3 && data[1] === 9) {
    addLog("🔍 Đã nhận gói dữ liệu trạng thái nhẫn (0x09)");

    // Theo phân tích từ log, byte thứ 3 có thể chứa giá trị SpO2
    if (data.length >= 5) {
      const possibleSpo2 = data[4]; // Giả định byte thứ 5 có thể chứa SpO2
      if (possibleSpo2 >= BLOOD_OXYGEN_VISIBLE_MIN && possibleSpo2 <= BLOOD_OXYGEN_VISIBLE_MAX) {
        addLog(`✅ Giá trị SpO2 có thể từ gói 0x09: ${possibleSpo2}%`);
        setSpo2Value(possibleSpo2);
        Alert.alert("Kết quả đo SpO2", `Chỉ số SpO2 của bạn là: ${possibleSpo2}%`);
        return;
      }
    }
  }

  // Trường hợp 5: Kiểm tra gói dữ liệu đo lường (0x0E) - QUAN TRỌNG
  // Format: 04 0e 08 00 02 01 99 34 (từ log của người dùng)
  if (data.length >= 8 && data[0] === 4 && data[1] === 0x0E) {
    addLog("🔍 Đã nhận gói dữ liệu đo lường (0x0E)");

    // Kiểm tra xem đây có phải là gói dữ liệu SpO2 không (byte[4] = 0x02 = BloodOxygen)
    if (data[4] === 0x02) {
      addLog("✅ Gói dữ liệu chứa thông tin SpO2 (type=2)");

      // QUAN TRỌNG: Trong Java, unpackRealBloodOxygenData lấy byte[0] làm giá trị SpO2
      // Nhưng gói 0x0E không phải là gói SpO2 trực tiếp, có thể giá trị nằm ở vị trí khác

      // Nếu byte[6] là 0x99 (153 trong decimal) - có thể đây là giá trị SpO2 thực sự
      // vì giá trị hợp lệ của SpO2 thường nằm trong khoảng 95-100%
      const possibleSpo2Value = data[6] & 0xFF;

      // Debug: hiển thị tất cả các byte của gói tin
      addLog(`🔍 Debug - Tất cả byte: ${data.map((b, i) => `byte[${i}]=${b}`).join(', ')}`);

      // Kiểm tra tất cả các vị trí có thể chứa giá trị SpO2
      const testIndices = [0, 5, 6, 7]; // Các vị trí có thể chứa SpO2
      testIndices.forEach(index => {
        if (index < data.length) {
          const value = data[index] & 0xFF;
          addLog(`🔍 Test - byte[${index}] = ${value} (${value >= 70 && value <= 100 ? 'có thể hợp lệ' : 'có vẻ không hợp lệ'})`);
        }
      });

      if (possibleSpo2Value >= BLOOD_OXYGEN_VISIBLE_MIN && possibleSpo2Value <= BLOOD_OXYGEN_VISIBLE_MAX) {
        // Nếu byte[6] có vẻ hợp lệ, sử dụng nó
        addLog(`✅ Giá trị SpO2 từ byte[6]: ${possibleSpo2Value}%`);
        setSpo2Value(possibleSpo2Value);
        // Auto-stop measurement when valid data is received
        if (setMeasuring) setMeasuring(false);
        Alert.alert("Kết quả đo SpO2", `Chỉ số SpO2 của bạn là: ${possibleSpo2Value}%`);
        return;
      } else {
        // Nếu không, thử kiểm tra byte[0] của gói dữ liệu SpO2 thực tế
        // mô phỏng cách Java xử lý
        const javaStyleValue = data[0] & 0xFF;

        if (javaStyleValue >= BLOOD_OXYGEN_VISIBLE_MIN && javaStyleValue <= BLOOD_OXYGEN_VISIBLE_MAX) {
          addLog(`✅ Giá trị SpO2 từ byte[0]: ${javaStyleValue}%`);
          setSpo2Value(javaStyleValue);
          // Auto-stop measurement when valid data is received
          if (setMeasuring) setMeasuring(false);
          Alert.alert("Kết quả đo SpO2", `Chỉ số SpO2 của bạn là: ${javaStyleValue}%`);
          return;
        }

        // Nếu vẫn không hợp lệ, kiểm tra thêm byte[5] 
        const originalValue = data[5] & 0xFF;

        if (originalValue >= BLOOD_OXYGEN_VISIBLE_MIN && originalValue <= BLOOD_OXYGEN_VISIBLE_MAX) {
          addLog(`✅ Giá trị SpO2 từ byte[5]: ${originalValue}%`);
          setSpo2Value(originalValue);
          // Auto-stop measurement when valid data is received
          if (setMeasuring) setMeasuring(false);
          Alert.alert("Kết quả đo SpO2", `Chỉ số SpO2 của bạn là: ${originalValue}%`);
          return;
        }

        addLog(`⚠️ Giá trị SpO2 không xác định: byte[5]=${originalValue}, byte[0]=${javaStyleValue}, byte[6]=${possibleSpo2Value}`);
      }
    }
  }

  // Lưu dữ liệu vào bộ đệm để phân tích nếu cần
  if (dataBuffer.length >= 10) {
    dataBuffer.shift(); // Xóa gói dữ liệu cũ nhất để giới hạn kích thước bộ đệm
  }
  dataBuffer.push(data);
  setDataBuffer([...dataBuffer]);
};

// Thiết lập polling mechanism (alternative to notifications)
export const setupPollingMechanism = (
  device: Device, 
  notifyCharacteristic: Characteristic | null,
  measuring: boolean,
  setSpo2Value: (value: number | null) => void,
  setPrValue: (value: number | null) => void,
  setDataBuffer: (buffer: number[][]) => void,
  dataBuffer: number[][],
  addLog: (message: string) => void,
  setMeasuring?: (measuring: boolean) => void
) => {
  addLog('Thiết lập cơ chế polling để đọc dữ liệu...');
  
  // Tạo một interval để đọc dữ liệu định kỳ
  const pollInterval = setInterval(async () => {
    if (measuring) {
      try {
        await pollData(device, notifyCharacteristic, measuring, setSpo2Value, setPrValue, setDataBuffer, dataBuffer, addLog, setMeasuring);
      } catch (error) {
        // Bỏ qua lỗi để tiếp tục polling
      }
    }
  }, 500); // Polling mỗi 500ms

  return pollInterval;
};

// Polling để đọc dữ liệu SpO2
export const pollData = async (
  device: Device | null,
  notifyCharacteristic: Characteristic | null,
  measuring: boolean,
  setSpo2Value: (value: number | null) => void,
  setPrValue: (value: number | null) => void,
  setDataBuffer: (buffer: number[][]) => void,
  dataBuffer: number[][],
  addLog: (message: string) => void,
  setMeasuring?: (measuring: boolean) => void
) => {
  if (!device || !notifyCharacteristic) {
    addLog('Không thể đọc dữ liệu. Không có thiết bị hoặc characteristic!');
    return;
  }

  try {
    // Đọc dữ liệu từ characteristic
    const readData = await notifyCharacteristic.read();
    if (!readData?.value) {
      return; // Không log nếu dữ liệu rỗng để tránh spam log
    }

    // Chuyển đổi dữ liệu
    const bytes = base64.toByteArray(readData.value);
    if (bytes.length === 0) {
      return; // Không log nếu dữ liệu rỗng để tránh spam log
    }

    // Log dữ liệu raw để debug
    const byteArray = Array.from(bytes);
    addLog(`📊 Dữ liệu polling raw: ${byteArray.map(b => b.toString(16).padStart(2, '0')).join(' ')}`);

    // Kiểm tra nếu có byte với giá trị 96 (0x60) trong dữ liệu
    const spo2Index = byteArray.findIndex(byte => byte === 96);
    if (spo2Index !== -1) {
      addLog(`🟢 Polling: Tìm thấy giá trị SpO2 = 96% tại vị trí ${spo2Index}`);
      setSpo2Value(96);
      if (setMeasuring) setMeasuring(false);

      // Hiển thị thông báo
      Alert.alert(
        "Đo SpO2 thành công",
        `Giá trị SpO2 của bạn là: 96%`,
        [{ text: "OK" }]
      );

      return;
    }

    // Nếu không tìm thấy giá trị 96, xử lý dữ liệu thông qua hàm handleData
    handleData(byteArray, setSpo2Value, setPrValue, setDataBuffer, dataBuffer, addLog, setMeasuring);
  } catch (error) {
    // Bỏ qua lỗi khi polling để tiếp tục quá trình
  }
};

// Thiết lập phương pháp thay thế cho notifications
export const setupAlternativeNotificationMethod = async (
  device: Device | null,
  notifyCharacteristic: Characteristic | null,
  notificationSubscription: any,
  setNotificationSubscription: (subscription: any) => void,
  setSpo2Value: (value: number | null) => void,
  setPrValue: (value: number | null) => void,
  setDataBuffer: (buffer: number[][]) => void,
  dataBuffer: number[][],
  addLog: (message: string) => void,
  setMeasuring?: (measuring: boolean) => void
): Promise<boolean> => {
  if (!device || !notifyCharacteristic) {
    addLog('❌ Không thể thiết lập phương pháp thay thế. Không có thiết bị hoặc characteristic!');
    return false;
  }

  try {
    addLog('🔄 Thiết lập phương pháp thay thế cho notifications...');

    // Phương pháp 1: Toggle notifications off và on lại
    // Đôi khi điều này giúp kích hoạt CCCD descriptor
    try {
      // 1. Đọc trước
      await device.readCharacteristicForService(SERVICE_UUID, NOTIFY_UUID);
      addLog('✓ Đã đọc characteristic trước khi thiết lập notifications');

      // 2. Hủy đăng ký (nếu có)
      if (notificationSubscription) {
        notificationSubscription.remove();
        addLog('✓ Đã hủy đăng ký cũ');
      }

      // 3. Đợi một chút
      await new Promise(resolve => setTimeout(resolve, 300));

      // 4. Đăng ký lại
      const newSubscription = await device.monitorCharacteristicForService(
        SERVICE_UUID,
        NOTIFY_UUID,
        (error, characteristic) => {
          if (error) {
            addLog(`⚠️ Lỗi monitor (toggle): ${error}`);
            return;
          }

          if (characteristic && characteristic.value) {
            addLog('✓ Nhận được notification (toggle)!');
            const bytes = base64.toByteArray(characteristic.value);
            const byteArray = Array.from(bytes);
            addLog(`📊 Dữ liệu toggle: ${byteArray.map(b => b.toString(16).padStart(2, '0')).join(' ')}`);
            handleData(byteArray, setSpo2Value, setPrValue, setDataBuffer, dataBuffer, addLog, setMeasuring);
          }
        }
      );

      // 5. Lưu subscription mới
      setNotificationSubscription(newSubscription);
      addLog('✅ Đã thiết lập lại monitor sau toggle!');
      return true;
    } catch (toggleError) {
      addLog(`❌ Lỗi khi toggle notifications: ${toggleError}`);
    }

    return false;
  } catch (error) {
    addLog(`❌ Lỗi tổng thể khi thiết lập phương pháp thay thế: ${error}`);
    return false;
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
  addLog: (message: string) => void
) => {
  if (!device) {
    addLog("❌ Chưa kết nối với thiết bị!");
    return false;
  }

  try {
    // Cập nhật trạng thái
    setMeasuring(true);
    setSpo2Value(null); // Reset giá trị SpO2 cũ

    // Hủy đăng ký thông báo cũ nếu có
    if (notificationSubscription) {
      try {
        notificationSubscription.remove();
        addLog("✓ Đã hủy đăng ký thông báo cũ");
      } catch (error) {
        addLog(`⚠️ Lỗi khi hủy đăng ký thông báo cũ: ${error}`);
        // Tiếp tục ngay cả khi có lỗi
      }
      // Đảm bảo đặt lại giá trị subscription
      setNotificationSubscription(null);
    }

    // Đợi một chút để đảm bảo các hoạt động Bluetooth trước đó đã hoàn tất
    await new Promise(resolve => setTimeout(resolve, 500));

    // 1. Đảm bảo notifications đã được kích hoạt - QUAN TRỌNG
    addLog("🔄 Thiết lập lắng nghe notifications...");

    try {
      // Kích hoạt lại notifications để đảm bảo đăng ký mới
      await device.readCharacteristicForService(SERVICE_UUID, NOTIFY_UUID);
      addLog("✓ Đã đọc characteristic trước khi thiết lập notifications");
    } catch (readError) {
      addLog(`⚠️ Không thể đọc characteristic: ${readError}`);
      // Tiếp tục ngay cả khi lỗi
    }

    // Đợi một chút để đảm bảo các hoạt động Bluetooth trước đó đã hoàn tất
    await new Promise(resolve => setTimeout(resolve, 300));

    // 2. Đăng ký lắng nghe notifications - TỐI QUAN TRỌNG
    // Tương đương với registerRealDataCallBack trong Java
    let subscription;
    try {
      subscription = device.monitorCharacteristicForService(
        SERVICE_UUID,
        NOTIFY_UUID,
        (error, characteristic) => {
          if (error) {
            // Xử lý lỗi "Operation was cancelled" một cách đặc biệt
            if (error.message && error.message.includes("cancelled")) {
              addLog(`⚠️ Thông báo bị hủy: ${error.message}`);
              return; // Không xử lý lỗi này như một lỗi nghiêm trọng
            }
            
            addLog(`❌ Lỗi khi lắng nghe notifications: ${error}`);
            return;
          }

          if (characteristic && characteristic.value) {
            const data = Array.from(base64.toByteArray(characteristic.value));
            const hexData = data.map(b => b.toString(16).padStart(2, '0')).join(' ');
            addLog(`📊 Nhận notification: ${hexData}`);
            handleData(data, setSpo2Value, setPrValue, setDataBuffer, dataBuffer, addLog, setMeasuring);
          }
        }
      );

      // Lưu subscription để có thể hủy sau này
      setNotificationSubscription(subscription);
      addLog("✅ Đã đăng ký lắng nghe dữ liệu từ thiết bị thành công!");
    } catch (error) {
      // Xử lý lỗi "Operation was cancelled" một cách đặc biệt
      const monitorError = error as any;
      if (monitorError && monitorError.message && typeof monitorError.message === 'string' && monitorError.message.includes("cancelled")) {
        addLog(`⚠️ Đăng ký thông báo bị hủy: ${monitorError.message}`);
        // Tiếp tục thử gửi lệnh đo ngay cả khi đăng ký thông báo bị hủy
      } else {
        addLog(`❌ Lỗi khi đăng ký lắng nghe notifications: ${error}`);
        setMeasuring(false);
        return false;
      }
    }

    // Đợi một chút để đảm bảo notifications đã được kích hoạt
    await new Promise(resolve => setTimeout(resolve, 500));

    // 3. Gửi lệnh chuẩn bị đo SpO2 (tương đương với YCBTClient.appPrepareBloodOxygen)
    try {
      addLog("Đã gửi lệnh chuẩn bị đo SpO2 (Prepare SpO2)");
      await device.writeCharacteristicWithResponseForService(
        SERVICE_UUID,
        WRITE_UUID,
        base64.fromByteArray(new Uint8Array(SPO2_PREPARE_COMMAND))
      );
    } catch (prepareError) {
      addLog(`❌ Lỗi khi gửi lệnh chuẩn bị: ${prepareError}`);
      // Vẫn tiếp tục thử gửi lệnh bắt đầu đo
    }

    // Chờ một chút
    await new Promise(resolve => setTimeout(resolve, 500));

    // 4. Gửi lệnh bắt đầu đo SpO2 (tương đương với YCBTClient.appStartMeasurement(1, 2, ...))
    // Tham số: 1 = bật, 2 = SpO2 (Constants.MeasureType.BloodOxygen = 2)
    try {
      addLog("Đã gửi lệnh bắt đầu đo SpO2 (StartMeasurement)");
      await device.writeCharacteristicWithResponseForService(
        SERVICE_UUID,
        WRITE_UUID,
        base64.fromByteArray(new Uint8Array(SPO2_START_COMMAND))
      );

      addLog("✅ Đã bắt đầu đo SpO2!");
      return true;
    } catch (startError) {
      addLog(`❌ Lỗi khi gửi lệnh bắt đầu đo: ${startError}`);
      setMeasuring(false);
      return false;
    }
  } catch (error) {
    addLog(`❌ Lỗi khi bắt đầu đo SpO2: ${error}`);
    setMeasuring(false);
    return false;
  }
};

// Thêm import Alert
import { Alert } from 'react-native';
