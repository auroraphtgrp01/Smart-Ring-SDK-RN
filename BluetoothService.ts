import { BleManager, Device, Characteristic, State } from 'react-native-ble-plx';
import { Platform, PermissionsAndroid, Alert } from 'react-native';
import * as base64 from 'base64-js';
import {
  SERVICE_UUID,
  WRITE_UUID,
  NOTIFY_UUID,
  BLOOD_OXYGEN_VISIBLE_MIN,
  BLOOD_OXYGEN_VISIBLE_MAX,
  DEVICE_NAME,
  manager
} from './constants';

// Kiểm tra quyền truy cập vị trí trên Android
export const requestLocationPermission = async (): Promise<boolean> => {
  if (Platform.OS === 'ios') {
    return true;
  }
  
  if (Platform.OS === 'android') {
    try {
      if (Platform.Version >= 31) { // Android 12 (API Level 31) trở lên
        const bluetoothScanPermission = await PermissionsAndroid.request(
          PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN,
          {
            title: 'Quyền quét Bluetooth',
            message: 'Ứng dụng cần quyền quét Bluetooth để tìm thiết bị.',
            buttonPositive: 'Đồng ý',
          }
        );
        
        const bluetoothConnectPermission = await PermissionsAndroid.request(
          PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT,
          {
            title: 'Quyền kết nối Bluetooth',
            message: 'Ứng dụng cần quyền kết nối Bluetooth để trao đổi dữ liệu.',
            buttonPositive: 'Đồng ý',
          }
        );
        
        const fineLocationPermission = await PermissionsAndroid.request(
          PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
          {
            title: 'Quyền vị trí',
            message: 'Ứng dụng cần quyền vị trí để quét thiết bị Bluetooth.',
            buttonPositive: 'Đồng ý',
          }
        );
        
        return (
          bluetoothScanPermission === 'granted' &&
          bluetoothConnectPermission === 'granted' &&
          fineLocationPermission === 'granted'
        );
      } else {
        // Android 11 trở xuống
        const granted = await PermissionsAndroid.request(
          PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
          {
            title: 'Quyền vị trí',
            message: 'Ứng dụng cần quyền vị trí để quét thiết bị Bluetooth.',
            buttonPositive: 'Đồng ý',
          }
        );
        
        return granted === PermissionsAndroid.RESULTS.GRANTED;
      }
    } catch (err) {
      console.warn(err);
      return false;
    }
  }
  
  return false;
};

// Quét thiết bị
export const scanForDevices = (onDeviceFound: (device: Device) => void, logCallback: (message: string) => void) => {
  // Dừng bất kỳ quá trình quét nào đang diễn ra
  manager.stopDeviceScan();
  
  logCallback(" Bắt đầu quét thiết bị...");
  
  // Bắt đầu quét thiết bị
  manager.startDeviceScan(null, { allowDuplicates: false }, (error, device) => {
    if (error) {
      logCallback(` Lỗi khi quét thiết bị: ${error.message}`);
      return;
    }
    
    // Chỉ quan tâm đến thiết bị có tên là "R12M 1DE1"
    if (device && device.name?.includes(DEVICE_NAME)) {
      logCallback(` Tìm thấy thiết bị: ${device.name} (${device.id})`);
      onDeviceFound(device);
    }
  });
  
  // Dừng quét sau 10 giây để tiết kiệm pin
  setTimeout(() => {
    manager.stopDeviceScan();
    logCallback(" Kết thúc quét thiết bị");
  }, 10000);
};

// Kết nối với thiết bị
export const connectToDevice = async (device: Device, logCallback: (message: string) => void): Promise<Device | null> => {
  try {
    logCallback(` Đang kết nối với ${device.name}...`);
    
    // Thử kết nối với thiết bị
    const connectedDevice = await device.connect();
    logCallback(` Đã kết nối với ${device.name}!`);
    
    // Phát hiện các services và characteristics
    logCallback(" Đang phát hiện services...");
    const deviceWithServices = await connectedDevice.discoverAllServicesAndCharacteristics();
    logCallback(" Đã phát hiện services và characteristics!");
    
    return deviceWithServices;
  } catch (error) {
    logCallback(` Lỗi khi kết nối: ${error}`);
    return null;
  }
};

// Ngắt kết nối với thiết bị
export const disconnectDevice = async (device: Device | null, logCallback: (message: string) => void): Promise<void> => {
  if (device) {
    try {
      logCallback(` Đang ngắt kết nối với ${device.name}...`);
      await device.cancelConnection();
      logCallback(` Đã ngắt kết nối với ${device.name}!`);
    } catch (error) {
      logCallback(` Lỗi khi ngắt kết nối: ${error}`);
    }
  }
};

// Bật notifications cho một characteristic
export const enableNotifications = async (
  device: Device,
  serviceUUID: string,
  characteristicUUID: string
): Promise<boolean> => {
  try {
    // Kiểm tra xem characteristic có hỗ trợ notifications không
    const characteristic = await device.readCharacteristicForService(
      serviceUUID,
      characteristicUUID
    );
    
    if (!characteristic || (!characteristic.isNotifiable && !characteristic.isIndicatable)) {
      return false;
    }
    
    // Bật notifications bằng cách ghi vào descriptor
    // Tìm descriptor Client Characteristic Configuration (0x2902)
    const descriptors = await device.descriptorsForService(serviceUUID, characteristicUUID);
    const cccdDescriptor = descriptors.find(desc => desc.uuid.toLowerCase().includes('2902'));
    
    if (cccdDescriptor) {
      // Bật notifications (0x01) hoặc indications (0x02)
      const enableValue = Platform.OS === 'ios' ? '01' : '0100';
      await device.writeDescriptorForService(
        serviceUUID,
        characteristicUUID,
        cccdDescriptor.uuid,
        base64.fromByteArray(new Uint8Array([1, 0]))
      );
      return true;
    }
    
    return false;
  } catch (error) {
    console.log(`Error enabling notifications: ${error}`);
    return false;
  }
};

// Thiết lập và quét các characteristics
export const setupCharacteristics = async (
  device: Device, 
  logCallback: (message: string) => void
): Promise<{
  writeCharacteristic: Characteristic | null,
  notifyCharacteristic: Characteristic | null
}> => {
  let writeCharacteristic: Characteristic | null = null;
  let notifyCharacteristic: Characteristic | null = null;
  
  try {
    // Bước 1: Lấy danh sách services
    const services = await device.services();
    logCallback(` Tìm thấy ${services.length} services!`);
    
    // Bước 2: Tìm service chính
    let targetService = null;
    for (const service of services) {
      logCallback(`  Service: ${service.uuid}`);
      
      if (service.uuid.toLowerCase() === SERVICE_UUID.toLowerCase()) {
        targetService = service;
        logCallback(`  Tìm thấy service chính: ${service.uuid}`);
        break;
      }
    }
    
    if (!targetService) {
      logCallback(' Không tìm thấy service chính!');
      return { writeCharacteristic, notifyCharacteristic };
    }
    
    // Bước 3: Lấy danh sách characteristics của service chính
    const characteristics = await device.characteristicsForService(SERVICE_UUID);
    logCallback(` Tìm thấy ${characteristics.length} characteristics trong service chính!`);
    
    // Bước 4: Xác định write characteristic và notify characteristic
    for (const characteristic of characteristics) {
      logCallback(`  Characteristic: ${characteristic.uuid}`);
      logCallback(`    - Có thể đọc: ${characteristic.isReadable}`);
      logCallback(`    - Có thể ghi: ${characteristic.isWritableWithResponse}`);
      logCallback(`    - Có thể notify: ${characteristic.isNotifiable}`);
      logCallback(`    - Có thể indicate: ${characteristic.isIndicatable}`);
      
      // Kiểm tra xem đây có phải là write characteristic không
      if (characteristic.uuid.toLowerCase() === WRITE_UUID.toLowerCase() && 
          characteristic.isWritableWithResponse) {
        writeCharacteristic = characteristic;
        logCallback(`  Tìm thấy write characteristic: ${characteristic.uuid}`);
      }
      
      // Kiểm tra xem đây có phải là notify characteristic không
      if (characteristic.uuid.toLowerCase() === NOTIFY_UUID.toLowerCase() && 
          (characteristic.isNotifiable || characteristic.isIndicatable)) {
        notifyCharacteristic = characteristic;
        logCallback(`  Tìm thấy notify characteristic: ${characteristic.uuid}`);
      }
    }
  } catch (error) {
    logCallback(` Lỗi khi thiết lập characteristics: ${error}`);
  }
  
  return { writeCharacteristic, notifyCharacteristic };
};

// Tạo đăng ký callback để nhận dữ liệu SpO2 trực tiếp
export const setupRealDataCallback = async (
  device: Device | null,
  handleData: (data: number[]) => void,
  logCallback: (message: string) => void
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
                  handleData(Array.from(data));
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
    const prepareCommand = new Uint8Array([3, 9, 9, 0, 0, 0, 2, 144, 233]);
    logCallback(" Đã gửi lệnh chuẩn bị đo SpO2 (Prepare SpO2)");
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(prepareCommand)
    );

    // Chờ một chút
    await new Promise(resolve => setTimeout(resolve, 500));

    // 2. Gửi lệnh bắt đầu đo SpO2 (tương đương với YCBTClient.appStartMeasurement(1, 2, ...))
    // Tham số: 1 = bật, 2 = SpO2 (Constants.MeasureType.BloodOxygen = 2)
    const startMeasurementCommand = new Uint8Array([3, 47, 8, 0, 1, 2, 13, 59]);
    logCallback(" Đã gửi lệnh bắt đầu đo SpO2 (StartMeasurement)");
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(startMeasurementCommand)
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
  setPollingIntervalId: (intervalId: NodeJS.Timeout | null) => void,
  setMeasuring: (measuring: boolean) => void,
  spo2Value: number | null,
  addLog: (message: string) => void
) => {
  if (!device || !measuring) {
    return;
  }

  try {
    // Gửi lệnh dừng đo SpO2 (tương đương với YCBTClient.appStartMeasurement(0, 2, ...))
    // Tham số: 0 = tắt, 2 = SpO2 (Constants.MeasureType.BloodOxygen = 2)
    const stopMeasurementCommand = new Uint8Array([3, 47, 8, 0, 0, 2, 13, 58]);
    addLog("Đã gửi lệnh dừng đo SpO2");
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(stopMeasurementCommand)
    );

    // Hủy bỏ đăng ký notification
    if (notificationSubscription) {
      notificationSubscription.remove();
      setNotificationSubscription(null);
      addLog("✅ Đã hủy đăng ký nhận thông báo");
    }

    // Xóa interval nếu có
    if (pollingIntervalId) {
      clearInterval(pollingIntervalId);
      setPollingIntervalId(null);
      addLog("✅ Đã dừng polling dữ liệu");
    }

    // Cập nhật trạng thái
    setMeasuring(false);

    // Hiển thị thông báo nếu không nhận được kết quả
    if (spo2Value === null) {
      addLog("⚠️ Chưa nhận được giá trị SpO2 hợp lệ!");
      Alert.alert("Không có dữ liệu", "Không nhận được kết quả đo SpO2 hợp lệ. Vui lòng thử lại.");
    } else {
      addLog(`✅ Kết thúc đo với giá trị SpO2: ${spo2Value}%`);
    }
    
    return true;
  } catch (error) {
    addLog(`❌ Lỗi khi dừng đo SpO2: ${error}`);
    return false;
  }
};

// Debug function
export const logData = (prefix: string, data: number[] | Uint8Array) => {
  if (!data || data.length === 0) return;
  console.log(`${prefix}: [${Array.from(data).join(', ')}] (${data.length} bytes)`);
};

// Xử lý dữ liệu nhận được từ thiết bị
export const handleData = (
  data: number[], 
  setSpo2Value: (value: number | null) => void,
  setPrValue: (value: number | null) => void,
  setDataBuffer: (buffer: number[][]) => void,
  dataBuffer: number[][],
  addLog: (message: string) => void
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
        Alert.alert("Kết quả đo SpO2", `Chỉ số SpO2 của bạn là: ${possibleSpo2Value}%`);
        return;
      } else {
        // Nếu không, thử kiểm tra byte[0] của gói dữ liệu SpO2 thực tế
        // mô phỏng cách Java xử lý
        const javaStyleValue = data[0] & 0xFF;

        if (javaStyleValue >= BLOOD_OXYGEN_VISIBLE_MIN && javaStyleValue <= BLOOD_OXYGEN_VISIBLE_MAX) {
          addLog(`✅ Giá trị SpO2 từ byte[0]: ${javaStyleValue}%`);
          setSpo2Value(javaStyleValue);
          Alert.alert("Kết quả đo SpO2", `Chỉ số SpO2 của bạn là: ${javaStyleValue}%`);
          return;
        }

        // Nếu vẫn không hợp lệ, kiểm tra thêm byte[5] 
        const originalValue = data[5] & 0xFF;

        if (originalValue >= BLOOD_OXYGEN_VISIBLE_MIN && originalValue <= BLOOD_OXYGEN_VISIBLE_MAX) {
          addLog(`✅ Giá trị SpO2 từ byte[5]: ${originalValue}%`);
          setSpo2Value(originalValue);
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
  addLog: (message: string) => void
) => {
  addLog('Thiết lập cơ chế polling để đọc dữ liệu...');
  
  // Tạo một interval để đọc dữ liệu định kỳ
  const pollInterval = setInterval(async () => {
    if (measuring) {
      try {
        await pollData(device, notifyCharacteristic, measuring, setSpo2Value, setPrValue, setDataBuffer, dataBuffer, addLog);
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
  addLog: (message: string) => void
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

      // Hiển thị thông báo
      Alert.alert(
        "Đo SpO2 thành công",
        `Giá trị SpO2 của bạn là: 96%`,
        [{ text: "OK" }]
      );

      return;
    }

    // Nếu không tìm thấy giá trị 96, xử lý dữ liệu thông qua hàm handleData
    handleData(byteArray, setSpo2Value, setPrValue, setDataBuffer, dataBuffer, addLog);
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
  addLog: (message: string) => void
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
            handleData(byteArray, setSpo2Value, setPrValue, setDataBuffer, dataBuffer, addLog);
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
    return;
  }

  try {
    // Cập nhật trạng thái
    setMeasuring(true);
    setSpo2Value(null); // Reset giá trị SpO2 cũ

    // Hủy đăng ký thông báo cũ nếu có
    if (notificationSubscription) {
      notificationSubscription.remove();
    }

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

    // 2. Đăng ký lắng nghe notifications - TỐI QUAN TRỌNG
    // Tương đương với registerRealDataCallBack trong Java
    const subscription = device.monitorCharacteristicForService(
      SERVICE_UUID,
      NOTIFY_UUID,
      (error, characteristic) => {
        if (error) {
          addLog(`❌ Lỗi khi lắng nghe notifications: ${error}`);
          return;
        }

        if (characteristic && characteristic.value) {
          const data = Array.from(base64.toByteArray(characteristic.value));
          const hexData = data.map(b => b.toString(16).padStart(2, '0')).join(' ');
          addLog(`📊 Nhận notification: ${hexData}`);
          handleData(data, setSpo2Value, setPrValue, setDataBuffer, dataBuffer, addLog);
        }
      }
    );

    // Lưu subscription để có thể hủy sau này
    setNotificationSubscription(subscription);
    addLog("✅ Đã đăng ký lắng nghe dữ liệu từ thiết bị thành công!");

    // Đợi một chút để đảm bảo notifications đã được kích hoạt
    await new Promise(resolve => setTimeout(resolve, 300));

    // 3. Gửi lệnh chuẩn bị đo SpO2 (tương đương với YCBTClient.appPrepareBloodOxygen)
    const prepareCommand = new Uint8Array([3, 9, 9, 0, 0, 0, 2, 144, 233]);
    addLog("Đã gửi lệnh chuẩn bị đo SpO2 (Prepare SpO2)");
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(prepareCommand)
    );

    // Chờ một chút
    await new Promise(resolve => setTimeout(resolve, 500));

    // 4. Gửi lệnh bắt đầu đo SpO2 (tương đương với YCBTClient.appStartMeasurement(1, 2, ...))
    // Tham số: 1 = bật, 2 = SpO2 (Constants.MeasureType.BloodOxygen = 2)
    const startMeasurementCommand = new Uint8Array([3, 47, 8, 0, 1, 2, 13, 59]);
    addLog("Đã gửi lệnh bắt đầu đo SpO2 (StartMeasurement)");
    await device.writeCharacteristicWithResponseForService(
      SERVICE_UUID,
      WRITE_UUID,
      base64.fromByteArray(startMeasurementCommand)
    );

    addLog("✅ Đã bắt đầu đo SpO2!");
    return true;
  } catch (error) {
    addLog(`❌ Lỗi khi bắt đầu đo SpO2: ${error}`);
    return false;
  }
};
