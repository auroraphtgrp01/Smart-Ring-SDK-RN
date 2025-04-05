import { BleManager, Device, Characteristic, State } from 'react-native-ble-plx';
import { Platform, PermissionsAndroid, Alert } from 'react-native';
import * as base64 from 'base64-js';
import {
  SERVICE_UUID,
  WRITE_UUID,
  NOTIFY_UUID,
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

// Debug function
export const logData = (prefix: string, data: number[] | Uint8Array) => {
  if (!data || data.length === 0) return;
  console.log(`${prefix}: [${Array.from(data).join(', ')}] (${data.length} bytes)`);
};
