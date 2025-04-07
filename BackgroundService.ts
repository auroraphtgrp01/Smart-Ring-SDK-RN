import { AppState, AppStateStatus, Platform, NativeEventEmitter, NativeModules } from 'react-native';
import { Device } from 'react-native-ble-plx';
import { manager, DEVICE_NAME } from './constants';
import { scanForDevices, connectToDevice } from './BluetoothService';

// Lưu trữ thông tin thiết bị đã kết nối trong bộ nhớ
let lastConnectedDevice: { id: string, name: string } | null = null;

// Lưu thông tin thiết bị đã kết nối
export const saveConnectedDevice = (device: Device) => {
  try {
    lastConnectedDevice = {
      id: device.id,
      name: device.name || 'Unknown Device'
    };
    console.log('Đã lưu thông tin thiết bị:', lastConnectedDevice);
  } catch (error) {
    console.error('Lỗi khi lưu thông tin thiết bị:', error);
  }
};

// Lấy thông tin thiết bị đã kết nối trước đó
export const getLastConnectedDevice = (): { id: string, name: string } | null => {
  return lastConnectedDevice;
};

// Xóa thông tin thiết bị đã kết nối
export const clearLastConnectedDevice = () => {
  lastConnectedDevice = null;
  console.log('Đã xóa thông tin thiết bị đã kết nối trước đó');
};

class BackgroundConnectionService {
  private reconnectTimer: NodeJS.Timeout | null = null;
  private appState: AppStateStatus = 'active';
  private currentConnectedDevice: Device | null = null;
  private isScanning: boolean = false;
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 10; // Giới hạn số lần thử kết nối lại
  private logCallback: (message: string) => void = console.log;

  constructor() {
    // Khởi tạo theo dõi trạng thái ứng dụng
    this.subscribeToAppState();
  }
  
  // Đăng ký lắng nghe sự kiện AppState
  private subscribeToAppState() {
    // Sử dụng cách tiếp cận tương thích với cả phiên bản cũ và mới của React Native
    this.appStateSubscription = { remove: () => {} };
    
    // Sử dụng useEffect để đăng ký sự kiện
    const subscription = AppState.addEventListener('change', this.handleAppStateChange);
    
    // Lưu hàm remove để có thể gọi sau này
    this.appStateSubscription = subscription || { remove: () => {} };
  }

  // Thiết lập callback cho log
  setLogCallback(callback: (message: string) => void) {
    this.logCallback = callback;
  }

  // Xử lý khi trạng thái ứng dụng thay đổi
  private handleAppStateChange = (nextAppState: AppStateStatus) => {
    this.logCallback(`Trạng thái ứng dụng thay đổi: ${this.appState} -> ${nextAppState}`);
    
    // Nếu ứng dụng chuyển từ background sang active
    if (this.appState.match(/inactive|background/) && nextAppState === 'active') {
      this.logCallback('Ứng dụng trở lại foreground');
      // Kiểm tra kết nối hiện tại
      this.checkConnectionStatus();
    } 
    // Nếu ứng dụng chuyển từ active sang background
    else if (this.appState === 'active' && nextAppState.match(/inactive|background/)) {
      this.logCallback('Ứng dụng chuyển sang background');
      
      // Nếu đang không có kết nối và có thiết bị đã kết nối trước đó, bắt đầu quét
      if (!this.currentConnectedDevice) {
        this.startReconnectTimer();
      } else {
        // Đảm bảo kết nối vẫn được duy trì khi ở background
        this.logCallback('Duy trì kết nối Bluetooth trong background');
        this.keepConnectionAlive();
      }
    }
    
    this.appState = nextAppState;
  };

  // Thiết lập thiết bị hiện tại
  setCurrentDevice(device: Device | null) {
    this.currentConnectedDevice = device;
    
    // Nếu có thiết bị mới được kết nối, lưu thông tin
    if (device) {
      this.logCallback(`Đã thiết lập thiết bị hiện tại: ${device.name} (${device.id})`);
      saveConnectedDevice(device);
      this.stopReconnectTimer(); // Dừng timer nếu đang chạy
      this.reconnectAttempts = 0; // Reset số lần thử kết nối
      
      // Nếu ứng dụng đang ở background, đảm bảo kết nối được duy trì
      if (this.appState.match(/inactive|background/)) {
        this.keepConnectionAlive();
      }
    } else {
      this.logCallback('Đã xóa thiết bị hiện tại');
      
      // Nếu ứng dụng đang ở background, bắt đầu quét lại
      if (this.appState.match(/inactive|background/)) {
        this.startReconnectTimer();
      }
    }
  }

  // Kiểm tra trạng thái kết nối hiện tại
  private async checkConnectionStatus() {
    if (this.currentConnectedDevice) {
      try {
        // Kiểm tra xem thiết bị còn kết nối không
        const isConnected = await this.currentConnectedDevice.isConnected();
        this.logCallback(`Kiểm tra kết nối: ${isConnected ? 'Đang kết nối' : 'Đã mất kết nối'}`);
        
        if (!isConnected) {
          // Nếu mất kết nối, bắt đầu quét lại
          this.currentConnectedDevice = null;
          this.startReconnectTimer();
        }
      } catch (error) {
        this.logCallback(`Lỗi khi kiểm tra kết nối: ${error}`);
        this.currentConnectedDevice = null;
        this.startReconnectTimer();
      }
    } else {
      // Nếu không có thiết bị hiện tại, kiểm tra xem có thiết bị đã kết nối trước đó không
      this.startReconnectTimer();
    }
  }

  // Bắt đầu timer để quét và kết nối lại
  startReconnectTimer() {
    // Dừng timer hiện tại nếu có
    this.stopReconnectTimer();
    
    // Bắt đầu timer mới, quét mỗi 10 giây
    this.reconnectTimer = setInterval(async () => {
      // Kiểm tra số lần thử kết nối
      if (this.reconnectAttempts >= this.maxReconnectAttempts) {
        this.logCallback(`Đã đạt giới hạn thử kết nối (${this.maxReconnectAttempts} lần). Dừng quét.`);
        this.stopReconnectTimer();
        return;
      }
      
      // Tăng số lần thử kết nối
      this.reconnectAttempts++;
      
      // Nếu đang quét, bỏ qua
      if (this.isScanning) {
        return;
      }
      
      // Lấy thông tin thiết bị đã kết nối trước đó
      const lastDevice = getLastConnectedDevice();
      if (!lastDevice) {
        this.logCallback('Không có thông tin thiết bị đã kết nối trước đó');
        this.stopReconnectTimer();
        return;
      }
      
      this.logCallback(`Quét lại thiết bị đã kết nối trước đó: ${lastDevice.name} (${lastDevice.id})`);
      this.scanForLastDevice(lastDevice.id);
    }, 10000); // 10 giây
    
    this.logCallback('Đã bắt đầu timer quét lại thiết bị');
  }

  // Dừng timer quét và kết nối lại
  private stopReconnectTimer() {
    if (this.reconnectTimer) {
      clearInterval(this.reconnectTimer);
      this.reconnectTimer = null;
      this.logCallback('Đã dừng timer quét lại thiết bị');
    }
  }

  // Quét tìm thiết bị đã kết nối trước đó
  private scanForLastDevice(lastDeviceId: string) {
    if (this.isScanning) {
      return;
    }
    
    this.isScanning = true;
    this.logCallback('Bắt đầu quét tìm thiết bị đã kết nối trước đó...');
    
    // Dừng bất kỳ quá trình quét nào đang diễn ra
    manager.stopDeviceScan();
    
    // Bắt đầu quét thiết bị
    manager.startDeviceScan(null, { allowDuplicates: false }, async (error, device) => {
      if (error) {
        this.logCallback(`Lỗi khi quét thiết bị: ${error.message}`);
        this.isScanning = false;
        return;
      }
      
      // Kiểm tra xem có phải thiết bị cần tìm không
      if (device && (device.id === lastDeviceId || (device.name && device.name.includes(DEVICE_NAME)))) {
        this.logCallback(`Tìm thấy thiết bị đã kết nối trước đó: ${device.name} (${device.id})`);
        
        // Dừng quét
        manager.stopDeviceScan();
        this.isScanning = false;
        
        // Kết nối lại với thiết bị
        try {
          const connectedDevice = await connectToDevice(device, this.logCallback);
          if (connectedDevice) {
            this.logCallback(`Đã kết nối lại với thiết bị: ${connectedDevice.name}`);
            this.setCurrentDevice(connectedDevice);
          }
        } catch (error) {
          this.logCallback(`Lỗi khi kết nối lại với thiết bị: ${error}`);
        }
      }
    });
    
    // Dừng quét sau 5 giây để tiết kiệm pin
    setTimeout(() => {
      if (this.isScanning) {
        manager.stopDeviceScan();
        this.isScanning = false;
        this.logCallback('Kết thúc quét thiết bị');
      }
    }, 5000);
  }

  // Biến lưu trữ subscription
  private appStateSubscription: { remove: () => void } | null = null;
  
  // Giữ kết nối Bluetooth hoạt động trong background
  private keepConnectionAlive() {
    if (!this.currentConnectedDevice) return;
    
    // Tạo một hàm để thực hiện ping đến thiết bị
    const pingDevice = async () => {
      try {
        if (this.currentConnectedDevice) {
          // Kiểm tra xem thiết bị có còn kết nối không
          const isConnected = await this.currentConnectedDevice.isConnected();
          if (isConnected) {
            this.logCallback('Giữ kết nối Bluetooth: thiết bị vẫn đang kết nối');
            
            // Thực hiện một thao tác đọc đơn giản để giữ kết nối
            try {
              const services = await this.currentConnectedDevice.services();
              if (services && services.length > 0) {
                this.logCallback(`Ping thiết bị thành công: ${services.length} services`);
              }
            } catch (readError) {
              this.logCallback(`Lỗi khi ping thiết bị: ${readError}`);
            }
          } else {
            this.logCallback('Thiết bị đã mất kết nối, bắt đầu quét lại');
            this.setCurrentDevice(null);
            this.startReconnectTimer();
          }
        }
      } catch (error) {
        this.logCallback(`Lỗi khi kiểm tra kết nối: ${error}`);
        // Nếu có lỗi, giả định thiết bị đã mất kết nối
        this.setCurrentDevice(null);
        this.startReconnectTimer();
      }
    };
    
    // Thực hiện ping ngay lập tức
    pingDevice();
    
    // Sau đó thiết lập ping định kỳ
    const keepAliveInterval = setInterval(pingDevice, 5000); // 5 giây ping một lần
    
    // Đảm bảo interval được xóa khi AppState thay đổi
    const appStateSubscription = AppState.addEventListener('change', (nextState: AppStateStatus) => {
      if (nextState === 'active') {
        clearInterval(keepAliveInterval);
        appStateSubscription.remove();
      }
    });
  }

  // Hủy dịch vụ
  destroy() {
    this.stopReconnectTimer();
    
    // Hủy đăng ký lắng nghe sự kiện AppState
    if (this.appStateSubscription) {
      this.appStateSubscription.remove();
      this.appStateSubscription = null;
    }
    
    this.logCallback('Đã hủy dịch vụ kết nối nền');
  }
}

// Tạo và xuất instance duy nhất của dịch vụ
export const backgroundService = new BackgroundConnectionService();
