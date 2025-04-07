import React, { useState, useEffect, useRef } from 'react';
import { StyleSheet, Text, View, TouchableOpacity, ScrollView, Alert, Platform, AppState, AppStateStatus } from 'react-native';
import { Device, Characteristic } from 'react-native-ble-plx';
import {
  manager,
  SERVICE_UUID,
  WRITE_UUID,
  NOTIFY_UUID
} from './constants';

// Import BackgroundService
import { backgroundService, getLastConnectedDevice } from './BackgroundService';

import {
  // Functionsr
  requestLocationPermission,
  scanForDevices,
  connectToDevice,
  disconnectDevice,
  enableNotifications,
  setupCharacteristics,
  logData
} from './BluetoothService';

import {
  // SpO2 related functions
  sendSpO2Commands,
  stopSpO2Measurement,
  handleData,
  setupPollingMechanism,
  pollData,
  startSpO2Measurement
} from './SpO2Service';

// Import các hàm từ HeartRateService
import {
  sendHeartRateCommands,
  stopHeartRateMeasurement,
  handleData as handleHeartRateData,
  startHeartRateMeasurement
} from './HeartRateService';

// Import các hàm từ BaseMeasureService
import {
  setupRealDataCallback
} from './BaseMeasureService';

// Main App
export default function App() {
  // State variables
  const [logs, setLogs] = useState<string[]>([]);
  const [scanning, setScanning] = useState<boolean>(false);
  const [device, setDevice] = useState<Device | null>(null);
  const [bluetoothReady, setBluetoothReady] = useState<boolean>(false);
  const [writeCharacteristic, setWriteCharacteristic] = useState<Characteristic | null>(null);
  const [notifyCharacteristic, setNotifyCharacteristic] = useState<Characteristic | null>(null);
  const [spo2Value, setSpo2Value] = useState<number | null>(null);
  const [dataBuffer, setDataBuffer] = useState<number[][]>([]);
  const [pollingIntervalId, setPollingIntervalId] = useState<NodeJS.Timeout | null>(null);
  const [notificationSubscription, setNotificationSubscription] = useState<any>(null);
  const [additionalSubscriptions, setAdditionalSubscriptions] = useState<any[]>([]);
  const [measuring, setMeasuring] = useState(false);
  const [prValue, setPrValue] = useState<number | null>(null); // Pulse Rate - Nhịp tim
  const [isDiscoverService, setIsDiscoverService] = useState<boolean>(false);
  const [devices, setDevices] = useState<Device[]>([]);

  // Thêm state cho nhịp tim
  const [measuringHeartRate, setMeasuringHeartRate] = useState(false);
  const [hrValue, setHrValue] = useState<number | null>(null); // Heart Rate - Nhịp tim riêng biệt
  const [hrDataBuffer, setHrDataBuffer] = useState<number[][]>([]);
  const [hrNotificationSubscription, setHrNotificationSubscription] = useState<any>(null);
  
  // Thêm state cho theo dõi trạng thái ứng dụng và kết nối
  const [appState, setAppState] = useState<AppStateStatus>(AppState.currentState);
  const [connectionCheckTimer, setConnectionCheckTimer] = useState<NodeJS.Timeout | null>(null);

  // Logging function
  const addLog = (message: string) => {
    console.log(message);
    setLogs(prev => [...prev, `${new Date().toLocaleTimeString()}: ${message}`]);
  };

  // Kiểm tra trạng thái kết nối của thiết bị
  const checkDeviceConnection = async () => {
    if (device) {
      try {
        const isConnected = await device.isConnected();
        if (!isConnected) {
          addLog("⚠️ Thiết bị đã mất kết nối!");
          // Thông báo cho BackgroundService trước
          backgroundService.setCurrentDevice(null);
          
          // Reset trạng thái ứng dụng
          setDevice(null);
          setWriteCharacteristic(null);
          setNotifyCharacteristic(null);
          setIsDiscoverService(false);
          setSpo2Value(null);
          setPrValue(null);
          setHrValue(null);
          setMeasuring(false);
          setMeasuringHeartRate(false);
          
          // Bắt đầu quét lại nếu cần
          backgroundService.startReconnectTimer();
        } else {
          addLog("✅ Thiết bị vẫn đang kết nối");
          // Đảm bảo thiết bị được đăng ký với BackgroundService
          backgroundService.setCurrentDevice(device);
          
          // Nếu ứng dụng đang ở background, đảm bảo kết nối được duy trì
          if (appState !== 'active') {
            backgroundService.keepConnectionAlive();
          }
        }
      } catch (error) {
        addLog(`❌ Lỗi khi kiểm tra kết nối: ${error}`);
      }
    }
  };

  // Theo dõi trạng thái của ứng dụng (foreground/background)
  useEffect(() => {
    // Lắng nghe sự kiện thay đổi trạng thái ứng dụng
    const appStateSubscription = AppState.addEventListener('change', handleAppStateChange);
    
    // Thiết lập kiểm tra kết nối định kỳ
    startConnectionCheckTimer();
    
    // Cleanup function
    return () => {
      appStateSubscription.remove();
      stopConnectionCheckTimer();
    };
  }, [device]); // Chỉ chạy lại khi device thay đổi
  
  // Xử lý khi trạng thái ứng dụng thay đổi
  const handleAppStateChange = (nextAppState: AppStateStatus) => {
    addLog(`Trạng thái ứng dụng thay đổi: ${appState} -> ${nextAppState}`);
    
    // Nếu ứng dụng chuyển từ background sang active
    if (appState.match(/inactive|background/) && nextAppState === 'active') {
      addLog('Ứng dụng trở lại foreground');
      // Kiểm tra kết nối hiện tại
      checkDeviceConnection();
    } 
    // Nếu ứng dụng chuyển từ active sang background
    else if (appState === 'active' && nextAppState.match(/inactive|background/)) {
      addLog('Ứng dụng chuyển sang background');
      
      if (device) {
        // Đảm bảo kết nối vẫn được duy trì khi ở background
        addLog('Duy trì kết nối Bluetooth trong background');
        backgroundService.setCurrentDevice(device);
        backgroundService.keepConnectionAlive();
      } else {
        // Nếu không có thiết bị hiện tại, bắt đầu quét trong background
        addLog('Không có thiết bị kết nối, bắt đầu quét trong background');
        backgroundService.startReconnectTimer();
      }
    }
    
    // Cập nhật trạng thái hiện tại
    setAppState(nextAppState);
  };
  
  // Bắt đầu timer kiểm tra kết nối định kỳ
  const startConnectionCheckTimer = () => {
    // Dừng timer hiện tại nếu có
    stopConnectionCheckTimer();
    
    // Thiết lập timer mới, kiểm tra mỗi 15 giây
    const timer = setInterval(() => {
      if (device) {
        addLog('Kiểm tra kết nối định kỳ');
        checkDeviceConnection();
      }
    }, 15000); // 15 giây
    
    setConnectionCheckTimer(timer);
    addLog('Đã bắt đầu timer kiểm tra kết nối định kỳ');
  };
  
  // Dừng timer kiểm tra kết nối
  const stopConnectionCheckTimer = () => {
    if (connectionCheckTimer) {
      clearInterval(connectionCheckTimer);
      setConnectionCheckTimer(null);
      addLog('Đã dừng timer kiểm tra kết nối');
    }
  };
  
  // Xử lý khi thiết bị được kết nối lại từ BackgroundService
  const handleDeviceReconnected = async (reconnectedDevice: Device) => {
    addLog(`Thiết bị được kết nối lại từ background: ${reconnectedDevice.name}`);
    
    // Kiểm tra nếu đã có thiết bị được đặt trước đó
    if (device && device.id === reconnectedDevice.id) {
      addLog('Đã có thiết bị này trong UI, không cần cập nhật lại');
      return;
    }
    
    // Cập nhật trạng thái UI
    setDevice(reconnectedDevice);
    
    // Thiết lập các đặc tính (characteristics) cần thiết
    try {
      // Thiết lập các đặc tính
      const { writeCharacteristic: writeChar, notifyCharacteristic: notifyChar } = await setupCharacteristics(reconnectedDevice, addLog);
      
      // Cập nhật state
      setWriteCharacteristic(writeChar);
      setNotifyCharacteristic(notifyChar);
      setIsDiscoverService(true);
      
      addLog('Đã thiết lập lại các đặc tính sau khi kết nối lại');
      
      // Bắt đầu lại các đo lường nếu trước đó đang đo
      if (measuring) {
        addLog('Tự động bắt đầu lại đo SpO2 sau khi kết nối lại');
        setTimeout(() => {
          startMeasurementLocal();
        }, 1000);
      }
      
      if (measuringHeartRate) {
        addLog('Tự động bắt đầu lại đo nhịp tim sau khi kết nối lại');
        setTimeout(() => {
          startHeartRateMeasurementLocal();
        }, 1500);
      }
    } catch (error) {
      addLog(`Lỗi khi thiết lập lại các đặc tính: ${error}`);
      setIsDiscoverService(false);
    }
  };

  // Setup permissions
  useEffect(() => {
    const setupBluetooth = async () => {
      try {
        // Xin quyền truy cập vị trí (cần thiết cho BLE trên Android)
        const permissionGranted = await requestLocationPermission();
        if (!permissionGranted) {
          addLog("❌ Quyền truy cập vị trí bị từ chối!");
          return;
        }

        // Kiểm tra trạng thái Bluetooth
        const btState = await manager.state();

        if (btState !== 'PoweredOn') {
          addLog("⚠️ Bluetooth chưa được bật. Vui lòng bật Bluetooth và thử lại.");
          Alert.alert(
            "Bluetooth tắt",
            "Vui lòng bật Bluetooth và thử lại.",
            [{ text: "OK" }]
          );
        } else {
          addLog("✅ Bluetooth đã sẵn sàng!");
          setBluetoothReady(true);
          
          // Thiết lập callback log cho BackgroundService
          backgroundService.setLogCallback(addLog);
          
          // Thiết lập callback khi thiết bị được kết nối lại
          backgroundService.setReconnectionCallback(handleDeviceReconnected);
          
          // Khi khởi động app, tự động tìm và kết nối lại thiết bị cũ
          const lastDevice = getLastConnectedDevice();
          if (lastDevice) {
            addLog(`Tìm thấy thiết bị đã kết nối trước đó: ${lastDevice.name}. Đang thử kết nối lại...`);
            scanAndConnect();
          }
        }
      } catch (error) {
        addLog(`❌ Lỗi khởi tạo Bluetooth: ${error}`);
      }
    };

    setupBluetooth();
    
    // Theo dõi trạng thái Bluetooth
    const bluetoothStateSubscription = manager.onStateChange((state) => {
      addLog(`Trạng thái Bluetooth thay đổi: ${state}`);
      
      if (state === 'PoweredOn') {
        // Bluetooth vừa được bật
        addLog('Bluetooth vừa được bật. Đang thử kết nối lại thiết bị cũ...');
        setBluetoothReady(true);
        
        // Tự động tìm và kết nối lại thiết bị cũ
        const lastDevice = getLastConnectedDevice();
        if (lastDevice) {
          addLog(`Tìm thấy thiết bị đã kết nối trước đó: ${lastDevice.name}. Đang thử kết nối lại...`);
          scanAndConnect();
        }
      } else if (state === 'PoweredOff') {
        // Bluetooth vừa bị tắt
        addLog('Bluetooth vừa bị tắt. Các kết nối sẽ bị mất.');
        setBluetoothReady(false);
        
        // Reset trạng thái UI
        if (device) {
          addLog('Đặt lại trạng thái UI do Bluetooth bị tắt');
          setDevice(null);
          setWriteCharacteristic(null);
          setNotifyCharacteristic(null);
          setIsDiscoverService(false);
          setMeasuring(false);
          setMeasuringHeartRate(false);
        }
      }
    }, true);
    
    // Thiết lập kiểm tra kết nối định kỳ
    const connectionCheckInterval = setInterval(() => {
      if (device) {
        checkDeviceConnection();
      }
    }, 30000); // Kiểm tra mỗi 30 giây

    // Cleanup khi component unmount
    return () => {
      if (device) {
        disconnectDeviceLocal();
      }
      // Hủy BackgroundService khi component unmount
      backgroundService.destroy();
      // Xóa interval kiểm tra kết nối
      clearInterval(connectionCheckInterval);
      // Xóa subscription theo dõi trạng thái Bluetooth
      bluetoothStateSubscription.remove();
    };
  }, [device]);

  // Hàm ngắt kết nối cục bộ
  const disconnectDeviceLocal = async () => {
    try {
      if (device) {
        // Thông báo cho BackgroundService trước khi ngắt kết nối
        // Đặt trước để đảm bảo background service không cố gắng duy trì kết nối
        backgroundService.setCurrentDevice(null);
        
        // Dừng đo lường nếu đang đo
        if (measuring) {
          try {
            await stopMeasurementLocal();
          } catch (e) {
            addLog(`Lỗi khi dừng đo: ${e}`);
          }
        }
        
        // Hủy đăng ký các subscription
        if (notificationSubscription) {
          try {
            notificationSubscription.remove();
          } catch (e) {
            addLog(`Lỗi khi hủy thông báo: ${e}`);
          }
          setNotificationSubscription(null);
        }
        
        // Hủy các subscription bổ sung
        for (const sub of additionalSubscriptions) {
          try {
            sub.remove();
          } catch (e) {
            addLog(`Lỗi khi hủy subscription: ${e}`);
          }
        }
        setAdditionalSubscriptions([]);
        
        // Dừng polling nếu đang chạy
        if (pollingIntervalId) {
          clearInterval(pollingIntervalId);
          setPollingIntervalId(null);
        }

        addLog(`Đang ngắt kết nối từ thiết bị ${device.name || 'Không tên'} (${device.id})...`);
        try {
          await disconnectDevice(device, addLog);
          addLog('Đã ngắt kết nối thành công');
        } catch (disconnectError) {
          addLog(`Lỗi khi ngắt kết nối thiết bị: ${disconnectError}`);
          // Tiếp tục để reset state ngay cả khi ngắt kết nối thất bại
        }
        
        // Reset state
        setDevice(null);
        setWriteCharacteristic(null);
        setNotifyCharacteristic(null);
        setIsDiscoverService(false);
        setSpo2Value(null);
        setPrValue(null);
        setHrValue(null);
        setMeasuring(false);
        setMeasuringHeartRate(false);
      }
    } catch (error) {
      addLog(`Lỗi khi ngắt kết nối: ${error}`);
      
      // Reset state ngay cả khi có lỗi
      setDevice(null);
      setWriteCharacteristic(null);
      setNotifyCharacteristic(null);
      setIsDiscoverService(false);
      setSpo2Value(null);
      setPrValue(null);
      setHrValue(null);
      setMeasuring(false);
      setMeasuringHeartRate(false);
      
      // Đảm bảo BackgroundService cũng được reset
      backgroundService.setCurrentDevice(null);
    }
  };

  // Quét tìm thiết bị
  const scanDevices = async () => {
    try {
      if (!bluetoothReady) {
        addLog("❌ Bluetooth chưa sẵn sàng!");
        return;
      }
      
      setScanning(true);
      setDevices([]);
      addLog("Đang quét tìm thiết bị...");

      // Dừng quét cũ nếu có
      manager.stopDeviceScan();

      // Bắt đầu quét mới
      manager.startDeviceScan(null, { allowDuplicates: false }, (error, device) => {
        if (error) {
          addLog(`❌ Lỗi khi quét: ${error}`);
          setScanning(false);
          return;
        }

        if (device && device.name && device.name.includes("R12M")) {
          // Thêm thiết bị vào danh sách nếu chưa có
          setDevices(prevDevices => {
            if (!prevDevices.some(d => d.id === device.id)) {
              addLog(`Tìm thấy thiết bị: ${device.name} (${device.id})`);
              return [...prevDevices, device];
            }
            return prevDevices;
          });
        }
      });

      // Tự động dừng quét sau 10 giây
      setTimeout(() => {
        manager.stopDeviceScan();
        setScanning(false);
        addLog("Đã dừng quét thiết bị.");
      }, 10000);
    } catch (error) {
      addLog(`❌ Lỗi khi quét thiết bị: ${error}`);
      setScanning(false);
    }
  };
  
  // Scan và kết nối tự động với thiết bị đã kết nối trước đó
  const scanAndConnect = async () => {
    if (!bluetoothReady) {
      addLog("⚠️ Bluetooth chưa sẵn sàng!");
      return;
    }
    
    if (scanning) {
      addLog("⚠️ Đang quét. Vui lòng đợi...");
      return;
    }
    
    const lastDevice = getLastConnectedDevice();
    if (!lastDevice) {
      addLog("Không có thông tin thiết bị đã kết nối trước đó");
      return;
    }
    
    setScanning(true);
    addLog(`Đang quét tìm thiết bị đã kết nối trước đó: ${lastDevice.name} (${lastDevice.id})...`);
    
    try {
      // Dừng bất kỳ quá trình quét nào đang diễn ra
      manager.stopDeviceScan();
      
      // Bắt đầu quét
      manager.startDeviceScan(null, { allowDuplicates: false }, async (error, device) => {
        if (error) {
          addLog(`❌ Lỗi khi quét thiết bị: ${error.message}`);
          setScanning(false);
          return;
        }
        
        // Kiểm tra xem có phải thiết bị cần tìm không
        if (device && (device.id === lastDevice.id || (device.name && device.name.includes("R12M")))) {
          addLog(`Tìm thấy thiết bị đã kết nối trước đó: ${device.name} (${device.id})`);
          
          // Dừng quét
          manager.stopDeviceScan();
          setScanning(false);
          
          // Kết nối với thiết bị
          try {
            addLog(`Đang kết nối với thiết bị ${device.name || 'Không tên'} (${device.id})...`);
            const connectedDevice = await connectToDevice(device, addLog);
            
            if (connectedDevice) {
              addLog(`✅ Đã kết nối với thiết bị ${connectedDevice.name || 'Không tên'} (${connectedDevice.id})`);
              setDevice(connectedDevice);
              
              // Thông báo cho BackgroundService về thiết bị đã kết nối
              backgroundService.setCurrentDevice(connectedDevice);
              
              // Thiết lập các đặc tính (characteristics) cần thiết
              const { writeCharacteristic, notifyCharacteristic } = await setupCharacteristics(connectedDevice, addLog);
              
              setWriteCharacteristic(writeCharacteristic);
              setNotifyCharacteristic(notifyCharacteristic);
            }
          } catch (error) {
            addLog(`❌ Lỗi khi kết nối với thiết bị: ${error}`);
          }
        }
      });
      
      // Dừng quét sau 10 giây
      setTimeout(() => {
        if (scanning) {
          manager.stopDeviceScan();
          setScanning(false);
          addLog("Kết thúc quét tìm thiết bị đã kết nối trước đó");
        }
      }, 10000);
    } catch (error) {
      addLog(`❌ Lỗi khi quét tìm thiết bị đã kết nối trước đó: ${error}`);
      setScanning(false);
    }
  };

  // Thiết lập kiểm tra kết nối định kỳ
  useEffect(() => {
    // Kiểm tra kết nối mỗi 15 giây
    const checkConnectionInterval = setInterval(() => {
      if (device) {
        checkDeviceConnection();
      }
    }, 15000);
    
    // Kiểm tra ngay lập tức khi component mount hoặc device thay đổi
    if (device) {
      checkDeviceConnection();
    }
    
    return () => clearInterval(checkConnectionInterval);
  }, [device]);

  // Thiết lập các đặc tính (characteristics) cần thiết
  const setupCharacteristics = async (device: Device, addLog: (message: string) => void) => {
    try {
      addLog("Đang thiết lập các đặc tính...");

      // Tìm kiếm các đặc tính cần thiết
      const services = await device.services();
      let foundService = false;
      let writeChar: Characteristic | null = null;
      let notifyChar: Characteristic | null = null;

      for (const service of services) {
        if (service.uuid === SERVICE_UUID) {
          foundService = true;
          addLog(`Tìm thấy service: ${service.uuid}`);

          const characteristics = await device.characteristicsForService(service.uuid);
          addLog(`Tìm thấy ${characteristics.length} đặc tính trong service`);

          for (const characteristic of characteristics) {
            addLog(`Đặc tính: ${characteristic.uuid}`);

            if (characteristic.uuid === WRITE_UUID) {
              addLog(`✅ Đã tìm thấy đặc tính ghi: ${characteristic.uuid}`);
              writeChar = characteristic;
            }

            if (characteristic.uuid === NOTIFY_UUID) {
              addLog(`✅ Đã tìm thấy đặc tính thông báo: ${characteristic.uuid}`);
              notifyChar = characteristic;
            }
          }
        }
      }

      if (!foundService) {
        addLog("❌ Không tìm thấy service cần thiết!");
        return { writeCharacteristic: null, notifyCharacteristic: null };
      }

      addLog("✅ Đã thiết lập các đặc tính thành công!");
      setIsDiscoverService(true);
      return { writeCharacteristic: writeChar, notifyCharacteristic: notifyChar };
    } catch (error) {
      addLog(`❌ Lỗi khi thiết lập đặc tính: ${error}`);
      return { writeCharacteristic: null, notifyCharacteristic: null };
    }
  };

  // Bắt đầu đo SpO2
  const startMeasurementLocal = async () => {
    if (!device) {
      addLog("❌ Chưa kết nối với thiết bị!");
      return;
    }

    // Kiểm tra xem thiết bị có thực sự được kết nối không
    let isConnected = false;
    try {
      isConnected = await device.isConnected();
    } catch (error) {
      addLog(`❌ Thiết bị đã mất kết nối: ${error}`);
      // Đặt lại trạng thái thiết bị
      setDevice(null);
      setWriteCharacteristic(null);
      setNotifyCharacteristic(null);
      setIsDiscoverService(false);
      Alert.alert(
        "Mất kết nối",
        "Thiết bị đã mất kết nối. Vui lòng quét và kết nối lại.",
        [{ text: "OK" }]
      );
      return;
    }

    if (!isConnected) {
      addLog("❌ Thiết bị không còn kết nối. Đang thử kết nối lại...");
      try {
        // Thử kết nối lại với thiết bị
        await device.connect();
        addLog("✅ Đã kết nối lại với thiết bị");

        // Khám phá lại dịch vụ
        await device.discoverAllServicesAndCharacteristics();
        addLog("✅ Đã khám phá lại dịch vụ và đặc tính");

        // Thiết lập lại các đặc tính
        const { writeCharacteristic: wChar, notifyCharacteristic: nChar } = await setupCharacteristics(device, addLog);
        if (wChar) setWriteCharacteristic(wChar);
        if (nChar) setNotifyCharacteristic(nChar);
      } catch (reconnectError) {
        addLog(`❌ Không thể kết nối lại với thiết bị: ${reconnectError}`);
        setDevice(null);
        setWriteCharacteristic(null);
        setNotifyCharacteristic(null);
        setIsDiscoverService(false);
        Alert.alert(
          "Lỗi kết nối",
          "Không thể kết nối lại với thiết bị. Vui lòng quét và kết nối lại.",
          [{ text: "OK" }]
        );
        return;
      }
    }

    try {
      // Reset các giá trị trước khi bắt đầu đo mới
      setSpo2Value(null);
      setPrValue(null);
      setDataBuffer([]);

      // Hủy bỏ các subscription cũ nếu có
      if (additionalSubscriptions.length > 0) {
        additionalSubscriptions.forEach(sub => {
          if (sub && sub.remove) sub.remove();
        });
        setAdditionalSubscriptions([]);
      }

      // Hủy bỏ polling interval cũ nếu có
      if (pollingIntervalId) {
        clearInterval(pollingIntervalId);
        setPollingIntervalId(null);
      }

      // Sử dụng hàm từ SpO2ServiceRefactored
      addLog("🔄 Đang bắt đầu đo SpO2...");
      const success = await startSpO2Measurement(
        device,
        notificationSubscription,
        setNotificationSubscription,
        setMeasuring,
        setSpo2Value,
        setPrValue,
        setDataBuffer,
        dataBuffer,
        addLog,
        setPollingIntervalId
      );

      if (!success) {
        addLog("❌ Không thể bắt đầu đo SpO2");
        setMeasuring(false);
        return;
      }

      // Thiết lập thêm callback để nhận dữ liệu SpO2 trực tiếp
      const newSubscriptions = await setupRealDataCallback(
        device,
        (data: number[], setMeasuringCallback?: (measuring: boolean) => void) => handleData(
          data,
          setSpo2Value,
          setPrValue,
          setDataBuffer,
          dataBuffer,
          addLog,
          setMeasuringCallback || setMeasuring
        ),
        addLog,
        setMeasuring
      );

      // Lưu các subscription mới
      setAdditionalSubscriptions(prev => [...prev, ...newSubscriptions]);

    } catch (error) {
      addLog(`❌ Lỗi khi bắt đầu đo SpO2: ${error}`);
      setMeasuring(false);
    }
  };

  // Dừng việc đo SpO2
  const stopMeasurementLocal = async () => {
    if (!device) {
      setMeasuring(false);
      return;
    }

    // Kiểm tra xem thiết bị có thực sự được kết nối không
    let isConnected = false;
    try {
      isConnected = await device.isConnected();
    } catch (error) {
      addLog(`❌ Thiết bị đã mất kết nối khi cố gắng dừng đo: ${error}`);
      // Đặt lại trạng thái
      setMeasuring(false);
      setDevice(null);
      setWriteCharacteristic(null);
      setNotifyCharacteristic(null);
      setIsDiscoverService(false);
      return;
    }

    if (!isConnected) {
      addLog("❌ Thiết bị không còn kết nối");
      setMeasuring(false);
      return;
    }

    try {
      // Sử dụng hàm từ SpO2ServiceRefactored
      addLog(" 🔴 Đang dừng đo SpO2...");
      await stopSpO2Measurement(
        device,
        measuring,
        notificationSubscription,
        setNotificationSubscription,
        pollingIntervalId,
        setPollingIntervalId,
        setMeasuring,
        spo2Value,
        addLog
      );

      // Hủy bỏ các subscription bổ sung
      additionalSubscriptions.forEach(subscription => {
        if (subscription && subscription.remove) {
          subscription.remove();
        }
      });
      setAdditionalSubscriptions([]);

    } catch (error) {
      addLog(`❌ Lỗi khi dừng đo SpO2: ${error}`);
      // Đảm bảo trạng thái đo được đặt lại ngay cả khi có lỗi
      setMeasuring(false);
    }
  };

  // Bắt đầu đo nhịp tim
  const startHeartRateMeasurementLocal = async () => {
    if (!device) {
      addLog("❌ Chưa kết nối với thiết bị!");
      return;
    }

    // Kiểm tra xem thiết bị có thực sự được kết nối không
    let isConnected = false;
    try {
      isConnected = await device.isConnected();
    } catch (error) {
      addLog(`❌ Thiết bị đã mất kết nối: ${error}`);
      // Đặt lại trạng thái thiết bị
      setDevice(null);
      setWriteCharacteristic(null);
      setNotifyCharacteristic(null);
      setIsDiscoverService(false);
      Alert.alert(
        "Mất kết nối",
        "Thiết bị đã mất kết nối. Vui lòng quét và kết nối lại.",
        [{ text: "OK" }]
      );
      return;
    }

    if (!isConnected) {
      addLog("❌ Thiết bị không còn kết nối. Đang thử kết nối lại...");
      try {
        // Thử kết nối lại với thiết bị
        await device.connect();
        addLog("✅ Đã kết nối lại với thiết bị");

        // Khám phá lại dịch vụ
        await device.discoverAllServicesAndCharacteristics();
        addLog("✅ Đã khám phá lại dịch vụ và đặc tính");

        // Thiết lập lại các đặc tính
        const { writeCharacteristic: wChar, notifyCharacteristic: nChar } = await setupCharacteristics(device, addLog);
        if (wChar) setWriteCharacteristic(wChar);
        if (nChar) setNotifyCharacteristic(nChar);
      } catch (reconnectError) {
        addLog(`❌ Không thể kết nối lại với thiết bị: ${reconnectError}`);
        setDevice(null);
        setWriteCharacteristic(null);
        setNotifyCharacteristic(null);
        setIsDiscoverService(false);
        Alert.alert(
          "Lỗi kết nối",
          "Không thể kết nối lại với thiết bị. Vui lòng quét và kết nối lại.",
          [{ text: "OK" }]
        );
        return;
      }
    }

    try {
      // Reset các giá trị trước khi bắt đầu đo mới
      setHrValue(null);
      setHrDataBuffer([]);

      // Sử dụng hàm startHeartRateMeasurement từ service mới
      addLog("🔄 Đang bắt đầu đo nhịp tim...");
      const success = await startHeartRateMeasurement(
        device,
        hrNotificationSubscription,
        setHrNotificationSubscription,
        setMeasuringHeartRate,
        setHrValue,
        setHrDataBuffer,
        hrDataBuffer,
        addLog
      );

      if (!success) {
        addLog("❌ Không thể bắt đầu đo nhịp tim");
        setMeasuringHeartRate(false);
      }

    } catch (error) {
      addLog(`❌ Lỗi khi bắt đầu đo nhịp tim: ${error}`);
      setMeasuringHeartRate(false);
    }
  };

  // Dừng việc đo nhịp tim
  const stopHeartRateMeasurementLocal = async () => {
    if (!device) {
      setMeasuringHeartRate(false);
      return;
    }

    // Kiểm tra xem thiết bị có thực sự được kết nối không
    let isConnected = false;
    try {
      isConnected = await device.isConnected();
    } catch (error) {
      addLog(`❌ Thiết bị đã mất kết nối khi cố gắng dừng đo nhịp tim: ${error}`);
      // Đặt lại trạng thái
      setMeasuringHeartRate(false);
      return;
    }

    if (!isConnected) {
      addLog("❌ Thiết bị không còn kết nối");
      setMeasuringHeartRate(false);
      return;
    }

    try {
      // Sử dụng hàm từ HeartRateServiceRefactored
      addLog(" 🔴 Đang dừng đo nhịp tim...");
      await stopHeartRateMeasurement(
        device,
        hrNotificationSubscription,
        setHrNotificationSubscription,
        setMeasuringHeartRate,
        hrValue,
        addLog
      );

    } catch (error) {
      addLog(`❌ Lỗi khi dừng đo nhịp tim: ${error}`);
      // Đảm bảo trạng thái đo được đặt lại ngay cả khi có lỗi
      setMeasuringHeartRate(false);
    }
  };

  // Cleanup khi component unmount
  useEffect(() => {
    return () => {
      if (pollingIntervalId) {
        clearInterval(pollingIntervalId);
      }
      if (notificationSubscription) {
        notificationSubscription.remove();
      }
      additionalSubscriptions.forEach(subscription => subscription.remove());
    };
  }, [pollingIntervalId, notificationSubscription, additionalSubscriptions]);

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Ứng dụng Đo SpO2 qua Nhẫn Thông Minh</Text>
      <TouchableOpacity
        style={styles.button}
        onPress={scanDevices}
        disabled={scanning || device !== null}
      >
        <Text style={styles.buttonText}>
          {scanning ? 'Đang quét...' : device ? 'Đã kết nối' : 'Quét thiết bị'}
        </Text>
      </TouchableOpacity>

      {devices.length > 0 && (
        <View style={styles.deviceList}>
          <Text style={styles.sectionTitle}>Thiết bị đã tìm thấy:</Text>
          {devices.map(device => (
            <TouchableOpacity
              key={device.id}
              style={styles.deviceItem}
              onPress={() => connectToDevice(device, addLog).then((connectedDevice) => {
                if (connectedDevice) {
                  setDevice(connectedDevice);
                  addLog('Đã kết nối thành công!');
                  
                  // Cập nhật thiết bị hiện tại cho BackgroundService
                  backgroundService.setCurrentDevice(connectedDevice);

                  // Thiết lập các đặc tính
                  setupCharacteristics(connectedDevice, addLog)
                    .then(({ writeCharacteristic: wChar, notifyCharacteristic: nChar }) => {
                      if (wChar) setWriteCharacteristic(wChar);
                      if (nChar) setNotifyCharacteristic(nChar);
                      setBluetoothReady(true);
                      setIsDiscoverService(true); // Cập nhật trạng thái đã phát hiện service
                    });
                }
              })}
              disabled={device === null}
            >
              <Text style={styles.deviceName}>
                {device.name || 'Không có tên'}
                <Text style={styles.deviceId}> ({device.id})</Text>
              </Text>
            </TouchableOpacity>
          ))}
        </View>
      )}

      {device && (
        <View style={styles.measurementContainer}>
          <Text style={styles.deviceName}>
            Thiết bị: {device.name || 'Không tên'} ({device.id})
          </Text>

          <View style={styles.resultContainer}>
            <Text style={styles.resultLabel}>SpO2:</Text>
            <Text style={styles.resultValue}>
              {spo2Value !== null ? `${spo2Value}%` : '--'}
            </Text>
          </View>

          <View style={styles.resultContainer}>
            <Text style={styles.resultLabel}>Nhịp tim:</Text>
            <Text style={styles.resultValue}>
              {prValue !== null ? `${prValue} BPM` : '--'}
            </Text>
          </View>

          <TouchableOpacity
            style={[styles.buttonAction, measuring ? styles.buttonMeasuring : null]}
            onPress={measuring ? stopMeasurementLocal : startMeasurementLocal}
            disabled={!isDiscoverService}
          >
            <Text style={styles.buttonText}>
              {measuring ? 'Dừng đo' : 'Bắt đầu đo'}
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.buttonAction, measuringHeartRate ? styles.buttonMeasuring : null]}
            onPress={measuringHeartRate ? stopHeartRateMeasurementLocal : startHeartRateMeasurementLocal}
            disabled={!isDiscoverService}
          >
            <Text style={styles.buttonText}>
              {measuringHeartRate ? 'Dừng đo nhịp tim' : 'Bắt đầu đo nhịp tim'}
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.buttonDisconnect]}
            onPress={disconnectDeviceLocal}
          >
            <Text style={styles.buttonText}>Ngắt kết nối</Text>
          </TouchableOpacity>
        </View>
      )}

      <ScrollView style={styles.logContainer}>
        {logs.map((log, index) => (
          <Text key={index} style={styles.logText}>{log}</Text>
        ))}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    backgroundColor: '#f5f5f5',
  },
  title: {
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 20,
    textAlign: 'center',
  },
  button: {
    backgroundColor: '#2196F3',
    padding: 15,
    borderRadius: 5,
    alignItems: 'center',
    marginBottom: 10,
  },
  buttonText: {
    color: 'white',
    fontWeight: 'bold',
  },
  buttonAction: {
    backgroundColor: '#4CAF50',
    padding: 15,
    borderRadius: 5,
    alignItems: 'center',
    marginVertical: 5,
  },
  buttonMeasuring: {
    backgroundColor: '#f44336',
  },
  buttonDisconnect: {
    backgroundColor: '#607D8B',
    padding: 15,
    borderRadius: 5,
    alignItems: 'center',
    marginVertical: 5,
  },
  measurementContainer: {
    marginVertical: 10,
    padding: 10,
    backgroundColor: 'white',
    borderRadius: 5,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.2,
    shadowRadius: 1,
    elevation: 2,
  },
  deviceName: {
    fontSize: 16,
    marginBottom: 10,
  },
  resultContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginVertical: 5,
    padding: 10,
    backgroundColor: '#f9f9f9',
    borderRadius: 5,
  },
  resultLabel: {
    fontSize: 16,
    fontWeight: 'bold',
  },
  resultValue: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#2196F3',
  },
  logContainer: {
    flex: 1,
    marginTop: 20,
    padding: 10,
    backgroundColor: '#e0e0e0',
    borderRadius: 5,
  },
  logText: {
    fontSize: 12,
    marginBottom: 2,
  },
  deviceList: {
    marginVertical: 10,
    padding: 10,
    backgroundColor: 'white',
    borderRadius: 5,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.2,
    shadowRadius: 1,
    elevation: 2,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    marginBottom: 10,
  },
  deviceItem: {
    padding: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#ccc',
  },
  deviceId: {
    fontSize: 14,
    color: '#666',
    fontWeight: 'normal',
  },
});
