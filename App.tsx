import React, { useState, useEffect } from 'react';
import { StyleSheet, Text, View, TouchableOpacity, ScrollView, Alert, Platform } from 'react-native';
import { Device, Characteristic } from 'react-native-ble-plx';
import {
  manager,
  SERVICE_UUID,
  WRITE_UUID,
  NOTIFY_UUID
} from './constants';

import {
  // Functions
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
  setupAlternativeNotificationMethod,
  startSpO2Measurement,
  setupRealDataCallback
} from './SpO2Service';

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

  // Logging function
  const addLog = (message: string) => {
    console.log(message);
    setLogs(prev => [...prev, `${new Date().toLocaleTimeString()}: ${message}`]);
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
        }
      } catch (error) {
        addLog(`❌ Lỗi khởi tạo Bluetooth: ${error}`);
      }
    };

    setupBluetooth();

    // Cleanup khi component unmount
    return () => {
      if (device) {
        disconnectDeviceLocal();
      }
    };
  }, [device]);

  // Hàm ngắt kết nối cục bộ
  const disconnectDeviceLocal = async () => {
    try {
      if (device) {
        // Dừng đo lường nếu đang đo
        if (measuring) {
          await stopMeasurementLocal();
        }

        addLog(`Đang ngắt kết nối từ thiết bị ${device.name || 'Không tên'} (${device.id})...`);
        await disconnectDevice(device, addLog);
        addLog('Đã ngắt kết nối thành công');

        // Reset state
        setDevice(null);
        setWriteCharacteristic(null);
        setNotifyCharacteristic(null);
        setIsDiscoverService(false);
        setSpo2Value(null);
        setPrValue(null);
      }
    } catch (error) {
      addLog(`Lỗi khi ngắt kết nối: ${error}`);
    }
  };

  // Quét tìm thiết bị
  const scanDevices = async () => {
    try {
      setScanning(true);
      setDevices([]);
      addLog("Đang quét tìm thiết bị...");

      // Dừng quét cũ nếu có
      manager.stopDeviceScan();

      // Bắt đầu quét mới
      manager.startDeviceScan(null, null, (error, device) => {
        if (error) {
          addLog(`❌ Lỗi khi quét: ${error}`);
          setScanning(false);
          return;
        }

        if (device && device.name && device.name.startsWith("R12M")) {
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

      // Sử dụng hàm từ SpO2Service
      const success = await startSpO2Measurement(
        device,
        notificationSubscription,
        setNotificationSubscription,
        setMeasuring,
        setSpo2Value,
        setPrValue,
        setDataBuffer,
        dataBuffer,
        addLog
      );

      if (!success) {
        addLog("❌ Không thể bắt đầu đo SpO2");
        return;
      }

      // Thiết lập callback để nhận dữ liệu SpO2 trực tiếp
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

      // Thiết lập cơ chế polling dự phòng
      const pollInterval = setupPollingMechanism(
        device,
        notifyCharacteristic,
        measuring,
        setSpo2Value,
        setPrValue,
        setDataBuffer,
        dataBuffer,
        addLog,
        setMeasuring
      );
      setPollingIntervalId(pollInterval);

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
      // Sử dụng hàm từ SpO2Service
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
