import React, { useState, useEffect } from 'react';
import { StyleSheet, Text, View, TouchableOpacity, ScrollView, Alert, Platform } from 'react-native';
import { Device, Characteristic } from 'react-native-ble-plx';
import {
  manager,
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

  // Scan for devices
  const startScan = async () => {
    if (!scanning) {
      setScanning(true);
      addLog('Bắt đầu quét thiết bị...');

      try {
        // Sử dụng scanForDevices từ BluetoothService
        scanForDevices(
          // Callback khi tìm thấy thiết bị
          (scannedDevice: Device) => {
            addLog(`Tìm thấy thiết bị: ${scannedDevice.name} (${scannedDevice.id})`);

            // Auto-connect to the device - sử dụng hàm từ BluetoothService
            connectToDevice(scannedDevice, addLog).then((connectedDevice) => {
              if (connectedDevice) {
                setDevice(connectedDevice);
                addLog('Đã kết nối thành công!');

                // Thiết lập các characteristics
                setupCharacteristics(connectedDevice, addLog)
                  .then(({ writeCharacteristic: wChar, notifyCharacteristic: nChar }) => {
                    if (wChar) setWriteCharacteristic(wChar);
                    if (nChar) setNotifyCharacteristic(nChar);
                    setBluetoothReady(true);
                    setIsDiscoverService(true); // Cập nhật trạng thái đã phát hiện service
                  });
              }
            });
          },
          // Callback log
          addLog
        );
      } catch (error) {
        addLog(`Lỗi quét: ${error instanceof Error ? error.message : String(error)}`);
        setScanning(false);
      }

      // Đặt timeout để dừng quét sau 10 giây
      setTimeout(() => {
        setScanning(false);
      }, 10000);
    } else {
      // Dừng quét nếu đang quét
      manager.stopDeviceScan();
      setScanning(false);
      addLog('Dừng quét thiết bị');
    }
  };

  // Bắt đầu đo SpO2
  const startMeasurementLocal = async () => {
    if (!device) {
      addLog("❌ Chưa kết nối với thiết bị!");
      return;
    }

    try {
      // Sử dụng hàm từ SpO2Service
      await startSpO2Measurement(
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

      // Thiết lập callback để nhận dữ liệu SpO2 trực tiếp
      const newSubscriptions = await setupRealDataCallback(
        device,
        (data: number[]) => handleData(
          data,
          setSpo2Value,
          setPrValue,
          setDataBuffer,
          dataBuffer,
          addLog
        ),
        addLog
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
        addLog
      );
      setPollingIntervalId(pollInterval);

    } catch (error) {
      addLog(`❌ Lỗi khi bắt đầu đo SpO2: ${error}`);
    }
  };

  // Dừng việc đo SpO2
  const stopMeasurementLocal = async () => {
    if (!device || !measuring) {
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
        onPress={startScan}
        disabled={scanning || device !== null}
      >
        <Text style={styles.buttonText}>
          {scanning ? 'Đang quét...' : device ? 'Đã kết nối' : 'Quét thiết bị'}
        </Text>
      </TouchableOpacity>

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
});
