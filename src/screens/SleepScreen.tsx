import React, { useState, useEffect } from 'react';
import { StyleSheet, View, Text, TouchableOpacity, ScrollView, Alert } from 'react-native';
import { Device } from 'react-native-ble-plx';
import * as base64 from 'base64-js';
import { SERVICE_UUID, WRITE_UUID, NOTIFY_UUID } from '../constants';
import {
  calculateCRC16,
  createSleepDataRequest,
  bytesToHexString,
  parseSleepData,
  SleepDataRecord,
  createHealthDataConfirmation,
  createDateTimePacket,
  createGFPacket,
  create021bPacket,
  createGCPacket,
  createCFPacket
} from '../utils/SleepDataUtils';

// Props cho SleepScreen
interface SleepScreenProps {
  device: Device | null;
  onClose: () => void;
}

const SleepScreen: React.FC<SleepScreenProps> = ({ device, onClose }) => {
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [sleepData, setSleepData] = useState<SleepDataRecord[]>([]);
  const [logMessages, setLogMessages] = useState<string[]>([]);

  // Thêm log message
  const addLog = (message: string) => {
    console.log(`[SLEEP_LOG] ${message}`); // Log ra console
    setLogMessages(prev => [...prev, message]);
  };

  // Xử lý dữ liệu khi nhận được từ nhẫn
  const handleSleepDataResponse = (data: Uint8Array) => {
    const hexData = bytesToHexString(data);
    addLog(`Nhận dữ liệu: ${hexData}`);

    // Log chi tiết từng byte
    console.log('[SLEEP_DATA_RECEIVED] Dữ liệu nhận từ nhẫn:');
    console.log(`- Độ dài: ${data.length} bytes`);
    console.log(`- Dữ liệu HEX: ${hexData}`);

    // Log từng byte với index
    console.log('- Chi tiết từng byte:');
    data.forEach((byte, index) => {
      console.log(`  Byte ${index}: ${byte.toString(16).padStart(2, '0')} (${byte})`);
    });

    // Phân tích dữ liệu
    const parsedData = parseSleepData(data);
    console.log('[SLEEP_DATA_PARSED] Dữ liệu đã phân tích:', parsedData);

    // Lưu dữ liệu nhận được
    const timestamp = new Date().toISOString();
    const sleepRecord: SleepDataRecord = {
      timestamp,
      rawData: hexData,
      parsedData: parsedData,
      error: parsedData.error
    };

    console.log('[SLEEP_RECORD] Bản ghi giấc ngủ mới:', JSON.stringify(sleepRecord, null, 2));
    setSleepData(prev => [...prev, sleepRecord]);

    // Kiểm tra nếu nhận được phản hồi đặc biệt như "không có dữ liệu"
    if (parsedData.statusCode === 0xFF && parsedData.message) {
      addLog(parsedData.message);
      if (parsedData.detail) {
        addLog(parsedData.detail);
      }
      Alert.alert('Thông báo từ nhẫn', parsedData.message);
    }

    // Dừng trạng thái loading
    setIsLoading(false);
  };

  // Lấy thông tin giấc ngủ từ nhẫn
  // Lấy thông tin giấc ngủ từ nhẫn
  const createGPPacket = (): Uint8Array => {
    // GP = 47 50 trong ASCII
    const headerData = [0x02, 0x03, 0x08, 0x00]; // Header 0x0203, length 8
    const cmdData = [0x47, 0x50]; // "GP" trong ASCII
    const packetData = [...headerData, ...cmdData];

    // Tính CRC
    const crc = calculateCRC16(packetData);
    const crcLow = crc & 0xFF;
    const crcHigh = (crc >> 8) & 0xFF;

    return new Uint8Array([...packetData, crcLow, crcHigh]);
  };
  const getSleepData = async () => {
    if (!device) {
      console.error('[SLEEP_ERROR] Không có thiết bị được kết nối');
      Alert.alert('Lỗi', 'Không có thiết bị được kết nối');
      return;
    }

    try {
      console.log('\n======================================');
      console.log('[SLEEP_REQUEST] Bắt đầu gửi yêu cầu lấy dữ liệu giấc ngủ');
      console.log(`[SLEEP_DEVICE] Thông tin thiết bị: ID=${device.id}, Name=${device.name}`);

      setIsLoading(true);
      addLog('Bắt đầu lấy dữ liệu giấc ngủ...');

      // Thiết lập lắng nghe thông báo từ nhẫn trước khi gửi dữ liệu
      console.log('[SLEEP_MONITOR] Thiết lập lắng nghe thông báo từ nhẫn');
      console.log(`- Service UUID: ${SERVICE_UUID}`);
      console.log(`- Notify UUID: ${NOTIFY_UUID}`);

      const subscription = device.monitorCharacteristicForService(
        SERVICE_UUID,
        NOTIFY_UUID,
        (error, characteristic) => {
          if (error) {
            console.error('[SLEEP_ERROR] Lỗi khi nhận dữ liệu:', error);
            addLog(`Lỗi khi nhận dữ liệu: ${error.message}`);
            setIsLoading(false);
            subscription.remove();
            return;
          }

          if (characteristic?.value) {
            console.log('[SLEEP_NOTIFY] Nhận được thông báo từ nhẫn');
            console.log(`- Characteristic UUID: ${characteristic.uuid}`);
            console.log(`- Characteristic value (base64): ${characteristic.value}`);

            const data = base64.toByteArray(characteristic.value);
            console.log(`- Đã chuyển đổi từ base64 sang array (${data.length} bytes)`);

            // Log từng byte để debug chi tiết
            console.log('- Chi tiết từng byte:');
            data.forEach((byte, index) => {
              console.log(`  Byte ${index}: ${byte.toString(16).padStart(2, '0')} (${byte})`);
            });

            handleSleepDataResponse(data);
          }
        }
      );

      // Hàm gửi gói dữ liệu với log
      const sendPacketWithLog = async (payload: Uint8Array, name: string) => {
        const hexPayload = bytesToHexString(payload);

        console.log(`[PACKET_${name}] Gửi gói dữ liệu ${name}:`);
        console.log(`- Độ dài: ${payload.length} bytes`);
        console.log(`- Dữ liệu HEX: ${hexPayload}`);

        addLog(`Gửi gói dữ liệu ${name}: ${hexPayload}`);

        await device.writeCharacteristicWithResponseForService(
          SERVICE_UUID,
          WRITE_UUID,
          base64.fromByteArray(payload)
        );

        console.log(`[PACKET_${name}] Đã gửi gói dữ liệu thành công`);

        // Thêm độ trễ giữa các gói dữ liệu
        await new Promise(resolve => setTimeout(resolve, 200));
      };

      // 0. Gửi gói GP (0x0203) - nếu có
      const gpPayload = new Uint8Array([0x47, 0x50]); // "GP" - Từ log
      await sendPacketWithLog(gpPayload, 'GP');

      // 1. Gửi gói DateTime (0x0100)
      const dateTimePayload = createDateTimePacket();
      await sendPacketWithLog(dateTimePayload, 'DATE_TIME');

      // 2. Gửi gói GF (0x0201)
      const gfPayload = createGFPacket();
      await sendPacketWithLog(gfPayload, 'GF');

      // 3. Gửi gói 0x021b
      const packet021b = create021bPacket();
      await sendPacketWithLog(packet021b, '021B');

      // 4. Gửi gói GC (0x0200) - lặp lại 3 lần theo log
      const gcPayload = createGCPacket();
      for (let i = 0; i < 3; i++) {
        await sendPacketWithLog(gcPayload, `GC_${i + 1}`);
      }

      // 5. Gửi gói CF (0x0207)
      const cfPayload = createCFPacket();
      await sendPacketWithLog(cfPayload, 'CF');

      // 6. Gửi gói yêu cầu lấy dữ liệu giấc ngủ (0x0502)
      const sleepRequestPayload = createSleepDataRequest();
      await sendPacketWithLog(sleepRequestPayload, 'SLEEP_REQUEST');

      // 7. Gửi gói xác nhận (0x0580)
      const confirmationPayload = createHealthDataConfirmation();
      await sendPacketWithLog(confirmationPayload, 'CONFIRMATION');

      // Đặt thời gian chờ tối đa để nhận phản hồi
      console.log('[SLEEP_TIMEOUT] Thiết lập timeout 15 giây');
      setTimeout(() => {
        if (isLoading) {
          console.log('[SLEEP_TIMEOUT] Hết thời gian chờ phản hồi từ nhẫn');
          setIsLoading(false);
          addLog('Hết thời gian chờ phản hồi từ nhẫn');
          subscription.remove();
        }
      }, 15000); // Tăng thời gian chờ lên 15 giây để đủ thời gian nhận phản hồi

    } catch (error: any) {
      console.error('[SLEEP_ERROR] Lỗi khi gửi yêu cầu:', error);
      console.error(`- Message: ${error?.message || 'Không xác định'}`);
      console.error(`- Stack: ${error?.stack || 'Không có thông tin stack'}`);

      setIsLoading(false);
      addLog(`Lỗi: ${error?.message || 'Không xác định'}`);
      Alert.alert('Lỗi', `Không thể lấy dữ liệu giấc ngủ: ${error?.message || 'Không xác định'}`);
    }
  };

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>Quản Lý Giấc Ngủ</Text>
        <TouchableOpacity style={styles.closeButton} onPress={onClose}>
          <Text style={styles.closeButtonText}>Đóng</Text>
        </TouchableOpacity>
      </View>

      <View style={styles.trackingContainer}>
        <Text style={styles.sectionTitle}>Đồng Bộ Dữ Liệu Giấc Ngủ</Text>
        <TouchableOpacity
          style={[styles.trackingButton, isLoading ? styles.stopButton : styles.startButton]}
          onPress={getSleepData}
          disabled={isLoading}
        >
          <Text style={styles.buttonText}>
            {isLoading ? 'Đang lấy dữ liệu...' : 'Lấy thông tin giấc ngủ'}
          </Text>
        </TouchableOpacity>
        <Text style={styles.trackingInfo}>
          {isLoading
            ? 'Đang lấy dữ liệu giấc ngủ từ nhẫn, vui lòng đợi...'
            : 'Nhấn nút để lấy dữ liệu giấc ngủ từ nhẫn'}
        </Text>
      </View>

      {sleepData.length > 0 && (
        <View style={styles.historyContainer}>
          <Text style={styles.sectionTitle}>Dữ liệu đã nhận</Text>
          <ScrollView style={styles.historyList}>
            {sleepData.map((item, index) => (
              <View key={index} style={styles.historyItem}>
                <View style={styles.historyHeader}>
                  <Text style={styles.historyDate}>{new Date(item.timestamp).toLocaleString()}</Text>
                </View>
                <View style={styles.historyDetails}>
                  <View style={styles.detailItem}>
                    <Text style={styles.detailLabel}>Dữ liệu (HEX):</Text>
                  </View>
                  <View style={styles.detailItem}>
                    <Text style={styles.detailValue}>{item.rawData}</Text>
                  </View>
                  {item.error ? (
                    <View style={styles.detailItem}>
                      <Text style={styles.errorText}>{item.error}</Text>
                    </View>
                  ) : item.parsedData && (
                    <>
                      <View style={styles.detailItem}>
                        <Text style={styles.detailLabel}>DataType:</Text>
                        <Text style={styles.detailValue}>{item.parsedData.dataType}</Text>
                      </View>
                      {/* Hiển thị các thông tin khác về giấc ngủ khi đã phân tích được dữ liệu */}
                    </>
                  )}
                </View>
              </View>
            ))}
          </ScrollView>
        </View>
      )}

      <View style={styles.logContainer}>
        <Text style={styles.sectionTitle}>Nhật ký</Text>
        <ScrollView style={styles.logList}>
          {logMessages.map((log, index) => (
            <Text key={index} style={styles.logText}>- {log}</Text>
          ))}
        </ScrollView>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 15,
    backgroundColor: '#2196F3',
  },
  title: {
    fontSize: 20,
    fontWeight: 'bold',
    color: 'white',
  },
  closeButton: {
    padding: 8,
    backgroundColor: 'rgba(255,255,255,0.3)',
    borderRadius: 5,
  },
  closeButtonText: {
    color: 'white',
    fontWeight: 'bold',
  },
  trackingContainer: {
    margin: 15,
    padding: 15,
    backgroundColor: 'white',
    borderRadius: 10,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 3,
    elevation: 3,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 15,
    color: '#333',
  },
  trackingButton: {
    padding: 15,
    borderRadius: 8,
    alignItems: 'center',
  },
  startButton: {
    backgroundColor: '#4CAF50',
  },
  stopButton: {
    backgroundColor: '#F44336',
  },
  buttonText: {
    color: 'white',
    fontWeight: 'bold',
    fontSize: 16,
  },
  trackingInfo: {
    marginTop: 10,
    fontSize: 14,
    color: '#666',
    textAlign: 'center',
  },
  historyContainer: {
    margin: 15,
    padding: 15,
    backgroundColor: 'white',
    borderRadius: 10,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 3,
    elevation: 3,
    maxHeight: 280,
  },
  historyList: {
    flex: 1,
  },
  historyItem: {
    marginBottom: 15,
    padding: 12,
    backgroundColor: '#f9f9f9',
    borderRadius: 8,
    borderLeftWidth: 4,
    borderLeftColor: '#2196F3',
  },
  historyHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  historyDate: {
    fontSize: 15,
    fontWeight: 'bold',
    color: '#444',
  },
  qualityBadge: {
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 12,
  },
  qualityText: {
    color: 'white',
    fontWeight: 'bold',
    fontSize: 12,
  },
  historyDetails: {
    marginTop: 5,
  },
  detailItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 4,
  },
  detailLabel: {
    fontSize: 14,
    color: '#666',
  },
  detailValue: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#333',
  },
  errorText: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#F44336',
  },
  logContainer: {
    margin: 15,
    padding: 15,
    backgroundColor: 'white',
    borderRadius: 10,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 3,
    elevation: 3,
    flex: 1,
  },
  logList: {
    flex: 1,
  },
  logText: {
    fontSize: 12,
    color: '#333',
    marginBottom: 4,
  },
});

export default SleepScreen;