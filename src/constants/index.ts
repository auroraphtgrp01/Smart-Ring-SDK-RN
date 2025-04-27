import { BleManager } from 'react-native-ble-plx';

export const SERVICE_UUID = "be940000-7333-be46-b7ae-689e71722bd5";
export const WRITE_UUID = "be940001-7333-be46-b7ae-689e71722bd5";
export const NOTIFY_UUID = "be940001-7333-be46-b7ae-689e71722bd5"; // Sử dụng cùng characteristic cho cả ghi và thông báo
export const HEART_RATE_NOTIFY_UUID = "be940003-7333-be46-b7ae-689e71722bd5"; // UUID đặc biệt cho dữ liệu nhịp tim

// Constants theo mã Java và debug mới
export const CMD_APP_START_MEASUREMENT = 815; // 0x32F
export const CMD_APP_PREPARE_SPO2 = 777;      // 0x309 - Mã chuẩn bị đo SpO2

// Constants for measurements
export const BLOOD_OXYGEN_MEASURE_TYPE = 2; // SpO2
export const HEART_RATE_MEASURE_TYPE = 1;   // Heart Rate
export const BLOOD_OXYGEN_VISIBLE_MIN = 70;
export const BLOOD_OXYGEN_VISIBLE_MAX = 100;
export const HEART_RATE_VISIBLE_MIN = 40;   // Nhịp tim hợp lệ tối thiểu
export const HEART_RATE_VISIBLE_MAX = 200;  // Nhịp tim hợp lệ tối đa

// Data package structure constants
export const PKG_HEADER = 3;                // Giá trị byte đầu tiên là 3
export const PKG_TYPE_MEASUREMENT = 47;     // Type byte cho gói đo lường (0x2F)
export const PKG_TYPE_MEASUREMENT_DATA = 62; // Type byte cho gói dữ liệu đo lường (0x3E)
export const PKG_TYPE_ACK = 5;              // Type byte cho gói ACK (0x05)
export const PKG_TYPE_QUERY_RESPONSE = 17;  // Type byte cho gói phản hồi truy vấn (0x11) - tương ứng với CMD.RealBloodOxygen

// Tên thiết bị cần tìm
export const DEVICE_NAME = "R12M";

// Các lệnh SpO2 dưới dạng mảng byte
export const SPO2_PREPARE_COMMAND = [3, 9, 9, 0, 0, 0, 2, 144, 233];
export const SPO2_START_COMMAND = [3, 47, 8, 0, 1, 2, 13, 59];
export const SPO2_STOP_COMMAND = [3, 47, 8, 0, 0, 2, 13, 58];

// Các lệnh Heart Rate dưới dạng mảng byte (dựa trên FRIDA debug logs)
// Sequence nhận được từ debug: 03 09 09 00 00 00 02 90 e9, sau đó là 03 09 07 00 00 39 89
export const HEART_RATE_PREPARE_COMMAND = [3, 9, 9, 0, 0, 0, 2, 0x90, 0xe9]; // Lệnh chuẩn bị từ debug
export const HEART_RATE_PREPARE_ACK = [3, 9, 7, 0, 0, 0x39, 0x89];           // ACK sau lệnh chuẩn bị

// Lệnh START thực tế từ debug: 03 2f 08 00 01 00 4f 1b
export const HEART_RATE_START_COMMAND = [3, 0x2f, 8, 0, 1, 0, 0x4f, 0x1b];  // Lệnh bắt đầu chính xác từ debug

// Lệnh STOP tương ứng: 03 2f 07 00 00 ee 99
export const HEART_RATE_STOP_COMMAND = [3, 0x2f, 7, 0, 0, 0xee, 0x99];        // Lệnh dừng từ debug

export const RESET_COMMAND_HR = [3, 9, 9, 0, 1, 0, 2, 0xa0, 0xde]

// Các hằng số liên quan đến giấc ngủ
export const SLEEP_DATATYPE = {
  HISTORY_SLEEP: 1284,      // Health_HistorySleep
  DELETE_SLEEP: 1348,       // Health_DeleteSleep
  SLEEP_HISTORY_TIMESTAMPS: 0x15,  // Các mốc thời gian ngủ (05 15)
  SLEEP_HISTORY_HEARTRATES: 0x17,  // Nhịp tim khi ngủ (05 17)
  SLEEP_HISTORY_DETAILS: 0x18,     // Chi tiết các giai đoạn giấc ngủ (05 18)
  SLEEP_REALTIME_DATA: 0x00       // Dữ liệu giấc ngủ thời gian thực (06 00)
};

export const SLEEP_TYPE = {
  DEEP_SLEEP: 241,          // Giấc ngủ sâu
  LIGHT_SLEEP: 242,         // Giấc ngủ nhẹ
  REM: 243,                 // Giai đoạn REM
  AWAKE: 244,               // Tỉnh táo
  NAPS: 245                 // Ngủ trưa
};

// Các lệnh giấc ngủ dựa trên log Frida
export const SLEEP_COMMANDS = {
  // Lệnh lấy dữ liệu giấc ngủ - dựa trên log Frida
  GET_SLEEP_DATA_COMMAND: [5, 4, 6, 0, 0xe3, 0x4e], // 05 04 06 00 e3 4e - Lệnh lấy dữ liệu cơ bản
  GET_SLEEP_DATA_ACK: [5, 4, 8, 0, 0, 0, 0xd4, 0x41], // 05 04 08 00 00 00 d4 41
  
  // Lệnh lấy thống kê giấc ngủ
  GET_SLEEP_STATS_COMMAND: [5, 6, 6, 0, 0x83, 0x20], // 05 06 06 00 83 20
  GET_SLEEP_STATS_ACK: [5, 6, 8, 0, 0, 0, 0x57, 0x05], // 05 06 08 00 00 00 57 05
  
  // Lệnh lấy chi tiết giai đoạn giấc ngủ
  GET_SLEEP_STAGES_COMMAND: [5, 8, 6, 0, 0x82, 0x3b], // 05 08 06 00 82 3b
  GET_SLEEP_STAGES_ACK: [5, 8, 8, 0, 0, 0, 0xff, 0xca], // 05 08 08 00 00 00 ff ca
  
  // Lệnh lấy thông tin chi tiết giấc ngủ
  GET_SLEEP_DETAILS_COMMAND: [5, 9, 6, 0, 0xb2, 0x0c], // 05 09 06 00 b2 0c
  GET_SLEEP_DETAILS_ACK: [5, 9, 8, 0, 0, 0, 0xae, 0x60], // 05 09 08 00 00 00 ae 60
  
  // QUAN TRỌNG: Xác định đúng lệnh bật/tắt theo dõi giấc ngủ theo log Frida
  ENABLE_SLEEP_TRACKING_COMMAND: [3, 9, 9, 0, 1, 0, 2, 0xa0, 0xde], // 03 09 09 00 01 00 02 a0 de
  ENABLE_SLEEP_TRACKING_ACK: [3, 9, 7, 0, 0, 0x39, 0x89], // 03 09 07 00 00 39 89
  
  DISABLE_SLEEP_TRACKING_COMMAND: [3, 9, 9, 0, 0, 0, 2, 0x90, 0xe9], // 03 09 09 00 00 00 02 90 e9
  DISABLE_SLEEP_TRACKING_ACK: [3, 9, 7, 0, 0, 0x39, 0x89], // 03 09 07 00 00 39 89

  // Xóa dữ liệu giấc ngủ
  DELETE_SLEEP_DATA_COMMAND: [5, 80, 7, 0, 0, 0xf3, 0x6a] // 05 80 07 00 00 f3 6a
};

export const FUNCTION_CONSTANT = {
  ISHASSLEEP: 'isHasSleep'  // Hằng số kiểm tra hỗ trợ tính năng giấc ngủ
};

// Chuyển đổi dataType sang byte thứ hai của gói (byte cuối của giá trị hex)
export const convertDataTypeToCommandType = (dataType: number): number => {
  // Theo debug mới, dataType 815 (0x32F) có byte thứ hai là 47 (0x2F)
  const hexString = dataType.toString(16).padStart(4, '0');
  const secondByte = parseInt(hexString.slice(2, 4), 16);
  return secondByte;
};

// Tạo BleManager singleton
export const manager = new BleManager();
