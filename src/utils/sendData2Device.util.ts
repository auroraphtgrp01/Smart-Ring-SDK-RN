import { Characteristic, Device } from 'react-native-ble-plx';
import * as base64 from 'base64-js';
import { prepareDataPacket } from './prepareDataPacket.util';

/**
 * Các mã lệnh đặc biệt
 */
export const CommandCodes = {
  COMMAND_OTAMODE: 2561, // 0x0A01
  COMMAND_FACTORYMODE: 2305, // 0x0901
  COMMAND_SPECIAL: 32258, // 0x7E02 - Sử dụng trong trường hợp đặc biệt dựa vào SPUtil.getChipScheme()
};

/**
 * Tính toán giá trị CRC16 cho một mảng byte
 * @param data Mảng dữ liệu cần tính CRC16
 * @param length Số byte cần tính (thường là toàn bộ mảng trừ 2 byte cuối dùng để lưu CRC)
 * @returns Giá trị CRC16
 */


/**
 * Chuẩn bị gói dữ liệu để gửi đến thiết bị, bao gồm mã lệnh, độ dài và CRC16
 * @param commandCode Mã lệnh (2 byte)
 * @param data Dữ liệu cần gửi
 * @returns Mảng byte đã được đóng gói
 */


/**
 * Kiểm tra xem một chip scheme có được sử dụng hay không (tương tự SPUtil.getChipScheme())
 * @returns Giá trị chip scheme
 */
export function getChipScheme(): number {
  // Giá trị mặc định là 0, có thể thay đổi dựa trên cấu hình thực tế của thiết bị
  // Trong ứng dụng thực tế, bạn cần lưu trữ và lấy giá trị này từ bộ nhớ thiết bị
  return 0;
}

/**
 * Gửi dữ liệu đến thiết bị thông qua giao thức BLE, tương tự phương thức sendData2Device trong Java
 * @param commandCode Mã lệnh (2 byte)
 * @param data Dữ liệu cần gửi
 * @param writeCharacteristic Đặc tính ghi BLE
 * @param logCallback Callback để ghi log
 * @returns Promise<boolean> Kết quả gửi dữ liệu (true nếu thành công)
 */
export async function sendData2Device(
  commandCode: number,
  data: Uint8Array,
  writeCharacteristic: Characteristic,
  logCallback: (message: string) => void
): Promise<boolean> {
  try {
    // Chuẩn bị gói dữ liệu
    const packet = prepareDataPacket(commandCode, data);
    
    // Chuyển đổi mảng byte thành chuỗi base64 để gửi qua BLE
    const base64Data = base64.fromByteArray(packet);

    logCallback(`Gửi lệnh ${commandCode.toString(16).padStart(4, '0').toUpperCase()} với ${data.length} byte dữ liệu`);
    
    // Gửi dữ liệu dựa trên mã lệnh (tương tự logic trong Java)
    if (commandCode === CommandCodes.COMMAND_OTAMODE) {
      // Mã lệnh OTAMODE (0x0A01)
      await writeCharacteristic.writeWithResponse(base64Data);
    } else {
      // Chờ 30ms trước khi gửi, tương tự Java
      await new Promise(resolve => setTimeout(resolve, 30));
      
      // Kiểm tra các điều kiện đặc biệt
      if (commandCode === CommandCodes.COMMAND_FACTORYMODE ||
          (getChipScheme() !== 0 && commandCode === CommandCodes.COMMAND_SPECIAL)) {
        // Sử dụng gatt2WriteData
        await writeCharacteristic.writeWithResponse(base64Data);
      } else {
        // Sử dụng gattWriteData
        await writeCharacteristic.writeWithResponse(base64Data);
      }
    }
    
    logCallback('Gửi dữ liệu thành công');
    return true;
  } catch (error) {
    logCallback(`Lỗi khi gửi dữ liệu: ${error}`);
    return false;
  }
}

/**
 * Gửi lệnh đơn giản đến thiết bị với mã lệnh và không có dữ liệu
 * @param commandCode Mã lệnh (2 byte)
 * @param device Thiết bị BLE
 * @param writeCharacteristic Đặc tính ghi BLE
 * @param logCallback Callback để ghi log
 * @returns Promise<boolean> Kết quả gửi lệnh
 */
export async function sendCommand(
  commandCode: number,
  device: Device,
  writeCharacteristic: Characteristic,
  logCallback: (message: string) => void
): Promise<boolean> {
  try {
    if (!device || !writeCharacteristic) {
      logCallback('Không có thiết bị hoặc đặc tính ghi để gửi lệnh');
      return false;
    }
    
    // Kiểm tra xem thiết bị có kết nối không
    const isConnected = await device.isConnected();
    if (!isConnected) {
      logCallback('Thiết bị không được kết nối, không thể gửi lệnh');
      return false;
    }
    
    // Gửi lệnh với mảng byte rỗng
    return await sendData2Device(commandCode, new Uint8Array(0), writeCharacteristic, logCallback);
  } catch (error) {
    logCallback(`Lỗi khi gửi lệnh: ${error}`);
    return false;
  }
}

/**
 * Chuyển đổi chuỗi hex thành mảng byte
 * @param hexString Chuỗi hex (ví dụ: "A1B2C3")
 * @returns Uint8Array chứa các giá trị byte
 */
export function hexStringToBytes(hexString: string): Uint8Array {
  const cleanString = hexString.replace(/\s/g, '');
  const bytes = new Uint8Array(cleanString.length / 2);
  
  for (let i = 0; i < cleanString.length; i += 2) {
    bytes[i / 2] = parseInt(cleanString.substr(i, 2), 16);
  }
  
  return bytes;
}

/**
 * Chuyển đổi mảng byte thành chuỗi hex để hiển thị
 * @param bytes Mảng byte
 * @param pretty Nếu true, thêm khoảng cách giữa các byte
 * @returns Chuỗi hex
 */
export function bytesToHexString(bytes: Uint8Array | number[], pretty: boolean = false): string {
  const hexChars = Array.from(bytes).map(b => 
    (b & 0xFF).toString(16).padStart(2, '0')
  );
  
  return pretty 
    ? hexChars.join(' ') 
    : hexChars.join('');
}

/**
 * Ghi log dữ liệu dưới dạng hex để debug
 * @param prefix Tiền tố cho log
 * @param data Dữ liệu cần log
 */
export function logDataHex(prefix: string, data: Uint8Array | number[]): void {
  if (!data || data.length === 0) return;
  
  const hexString = bytesToHexString(data, true);
  console.log(`${prefix}: ${hexString} (${data.length} bytes)`);
}
