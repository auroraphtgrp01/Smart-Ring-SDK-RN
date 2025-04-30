import { Characteristic, Device } from 'react-native-ble-plx';
import * as base64 from 'base64-js';
import { prepareDataPacket } from './prepareDataPacket.util';

/**
 * Interface đáp ứng dữ liệu BLE, tương tự BleDataResponse trong Java
 */
export interface BleDataResponse {
  onDataResponse: (status: number, data: any) => void;
}

/**
 * Class mô phỏng YCSendBean, lưu trữ thông tin về dữ liệu sẽ gửi
 */
export class YCSendBean {
  private static SENDSN: number = 1;
  private static readonly YCMAXLEN: number = 100000;
  
  // Các thuộc tính chính
  public collectDigits: number = 16;
  private currentSendPos: number = 0;
  public dataSendFinish: boolean = false;
  public dataType: number = 0;
  public groupSize: number = 0;
  public groupType: number = 0;
  public sendPriority: number = 0;
  private sendSN: number = 0;
  public willData: Uint8Array;
  public mDataResponse: BleDataResponse | null;

  /**
   * Khởi tạo đối tượng YCSendBean
   * @param data Dữ liệu cần gửi
   * @param priority Độ ưu tiên
   * @param dataResponse Callback phản hồi
   */
  constructor(data: Uint8Array, priority: number, dataResponse: BleDataResponse | null) {
    this.willData = data;
    this.sendPriority = priority;
    this.mDataResponse = dataResponse;
    this.sendSN = YCSendBean.SENDSN++;
    this.dataSendFinish = false;
    this.currentSendPos = 0;
  }

  /**
   * Đặt lại thông tin nhóm
   * @param dataType Loại dữ liệu
   * @param data Dữ liệu mới
   */
  public resetGroup(dataType: number, data: Uint8Array): void {
    this.dataType = dataType;
    this.willData = data;
    this.currentSendPos = 0;
  }

  /**
   * So sánh với đối tượng YCSendBean khác, dùng cho việc sắp xếp
   * @param other Đối tượng YCSendBean khác để so sánh
   * @returns Kết quả so sánh: -1, 0, hoặc 1
   */
  public compareTo(other: YCSendBean): number {
    if (this.sendPriority > other.sendPriority) {
      return -1;
    } else if (this.sendPriority < other.sendPriority) {
      return 1;
    } else {
      if (this.sendSN < other.sendSN) {
        return -1;
      } else if (this.sendSN > other.sendSN) {
        return 1;
      } else {
        return 0;
      }
    }
  }
}

// Hằng số mã lệnh đặc biệt
export const CommandCodes = {
  WATCH_DIAL: 2304,        // 0x0900
  SPECIAL_COMMAND: 32257,  // 0x7E01
};

/**
 * Quản lý hàng đợi gửi dữ liệu BLE
 */
export class BleQueueManager {
  private mSendQueue: YCSendBean[] = [];
  private isWatchDialPause: boolean = false;
  private sendingDataResponse: BleDataResponse | null = null;
  private isRecvRealEcging: boolean = false;
  private mQueueSendState: boolean = false;
  private logCallback: (message: string) => void;

  /**
   * Khởi tạo Quản lý hàng đợi BLE
   * @param logCallback Hàm callback để ghi log
   */
  constructor(logCallback: (message: string) => void) {
    this.logCallback = logCallback;
  }

  /**
   * Thêm đối tượng YCSendBean vào hàng đợi
   * @param sendBean Đối tượng YCSendBean để thêm vào hàng đợi
   */
  public pushQueue(sendBean: YCSendBean): void {
    this.logCallback(`pushQueue: dataType=${sendBean.dataType.toString(16)}, groupType=${sendBean.groupType}, queueSize=${this.mSendQueue.length}`);
    
    // Xử lý logic tương tự như trong Java
    if (sendBean.groupType === 11 && !this.isRecvRealEcging) {
      // Xóa các lệnh ECG từ hàng đợi
      const itemsToRemove = this.mSendQueue.filter(item => item.groupType === 10);
      for (const item of itemsToRemove) {
        const index = this.mSendQueue.indexOf(item);
        if (index !== -1) {
          this.mSendQueue.splice(index, 1);
          this.logCallback('Đã xóa lệnh ECG từ hàng đợi');
        }
      }
    }

    // Thêm vào hàng đợi
    this.mSendQueue.push(sendBean);
    this.logCallback(`Hàng đợi sau khi thêm: ${this.mSendQueue.length} mục`);

    // Xử lý ưu tiên nếu cần
    if (sendBean.groupType === 11) {
      this.logCallback('Nhận lệnh kết thúc ECG, sắp xếp lại hàng đợi');
      this.sortQueue();
      this.frontQueue();
      // Xử lý timeout nếu cần
    } else if (!this.mQueueSendState && !this.isRecvRealEcging) {
      this.frontQueue();
    }
  }

  /**
   * Gửi dữ liệu ở đầu hàng đợi
   */
  public frontQueue(): void {
    // Triển khai logic xử lý hàng đợi - phiên bản đơn giản
    this.logCallback('Xử lý mục trong hàng đợi');
    if (this.mSendQueue.length > 0 && !this.mQueueSendState) {
      this.mQueueSendState = true;
      // Ở đây sẽ gọi hàm xử lý gửi dữ liệu thực tế
      // Trong ứng dụng thực tế, bạn cần triển khai phần này để gửi dữ liệu qua BLE
      this.mQueueSendState = false;
    }
  }

  /**
   * Sắp xếp hàng đợi dựa trên độ ưu tiên
   */
  private sortQueue(): void {
    this.mSendQueue.sort((a, b) => a.compareTo(b));
  }

  /**
   * Gửi dữ liệu đơn lẻ đến thiết bị, tương tự sendSingleData2Device trong Java
   * @param dataType Loại dữ liệu (mã lệnh)
   * @param data Dữ liệu cần gửi
   * @param priority Độ ưu tiên
   * @param dataResponse Callback phản hồi
   */
  public sendSingleData2Device(
    dataType: number,
    data: Uint8Array,
    priority: number = 0,
    dataResponse: BleDataResponse | null = null
  ): void {
    // Tạo đối tượng YCSendBean mới
    const sendBean = new YCSendBean(data, priority, dataResponse);
    sendBean.dataType = dataType;
    sendBean.groupType = 1;

    this.logCallback(`Gửi lệnh đơn: ${dataType.toString(16)}, độ dài dữ liệu: ${data.length}`);

    // Xử lý các trường hợp đặc biệt - WATCH_DIAL (2304)
    if (dataType === CommandCodes.WATCH_DIAL && data.length > 0 && data[0] === 0) {
      // Xử lý trường hợp watchDial pause
      if (this.mSendQueue.length > 0 && this.mSendQueue[0].dataType === CommandCodes.WATCH_DIAL) {
        this.isWatchDialPause = true;
        this.logCallback('Tạm dừng watchDial - không thêm vào hàng đợi');
        return;
      }

      // Xóa tất cả các mục watchDial khỏi hàng đợi
      const itemsToRemove = this.mSendQueue.filter(item => item.dataType === CommandCodes.WATCH_DIAL);
      for (const item of itemsToRemove) {
        const index = this.mSendQueue.indexOf(item);
        if (index !== -1) {
          this.mSendQueue.splice(index, 1);
          this.logCallback('Đã xóa lệnh watchDial từ hàng đợi');
        }
      }
      return;
    }

    // Xử lý trường hợp đặc biệt - SPECIAL_COMMAND (32257)
    if (dataType === CommandCodes.SPECIAL_COMMAND) {
      // Kiểm tra xem đã có lệnh SPECIAL_COMMAND trong hàng đợi chưa
      const existingCommand = this.mSendQueue.find(item => item.dataType === CommandCodes.SPECIAL_COMMAND);
      if (existingCommand) {
        this.sendingDataResponse = dataResponse;
        this.logCallback('Đã có lệnh đặc biệt trong hàng đợi - chỉ cập nhật callback');
        return;
      }
    }

    // Thêm vào hàng đợi
    this.pushQueue(sendBean);
  }

  /**
   * Gửi dữ liệu thực tế qua BLE
   * @param device Thiết bị BLE
   * @param writeCharacteristic Đặc tính ghi
   * @param dataType Loại dữ liệu
   * @param data Dữ liệu cần gửi
   * @returns Promise trả về trạng thái thành công
   */
  public async sendDataToBleDevice(
    device: Device,
    writeCharacteristic: Characteristic,
    dataType: number,
    data: Uint8Array
  ): Promise<boolean> {
    try {
      // Tạo gói dữ liệu
      const packet = prepareDataPacket(dataType, data);
      const base64Data = base64.fromByteArray(packet);
      
      // Gửi dữ liệu
      this.logCallback(`Gửi dữ liệu: type=${dataType.toString(16)}, length=${data.length}`);
      await writeCharacteristic.writeWithResponse(base64Data);
      return true;
    } catch (error) {
      this.logCallback(`Lỗi khi gửi dữ liệu: ${error}`);
      return false;
    }
  }
}

/**
 * Tạo một instance của BleQueueManager để sử dụng trong ứng dụng
 * @param logCallback Hàm callback để ghi log
 * @returns Instance của BleQueueManager
 */
export function createBleQueueManager(logCallback: (message: string) => void = console.log): BleQueueManager {
  return new BleQueueManager(logCallback);
}

/**
 * Hàm tiện ích để gửi lệnh đơn giản đến thiết bị
 * @param queueManager Quản lý hàng đợi BLE
 * @param device Thiết bị BLE
 * @param writeCharacteristic Đặc tính ghi
 * @param dataType Loại dữ liệu (mã lệnh)
 * @param data Dữ liệu cần gửi
 * @param priority Độ ưu tiên
 * @param callback Callback phản hồi
 */
export async function sendSingleData2Device(
  queueManager: BleQueueManager,
  device: Device | null,
  writeCharacteristic: Characteristic | null,
  dataType: number,
  data: Uint8Array,
  priority: number = 0,
  callback?: (status: number, data: any) => void
): Promise<boolean> {
  if (!device || !writeCharacteristic) {
    console.log('Không có thiết bị hoặc đặc tính ghi để gửi dữ liệu');
    return false;
  }

  try {
    // Kiểm tra kết nối
    const isConnected = await device.isConnected();
    if (!isConnected) {
      console.log('Thiết bị không được kết nối, không thể gửi dữ liệu');
      return false;
    }

    // Tạo đối tượng phản hồi nếu có callback
    let dataResponse: BleDataResponse | null = null;
    if (callback) {
      dataResponse = {
        onDataResponse: callback
      };
    }

    // Thêm vào hàng đợi
    queueManager.sendSingleData2Device(dataType, data, priority, dataResponse);
    return true;
  } catch (error) {
    console.log(`Lỗi khi gửi dữ liệu đơn: ${error}`);
    return false;
  }
}
