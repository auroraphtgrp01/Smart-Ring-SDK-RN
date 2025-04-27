/**
 * Công cụ xử lý dữ liệu giấc ngủ từ nhẫn thông minh
 */

/**
 * Tính CRC16-MODBUS
 * Sử dụng để tính checksum cho gói dữ liệu gửi đến nhẫn
 * @param data Mảng byte dữ liệu cần tính CRC
 * @returns Giá trị CRC16
 */
export const calculateCRC16 = (data: number[]): number => {
  let crc = 0xFFFF;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];
    for (let j = 0; j < 8; j++) {
      if ((crc & 0x0001) !== 0) {
        crc >>= 1;
        crc ^= 0xA001;
      } else {
        crc >>= 1;
      }
    }
  }
  return crc;
};

/**
 * Tạo gói dữ liệu đặc biệt 0x0580 (theo sau các gói dữ liệu dữ liệu sức khỏe)
 * Dựa trên log từ file document/27.4.txt, sau mỗi yêu cầu dữ liệu sức khỏe luôn có gói 0x0580
 * @returns Uint8Array chứa gói dữ liệu hoàn chỉnh
 */
export const createHealthDataConfirmation = (): Uint8Array => {
  // Dựa trên log từ file document/27.4.txt:
  // - Header: 05 80 (dataType = 1408 = 0x0580)
  // - Length: 07 00 (độ dài gói = 7 bytes, bao gồm header và CRC)
  // - Data: 00 (1 byte dữ liệu = 0)
  // - CRC16: 2 byte cuối để kiểm tra tính toàn vẹn
  
  const headerData = [0x05, 0x80, 0x07, 0x00, 0x00];
  const crc = calculateCRC16(headerData);
  const crcLow = crc & 0xFF;
  const crcHigh = (crc >> 8) & 0xFF;

  return new Uint8Array([...headerData, crcLow, crcHigh]);
};

/**
 * Tạo gói dữ liệu ngày giờ (0x0100)
 * @returns Uint8Array chứa gói dữ liệu hoàn chỉnh
 */
export const createDateTimePacket = (): Uint8Array => {
  // Dựa trên log từ file document/27.4.txt:
  // Gói dữ liệu có dạng: e9 07 04 1b 08 0f 22 06
  // - Header: 01 00 (dataType = 256 = 0x0100 - Cài đặt ngày giờ)
  // - Length: 0E 00 (độ dài gói = 14 bytes, bao gồm header, data và CRC)
  // - Data: e9 07 04 1b 08 0f 22 06 (dữ liệu ngày giờ hiện tại)
  // - CRC16: 2 byte cuối để kiểm tra tính toàn vẹn
  
  // Lấy ngày giờ hiện tại (theo múi giờ hệ thống)
  const now = new Date();
  const year = now.getFullYear() - 2000; // Chỉ lấy 2 chữ số cuối của năm
  const month = now.getMonth() + 1; // getMonth() trả về 0-11
  const day = now.getDate();
  const hour = now.getHours();
  const minute = now.getMinutes();
  const second = now.getSeconds();
  const dayOfWeek = now.getDay(); // 0 = Chủ nhật, 1-6 = Thứ 2 - Thứ 7
  
  // Xây dựng gói dữ liệu
  const headerData = [0x01, 0x00, 0x0E, 0x00];
  const dateTimeData = [year, month, day, hour, minute, second, dayOfWeek, 0x00];
  const packetData = [...headerData, ...dateTimeData];
  
  // Tính CRC
  const crc = calculateCRC16(packetData);
  const crcLow = crc & 0xFF;
  const crcHigh = (crc >> 8) & 0xFF;

  return new Uint8Array([...packetData, crcLow, crcHigh]);
};

/**
 * Tạo gói dữ liệu 0x0201 (GF)
 * @returns Uint8Array chứa gói dữ liệu hoàn chỉnh
 */
export const createGFPacket = (): Uint8Array => {
  // Dựa trên log từ file document/27.4.txt:
  // - Header: 02 01 (dataType = 513 = 0x0201)
  // - Length: 08 00 (độ dài gói = 8 bytes, bao gồm header, data và CRC)
  // - Data: 47 46 ("GF" trong ASCII)
  // - CRC16: 2 byte cuối để kiểm tra tính toàn vẹn
  
  const headerData = [0x02, 0x01, 0x08, 0x00];
  const cmdData = [0x47, 0x46]; // "GF" trong ASCII
  const packetData = [...headerData, ...cmdData];
  
  // Tính CRC
  const crc = calculateCRC16(packetData);
  const crcLow = crc & 0xFF;
  const crcHigh = (crc >> 8) & 0xFF;

  return new Uint8Array([...packetData, crcLow, crcHigh]);
};

/**
 * Tạo gói dữ liệu 0x021b (không có data)
 * @returns Uint8Array chứa gói dữ liệu hoàn chỉnh
 */
export const create021bPacket = (): Uint8Array => {
  // Dựa trên log từ file document/27.4.txt:
  // - Header: 02 1b (dataType = 539 = 0x021b)
  // - Length: 06 00 (độ dài gói = 6 bytes, bao gồm header và CRC)
  // - Không có data
  // - CRC16: 2 byte cuối để kiểm tra tính toàn vẹn
  
  const headerData = [0x02, 0x1b, 0x06, 0x00];
  
  // Tính CRC
  const crc = calculateCRC16(headerData);
  const crcLow = crc & 0xFF;
  const crcHigh = (crc >> 8) & 0xFF;

  return new Uint8Array([...headerData, crcLow, crcHigh]);
};

/**
 * Tạo gói dữ liệu 0x0200 (GC)
 * @returns Uint8Array chứa gói dữ liệu hoàn chỉnh
 */
export const createGCPacket = (): Uint8Array => {
  // Dựa trên log từ file document/27.4.txt:
  // - Header: 02 00 (dataType = 512 = 0x0200)
  // - Length: 08 00 (độ dài gói = 8 bytes, bao gồm header, data và CRC)
  // - Data: 47 43 ("GC" trong ASCII)
  // - CRC16: 2 byte cuối để kiểm tra tính toàn vẹn
  
  const headerData = [0x02, 0x00, 0x08, 0x00];
  const cmdData = [0x47, 0x43]; // "GC" trong ASCII
  const packetData = [...headerData, ...cmdData];
  
  // Tính CRC
  const crc = calculateCRC16(packetData);
  const crcLow = crc & 0xFF;
  const crcHigh = (crc >> 8) & 0xFF;

  return new Uint8Array([...packetData, crcLow, crcHigh]);
};

/**
 * Tạo gói dữ liệu 0x0207 (CF)
 * @returns Uint8Array chứa gói dữ liệu hoàn chỉnh
 */
export const createCFPacket = (): Uint8Array => {
  // Dựa trên log từ file document/27.4.txt:
  // - Header: 02 07 (dataType = 519 = 0x0207)
  // - Length: 08 00 (độ dài gói = 8 bytes, bao gồm header, data và CRC)
  // - Data: 43 46 ("CF" trong ASCII)
  // - CRC16: 2 byte cuối để kiểm tra tính toàn vẹn
  
  const headerData = [0x02, 0x07, 0x08, 0x00];
  const cmdData = [0x43, 0x46]; // "CF" trong ASCII
  const packetData = [...headerData, ...cmdData];
  
  // Tính CRC
  const crc = calculateCRC16(packetData);
  const crcLow = crc & 0xFF;
  const crcHigh = (crc >> 8) & 0xFF;

  return new Uint8Array([...packetData, crcLow, crcHigh]);
};

/**
 * Tạo gói dữ liệu yêu cầu dữ liệu giấc ngủ (0x0502)
 * @returns Uint8Array chứa gói dữ liệu hoàn chỉnh
 */
export const createSleepDataRequest = (): Uint8Array => {
  // Dựa trên log từ file document/27.4.txt:
  // - Header: 05 02 (dataType = 1282 = 0x0502)
  // - Length: 06 00 (độ dài gói = 6 bytes, bao gồm header và CRC)
  // - Không có data
  // - CRC16: 2 byte cuối để kiểm tra tính toàn vẹn
  
  const headerData = [0x05, 0x02, 0x06, 0x00];
  
  // Tính CRC
  const crc = calculateCRC16(headerData);
  const crcLow = crc & 0xFF;
  const crcHigh = (crc >> 8) & 0xFF;

  return new Uint8Array([...headerData, crcLow, crcHigh]);
};

/**
 * Chuyển đổi mảng byte thành chuỗi hex để hiển thị
 * @param data Mảng byte dữ liệu
 * @returns Chuỗi hex
 */
export const bytesToHexString = (data: Uint8Array | number[]): string => {
  return Array.from(data)
    .map(b => b.toString(16).padStart(2, '0'))
    .join(' ');
};

/**
 * Phân tích dữ liệu giấc ngủ từ mảng byte trả về từ nhẫn
 * @param data Mảng byte dữ liệu nhận được từ nhẫn
 * @returns Đối tượng chứa thông tin giấc ngủ đã được phân tích
 */
export const parseSleepData = (data: Uint8Array): any => {
  try {
    // Kiểm tra xem dữ liệu có đủ dài không
    if (data.length < 6) {
      return { 
        error: 'Dữ liệu không hợp lệ: quá ngắn',
        details: `Độ dài thực tế: ${data.length} bytes, yêu cầu tối thiểu: 6 bytes`,
        rawData: bytesToHexString(data)
      };
    }

    // Xử lý gói phản hồi theo nhiều định dạng khác nhau
    
    // 1. Xử lý gói phản hồi ACK với format 05 XX 07 00 FF YY ZZ
    // Đây là gói ACK tiêu chuẩn phản hồi sau mỗi lệnh gửi đi
    if (data.length === 7 && data[2] === 0x07 && data[3] === 0x00 && data[4] === 0xff) {
      const dataType = (data[0] << 8) | data[1];
      return {
        dataType,
        statusCode: 0xFF,
        isAck: true,
        message: `Phản hồi xác nhận cho gói 0x${dataType.toString(16).padStart(4, '0').toUpperCase()}`,
        rawData: bytesToHexString(data)
      };
    }

    // 2. Kiểm tra xem có phải định dạng dữ liệu giấc ngủ với header đặc biệt "af fa d4 00" không
    // (Dựa trên log DataUnpack.unpackHealthData)
    if (data.length > 20 && data[0] === 0xaf && data[1] === 0xfa && data[2] === 0xd4 || data[2] === 0x54) {
      return parseSleepDataWithAFHeader(data);
    }
    
    // 3. Kiểm tra header định dạng cũ (0x05 0x04)
    if (data[0] === 0x05 && data[1] === 0x04) {
      // Kiểm tra độ dài gói dữ liệu
      const declaredLength = data[2] | (data[3] << 8);
      
      // Kiểm tra và xử lý gói phản hồi 05 04 07 00 ff ca 63
      // Đây là gói đặc biệt với length = 7 và mã trạng thái FF
      if (data.length === 7 && declaredLength === 7 && data[4] === 0xff) {
        return {
          dataType: 0x0504,
          statusCode: 0xFF,
          message: 'Không có dữ liệu giấc ngủ khả dụng',
          detail: 'Thiết bị thông báo không có dữ liệu giấc ngủ. Hãy đảm bảo đeo nhẫn khi ngủ và thử lại sau.'
        };
      }
      
      // Nếu đây là gói ACK (phản hồi ban đầu), không có dữ liệu giấc ngủ thực tế
      if (data.length <= 8) {
        return {
          dataType: 0x0504,
          isAck: true,
          message: 'Gói ACK, chờ dữ liệu giấc ngủ thực tế'
        };
      }
      
      // Phân tích dữ liệu giấc ngủ thực tế
      const sleepData = data.slice(4, data.length - 2);
      return {
        dataType: 0x0504,
        sleepData: Array.from(sleepData),
        rawSleepData: bytesToHexString(sleepData)
      };
    }
    
    // 4. Trường hợp còn lại: định dạng không được nhận dạng
    return { 
      error: `Định dạng dữ liệu không nhận dạng: ${bytesToHexString(data.slice(0, 4))}`,
      dataType: (data[0] << 8) | data[1],
      rawData: bytesToHexString(data)
    };
  } catch (error) {
    return { 
      error: 'Lỗi khi phân tích dữ liệu: ' + (error as Error).message,
      rawData: bytesToHexString(data)
    };
  }
};

/**
 * Phân tích dữ liệu giấc ngủ với định dạng AF FA D4/54 header
 * Dựa trên cấu trúc từ log DataUnpack.unpackHealthData
 * @param data Mảng byte dữ liệu nhận được từ nhẫn
 * @returns Đối tượng chứa thông tin giấc ngủ đã được phân tích
 */
const parseSleepDataWithAFHeader = (data: Uint8Array): any => {
  try {
    // Lấy múi giờ hiện tại (ms)
    const timezoneOffset = new Date().getTimezoneOffset() * 60 * 1000;
    
    // Kiểm tra tiếp dữ liệu
    if (data.length < 20) {
      return {
        error: 'Dữ liệu giấc ngủ quá ngắn',
        rawData: bytesToHexString(data)
      };
    }
    
    // Bắt đầu phân tích dữ liệu giấc ngủ
    let offset = 4; // Bỏ qua 4 byte header af fa d4/54 00
    
    // Lấy thời gian bắt đầu giấc ngủ từ 4 byte tiếp theo
    const startTimestamp = readUint32(data, offset);
    offset += 4;
    
    // Lấy thời gian kết thúc giấc ngủ từ 4 byte tiếp theo
    const endTimestamp = readUint32(data, offset);
    offset += 4;
    
    // Hai byte tiếp theo là giá trị đặc biệt thường là FF FF (có thể là marker)
    offset += 2;
    
    // Các thông số giấc ngủ 
    // 2 byte deepSleepTotal, 2 byte lightSleepTotal, 2 byte rapidEyeMovementTotal, ...
    const deepSleepTotal = readUint16(data, offset);
    offset += 2;
    
    const lightSleepTotal = readUint16(data, offset);
    offset += 2;
    
    const rapidEyeMovementTotal = readUint16(data, offset);
    offset += 2;
    
    // Khởi tạo mảng chứa các giai đoạn giấc ngủ
    const sleepPhases: any[] = [];
    
    // Phân tích từng giai đoạn giấc ngủ (mỗi giai đoạn 8 byte)
    // Cấu trúc: 1 byte mã (241=deep, 242=light, 243=REM), 1 byte không sử dụng, 
    // 4 byte timestamp, 2 byte độ dài (phút)
    while (offset + 8 <= data.length) {
      const sleepType = data[offset];
      offset += 1;
      
      // Bỏ qua 1 byte không sử dụng
      offset += 1;
      
      // Timestamp bắt đầu giai đoạn (4 byte)
      const phaseStartTime = readUint32(data, offset);
      offset += 4;
      
      // Độ dài của giai đoạn (phút)
      const sleepLen = readUint16(data, offset);
      offset += 2;
      
      // Thêm thông tin giai đoạn vào mảng
      sleepPhases.push({
        sleepType,
        sleepStartTime: phaseStartTime * 1000, // Chuyển sang milliseconds
        sleepLen,
        sleepTypeName: getSleepTypeName(sleepType)
      });
    }
    
    // Kết quả phân tích
    return {
      dataType: 1284, // 0x0504 = Health_HistorySleep
      data: [{
        startTime: startTimestamp * 1000, // Chuyển sang milliseconds
        endTime: endTimestamp * 1000,
        deepSleepTotal,
        lightSleepTotal,
        rapidEyeMovementTotal,
        wakeCount: 0, // Giá trị mặc định
        deepSleepCount: 0xFFFF, // Giá trị đặc biệt từ log
        lightSleepCount: 0,
        wakeDuration: 0,
        sleepData: sleepPhases,
        sleepQuality: calculateSleepQuality(deepSleepTotal, lightSleepTotal, rapidEyeMovementTotal),
      }],
      rawData: bytesToHexString(data)
    };
  } catch (error) {
    return { 
      error: 'Lỗi khi phân tích dữ liệu định dạng AF: ' + (error as Error).message,
      rawData: bytesToHexString(data)
    };
  }
};

/**
 * Đọc số 32 bit không dấu từ mảng byte
 * @param data Mảng byte
 * @param offset Vị trí bắt đầu đọc
 * @returns Số 32 bit không dấu
 */
const readUint32 = (data: Uint8Array, offset: number): number => {
  return (data[offset] & 0xFF) | 
         ((data[offset + 1] & 0xFF) << 8) | 
         ((data[offset + 2] & 0xFF) << 16) | 
         ((data[offset + 3] & 0xFF) << 24);
};

/**
 * Đọc số 16 bit không dấu từ mảng byte
 * @param data Mảng byte
 * @param offset Vị trí bắt đầu đọc
 * @returns Số 16 bit không dấu
 */
const readUint16 = (data: Uint8Array, offset: number): number => {
  return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
};

/**
 * Lấy tên của loại giấc ngủ dựa trên mã
 * @param sleepType Mã loại giấc ngủ
 * @returns Tên loại giấc ngủ
 */
const getSleepTypeName = (sleepType: number): string => {
  switch (sleepType) {
    case 241: // 0xF1
      return 'Ngủ sâu';
    case 242: // 0xF2
      return 'Ngủ nhẹ';
    case 243: // 0xF3
      return 'REM';
    case 244: // 0xF4
      return 'Thức giấc';
    default:
      return `Không xác định (${sleepType})`;
  }
};

/**
 * Tính chất lượng giấc ngủ dựa trên thời gian các giai đoạn
 * @param deepSleep Thời gian ngủ sâu (phút)
 * @param lightSleep Thời gian ngủ nhẹ (phút)
 * @param remSleep Thời gian REM (phút)
 * @returns Chất lượng giấc ngủ (0-100)
 */
const calculateSleepQuality = (deepSleep: number, lightSleep: number, remSleep: number): number => {
  const totalSleep = deepSleep + lightSleep + remSleep;
  if (totalSleep === 0) return 0;
  
  // Công thức tính chất lượng giấc ngủ (tham khảo)
  // 60% từ ngủ sâu, 30% từ REM, 10% từ ngủ nhẹ
  const deepSleepScore = Math.min(100, (deepSleep / totalSleep) * 100 * 1.5);
  const remSleepScore = Math.min(50, (remSleep / totalSleep) * 100 * 0.8);
  const lightSleepScore = Math.min(20, (lightSleep / totalSleep) * 100 * 0.2);
  
  const quality = Math.round(deepSleepScore + remSleepScore + lightSleepScore);
  return Math.min(100, quality);
};

/**
 * Interface mô tả cấu trúc dữ liệu giấc ngủ đã được phân tích
 */
export interface SleepDataRecord {
  timestamp: string;  // Timestamp định dạng ISO
  rawData: string;    // Dữ liệu thô dạng hex
  parsedData?: {
    dataType?: number;  // Loại dữ liệu
    isAck?: boolean;    // Là gói ACK
    statusCode?: number; // Mã trạng thái nếu có
    message?: string;   // Thông báo
    detail?: string;    // Thông tin chi tiết thêm
    startTime?: number;
    endTime?: number;
    deepSleepTime?: number;
    lightSleepTime?: number;
    remSleepTime?: number;
    wakeTime?: number;
    sleepQuality?: number;
    // Thêm các trường khác nếu cần
    error?: string;     // Thông báo lỗi trong quá trình phân tích
  };
  error?: string;     // Thông báo lỗi nếu có
} 