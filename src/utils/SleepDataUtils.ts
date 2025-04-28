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
// Cải tiến hàm parseSleepData trong utils/SleepDataUtils.ts
export function parseSleepData(data: Uint8Array) {
  try {
    // Kiểm tra xem dữ liệu có hợp lệ không
    if (!data || data.length < 6) {
      return {
        error: 'Dữ liệu không hợp lệ hoặc không đủ độ dài',
        statusCode: 0xFF,
        message: 'Dữ liệu không hợp lệ',
        detail: `Độ dài dữ liệu: ${data ? data.length : 0} bytes`
      };
    }

    // Kiểm tra mã phản hồi
    const header = data[0] << 8 | data[1]; // 2 byte đầu là mã lệnh
    const statusCode = data[2];
    
    // Nếu là phản hồi cho lệnh 0x0502 (1282) - lệnh lấy dữ liệu giấc ngủ
    if (header === 0x0502) {
      if (statusCode === 0) {
        // Nếu có dữ liệu giấc ngủ
        // Phân tích chi tiết dữ liệu nhận được
        // ...
        const sleepRecords = parseSleepRecords(data.slice(3));
        
        return {
          dataType: header,
          statusCode: statusCode,
          message: 'Nhận dữ liệu giấc ngủ thành công',
          records: sleepRecords
        };
      } else if (statusCode === 0xFF) {
        // Không có dữ liệu giấc ngủ
        return {
          dataType: header,
          statusCode: statusCode,
          message: 'Không có dữ liệu giấc ngủ',
          detail: 'Nhẫn không ghi nhận dữ liệu giấc ngủ trong thời gian gần đây'
        };
      } else {
        // Các mã phản hồi khác
        return {
          dataType: header,
          statusCode: statusCode,
          message: `Mã phản hồi không xác định: ${statusCode}`,
          detail: `Dữ liệu đầy đủ: ${bytesToHexString(data)}`
        };
      }
    }
    
    // Xử lý các loại phản hồi khác
    return {
      dataType: header,
      statusCode: statusCode,
      message: `Phản hồi cho lệnh: 0x${header.toString(16).padStart(4, '0')}`,
      detail: `Dữ liệu đầy đủ: ${bytesToHexString(data)}`
    };
    
  } catch (error: any) {
    console.error('[PARSE_ERROR] Lỗi khi phân tích dữ liệu:', error);
    return {
      error: `Lỗi phân tích: ${error.message}`,
      statusCode: 0xFF,
      message: 'Lỗi khi phân tích dữ liệu',
      detail: error.stack
    };
  }
}

// Hàm phụ trợ để phân tích bản ghi giấc ngủ
// Cải tiến hàm parseSleepRecords trong SleepDataUtils.ts
function parseSleepRecords(data: Uint8Array) {
  const records = [];
  
  // Tìm tất cả các đoạn bắt đầu bằng AF FA 54
  let offset = 0;
  while (offset < data.length - 4) {
    // Tìm header AF FA 54
    if (data[offset] === 0xAF && data[offset+1] === 0xFA && data[offset+2] === 0x54) {
      const recordIndex = data[offset+3];
      // Tách dữ liệu sau header
      const recordData = parseSleepRecord(data, offset);
      if (recordData) {
        records.push({
          index: recordIndex,
          ...recordData
        });
      }
      // Nhảy sang vị trí tiếp theo - nhảy ít nhất 20 byte, hoặc tùy vào cấu trúc thực tế
      offset += 20;
    } else {
      offset++;
    }
  }
  
  return records;
}

// Hàm phụ trợ phân tích từng bản ghi giấc ngủ
function parseSleepRecord(data: Uint8Array, offset: number) {
  try {
    // Đảm bảo có đủ byte để phân tích
    if (offset + 16 > data.length) return null;
    
    // Format: af fa 54 00 7e f1 9e 2f c1 01 9f 2f ff ff 3e 01...
    // Byte 4-7: startTime (little endian)
    // Byte 8-11: endTime hoặc duration (little endian)
    // Byte 12-13: thường là FF FF (marker)
    // Byte 14-15: có thể là thông số giấc ngủ khác
    
    const startTime = (data[offset+7] << 24) | (data[offset+6] << 16) | (data[offset+5] << 8) | data[offset+4];
    const endTime = (data[offset+11] << 24) | (data[offset+10] << 16) | (data[offset+9] << 8) | data[offset+8];
    
    // Phân tích thêm các dữ liệu khác tùy thuộc vào cấu trúc thực tế
    // Từ byte 16 trở đi có thể là các phân đoạn giấc ngủ với format F1/F2/F3 + timestamp + duration
    
    // Phân tích các phân đoạn chi tiết từ byte 16 trở đi
    const sleepSegments = [];
    let segmentOffset = offset + 16;
    while (segmentOffset < data.length - 8) {
      const sleepType = data[segmentOffset];
      
      // Format: F1/F2/F3 + byte không dùng + 4 byte timestamp + 2 byte duration
      if (sleepType === 0xF1 || sleepType === 0xF2 || sleepType === 0xF3) {
        const segTime = (data[segmentOffset+5] << 24) | (data[segmentOffset+4] << 16) | 
                       (data[segmentOffset+3] << 8) | data[segmentOffset+2];
        const duration = (data[segmentOffset+7] << 8) | data[segmentOffset+6];
        
        sleepSegments.push({
          type: sleepType,
          typeName: getSleepTypeName(sleepType),
          timestamp: segTime,
          duration: duration, // phút
          timeString: new Date(segTime * 1000).toISOString()
        });
        
        segmentOffset += 8;
      } else {
        segmentOffset++;
      }
    }
    
    return {
      startTime: startTime,
      startTimeString: new Date(startTime * 1000).toISOString(),
      endTime: endTime,
      endTimeString: new Date(endTime * 1000).toISOString(),
      sleepSegments: sleepSegments,
      rawSegmentData: bytesToHexString(data.slice(offset, offset + 20))
    };
  } catch (error) {
    console.error('[PARSE_ERROR] Lỗi khi phân tích dữ liệu bản ghi giấc ngủ:', error);
    return null;
  }
}

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
    case 0xF1:
      return 'Ngủ sâu';
    case 0xF2:
      return 'Ngủ nhẹ';
    case 0xF3:
      return 'REM (Mắt chuyển động nhanh)';
    case 0xF4:
      return 'Thức giấc';
    default:
      return `Không xác định (${sleepType.toString(16).toUpperCase()})`;
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