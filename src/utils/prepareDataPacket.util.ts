export function prepareDataPacket(commandCode: number, data: Uint8Array): Uint8Array {
  // Tính độ dài gói dữ liệu: data + 6 byte (2 byte mã lệnh + 2 byte độ dài + 2 byte CRC)
  const packetLength = data.length + 6;
  const packet = new Uint8Array(packetLength);

  // Đặt 2 byte mã lệnh (big-endian)
  packet[0] = (commandCode >> 8) & 0xFF;   // Byte cao của mã lệnh
  packet[1] = commandCode & 0xFF;          // Byte thấp của mã lệnh

  // Đặt 2 byte độ dài (little-endian)
  packet[2] = packetLength & 0xFF;         // Byte thấp của độ dài
  packet[3] = (packetLength >> 8) & 0xFF;  // Byte cao của độ dài

  // Sao chép dữ liệu
  for (let i = 0; i < data.length; i++) {
    packet[i + 4] = data[i];
  }

  // Tính CRC16 cho toàn bộ gói trừ 2 byte cuối
  const crc = crc16_compute(packet, packetLength - 2);

  // Đặt 2 byte CRC (little-endian)
  packet[packetLength - 2] = crc & 0xFF;           // Byte thấp của CRC
  packet[packetLength - 1] = (crc >> 8) & 0xFF;    // Byte cao của CRC

  return packet;
}

export function crc16_compute(data: Uint8Array, length: number): number {
    let crc = 0xFFFF;
    const polynomial = 0x1021; // CRC-16-CCITT polynomial
  
    for (let i = 0; i < length; i++) {
      crc ^= (data[i] << 8);
      for (let j = 0; j < 8; j++) {
        if ((crc & 0x8000) !== 0) {
          crc = ((crc << 1) ^ polynomial) & 0xFFFF;
        } else {
          crc = (crc << 1) & 0xFFFF;
        }
      }
    }
  
    return crc & 0xFFFF;
  }