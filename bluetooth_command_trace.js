// FRIDA script để theo dõi các lệnh Bluetooth và phân tích chi tiết các command format
setTimeout(function() {
    console.log("[+] Starting Bluetooth command tracing script");
    
    if (Java.available) {
        Java.perform(function() {
            try {
                // Tìm kiếm các package phổ biến cho Smart Wearable SDK
                var possiblePackages = [
                    "com.example.sdk", 
                    "com.jstyle.blesdk", 
                    "com.veepoo.protocol", 
                    "com.fizzo.sdk",
                    "com.hplus.ble",
                    "com.ycbt.sdk"
                ];
                
                var foundPackage = null;
                
                // Tìm kiếm lớp YCBTClient hoặc tương tự trong các package phổ biến
                for (var i = 0; i < possiblePackages.length; i++) {
                    try {
                        var testClass = Java.use(possiblePackages[i] + ".YCBTClient");
                        foundPackage = possiblePackages[i];
                        console.log("[+] Found SDK package: " + foundPackage);
                        break;
                    } catch (e) {
                        // Tiếp tục thử package tiếp theo
                    }
                }
                
                // Nếu không tìm thấy, tìm kiếm tất cả các lớp liên quan đến BLE
                if (!foundPackage) {
                    console.log("[-] SDK package not found in common paths, searching all loaded classes...");
                    Java.enumerateLoadedClasses({
                        onMatch: function(className) {
                            if (className.toLowerCase().includes("ble") || 
                                className.toLowerCase().includes("bluetooth") ||
                                className.toLowerCase().includes("ycbt") ||
                                className.toLowerCase().includes("smartband")) {
                                console.log("[+] Found potential BLE class: " + className);
                            }
                        },
                        onComplete: function() {
                            console.log("[*] Class enumeration complete");
                        }
                    });
                }
                
                // Hook vào các phương thức Bluetooth cấp thấp
                var BluetoothGatt = Java.use("android.bluetooth.BluetoothGatt");
                var BluetoothGattCharacteristic = Java.use("android.bluetooth.BluetoothGattCharacteristic");
                
                // Theo dõi việc ghi dữ liệu đến đặc tính Bluetooth
                BluetoothGatt.writeCharacteristic.overload('android.bluetooth.BluetoothGattCharacteristic').implementation = function(characteristic) {
                    // Lấy UUID của đặc tính
                    var uuid = characteristic.getUuid().toString();
                    
                    // Lấy dữ liệu được ghi
                    var value = characteristic.getValue();
                    if (value != null) {
                        // Chuyển đổi thành chuỗi hex để hiển thị
                        var hexData = "";
                        for (var i = 0; i < value.length; i++) {
                            var byteValue = value[i] & 0xFF;
                            var hex = byteValue.toString(16).padStart(2, '0');
                            hexData += hex + " ";
                        }
                        
                        console.log("[BLE WRITE] UUID: " + uuid);
                        console.log("[BLE WRITE] Data: " + hexData);
                        
                        // Phân tích cấu trúc lệnh phổ biến
                        if (value.length > 2) {
                            console.log("[BLE COMMAND] Command Header: " + value[0] + ", " + value[1]);
                            
                            // Kiểm tra các loại lệnh đo nhịp tim phổ biến
                            if (value[0] === 3 && value[1] === 47) {
                                console.log("[HEART RATE] Detected appStartMeasurement command");
                                if (value.length > 5) {
                                    console.log("[HEART RATE] Start/Stop: " + value[4] + ", Type: " + value[5]);
                                }
                            }
                            else if (value[0] === 3 && value[1] === 9) {
                                console.log("[HEART RATE] Detected appPerform command");
                                if (value.length > 6) {
                                    console.log("[HEART RATE] Measure Type: " + value[6]);
                                }
                            }
                        }
                    }
                    
                    // Gọi phương thức gốc
                    return this.writeCharacteristic(characteristic);
                };
                
                // Theo dõi thông báo nhận được
                BluetoothGattCharacteristic.setValue.overload('[B').implementation = function(value) {
                    if (value != null) {
                        var hexData = "";
                        for (var i = 0; i < value.length; i++) {
                            var byteValue = value[i] & 0xFF;
                            var hex = byteValue.toString(16).padStart(2, '0');
                            hexData += hex + " ";
                        }
                        
                        var uuid = this.getUuid().toString();
                        console.log("[BLE RECEIVE] UUID: " + uuid);
                        console.log("[BLE RECEIVE] Data: " + hexData);
                        
                        // Phân tích dữ liệu nhịp tim
                        if (value.length >= 5) {
                            // Mẫu dữ liệu nhịp tim phổ biến: 06 01 xx xx HR
                            if (value[0] === 0x06 && value[1] === 0x01) {
                                console.log("[HEART RATE DATA] Heart Rate Value: " + (value[4] & 0xFF) + " BPM");
                            }
                            // Thông báo hoàn thành đo lường: 04 0E xx xx
                            else if (value[0] === 0x04 && value[1] === 0x0E) {
                                console.log("[MEASUREMENT] Measurement Complete Notification");
                            }
                        }
                    }
                    
                    return this.setValue(value);
                };
                
                // Theo dõi thiết lập thông báo
                BluetoothGatt.setCharacteristicNotification.implementation = function(characteristic, enable) {
                    var uuid = characteristic.getUuid().toString();
                    console.log("[BLE NOTIFY] Setting notification for UUID: " + uuid + " to " + enable);
                    
                    return this.setCharacteristicNotification(characteristic, enable);
                };
                
                console.log("[+] Bluetooth tracing hooks installed successfully");
                
            } catch (err) {
                console.log("[-] Error setting up Bluetooth hooks: " + err);
            }
        });
    } else {
        console.log("[-] Java is not available on this device");
    }
}, 0);
