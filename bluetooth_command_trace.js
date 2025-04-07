setTimeout(function() {
    console.log("[+] Starting Bluetooth command tracing script");
    
    if (Java.available) {
        Java.perform(function() {
            try {
                var possiblePackages = [
                    "com.example.sdk", 
                    "com.jstyle.blesdk", 
                    "com.veepoo.protocol", 
                    "com.fizzo.sdk",
                    "com.hplus.ble",
                    "com.ycbt.sdk"
                ];
                
                var foundPackage = null;
                
                for (var i = 0; i < possiblePackages.length; i++) {
                    try {
                        var testClass = Java.use(possiblePackages[i] + ".YCBTClient");
                        foundPackage = possiblePackages[i];
                        console.log("[+] Found SDK package: " + foundPackage);
                        break;
                    } catch (e) {
                    }
                }
                
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
                
                var BluetoothGatt = Java.use("android.bluetooth.BluetoothGatt");
                var BluetoothGattCharacteristic = Java.use("android.bluetooth.BluetoothGattCharacteristic");
                
                BluetoothGatt.writeCharacteristic.overload('android.bluetooth.BluetoothGattCharacteristic').implementation = function(characteristic) {
                    var uuid = characteristic.getUuid().toString();
                    
                    var value = characteristic.getValue();
                    if (value != null) {
                        var hexData = "";
                        for (var i = 0; i < value.length; i++) {
                            var byteValue = value[i] & 0xFF;
                            var hex = byteValue.toString(16).padStart(2, '0');
                            hexData += hex + " ";
                        }
                        
                        console.log("[BLE WRITE] UUID: " + uuid);
                        console.log("[BLE WRITE] Data: " + hexData);
                        
                        if (value.length > 2) {
                            console.log("[BLE COMMAND] Command Header: " + value[0] + ", " + value[1]);
                            
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
                    
                    return this.writeCharacteristic(characteristic);
                };
                
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
                        
                        if (value.length >= 5) {
                            if (value[0] === 0x06 && value[1] === 0x01) {
                                console.log("[HEART RATE DATA] Heart Rate Value: " + (value[4] & 0xFF) + " BPM");
                            }
                            else if (value[0] === 0x04 && value[1] === 0x0E) {
                                console.log("[MEASUREMENT] Measurement Complete Notification");
                            }
                        }
                    }
                    
                    return this.setValue(value);
                };
                
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
