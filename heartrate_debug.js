// FRIDA script để debug các phương thức đo nhịp tim
setTimeout(function() {
    console.log("[+] Starting heart rate measurement debug script");
    
    // Tải lớp Java YCBTClient (adjust package name if needed)
    if (Java.available) {
        Java.perform(function() {
            try {
                // Hook main YCBTClient class
                var YCBTClient = Java.use("com.example.sdk.YCBTClient");
                console.log("[+] Successfully hooked YCBTClient class");
                
                // Hook appStartMeasurement method
                YCBTClient.appStartMeasurement.implementation = function(startOrStop, measurementType, callback) {
                    console.log("[+] appStartMeasurement called with:");
                    console.log("    startOrStop: " + startOrStop + " (1=start, 0=stop)");
                    console.log("    measurementType: " + measurementType);
                    console.log("    callback: " + callback);
                    
                    // Theo dõi packet data
                    console.log("    Constructing command bytes...");
                    
                    // Call original method and return result
                    var result = this.appStartMeasurement(startOrStop, measurementType, callback);
                    console.log("[+] appStartMeasurement result: " + result);
                    return result;
                };
                
                // Hook appSensorSwitchControl - commonly used for heart rate
                YCBTClient.appSensorSwitchControl.implementation = function(sensorType, enabled, callback) {
                    console.log("[+] appSensorSwitchControl called with:");
                    console.log("    sensorType: " + sensorType); 
                    console.log("    enabled: " + enabled);
                    console.log("    callback: " + callback);
                    
                    var result = this.appSensorSwitchControl(sensorType, enabled, callback);
                    console.log("[+] appSensorSwitchControl result: " + result);
                    return result;
                };
                
                // Hook appPerform - preparation method
                if (YCBTClient.appPerform) {
                    YCBTClient.appPerform.implementation = function(type, callback) {
                        console.log("[+] appPerform called with:");
                        console.log("    type: " + type);
                        console.log("    callback: " + callback);
                        
                        var result = this.appPerform(type, callback);
                        console.log("[+] appPerform result: " + result);
                        return result;
                    };
                }
                
                // Hook settingHeartMonitor
                if (YCBTClient.settingHeartMonitor) {
                    YCBTClient.settingHeartMonitor.implementation = function(interval, callback) {
                        console.log("[+] settingHeartMonitor called with:");
                        console.log("    interval: " + interval);
                        console.log("    callback: " + callback);
                        
                        var result = this.settingHeartMonitor(interval, callback);
                        console.log("[+] settingHeartMonitor result: " + result);
                        return result;
                    };
                }
                
                // Hook write method to see raw data being sent
                YCBTClient.write.implementation = function(bytes) {
                    // Convert byte array to hex string for display
                    var hexData = "";
                    for (var i = 0; i < bytes.length; i++) {
                        var byteValue = bytes[i] & 0xFF;
                        var hex = byteValue.toString(16).padStart(2, '0');
                        hexData += hex + " ";
                    }
                    
                    console.log("[+] BLE WRITE: " + hexData);
                    
                    // Calculate checksum if possible
                    if (bytes.length > 2) {
                        // Assume last byte might be checksum
                        console.log("    Payload length: " + bytes.length);
                        console.log("    Command type: " + bytes[0] + ", " + bytes[1]);
                    }
                    
                    return this.write(bytes);
                };
                
                // Hook BLE callbacks to see responses
                var YCBTCallback = Java.use("com.example.sdk.YCBTCallback");
                YCBTCallback.onReceive.implementation = function(bytes) {
                    // Convert byte array to hex string for display
                    var hexData = "";
                    for (var i = 0; i < bytes.length; i++) {
                        var byteValue = bytes[i] & 0xFF;
                        var hex = byteValue.toString(16).padStart(2, '0');
                        hexData += hex + " ";
                    }
                    
                    console.log("[+] BLE RECEIVE: " + hexData);
                    
                    // Analyze known patterns
                    if (bytes.length >= 5) {
                        // Check for heart rate pattern
                        if (bytes[0] === 0x06 && bytes[1] === 0x01) {
                            console.log("    HEART RATE DATA DETECTED: " + (bytes[4] & 0xFF) + " BPM");
                        }
                        // Check for measurement completed pattern
                        else if (bytes[0] === 0x04 && bytes[1] === 0x0E) {
                            console.log("    MEASUREMENT COMPLETE NOTIFICATION");
                        }
                    }
                    
                    return this.onReceive(bytes);
                };
                
                // Nếu bạn biết package name chính xác của app, có thể hook Activity có chức năng đo nhịp tim
                try {
                    var HeartRateActivity = Java.use("com.example.app.HeartRateActivity");
                    console.log("[+] Successfully hooked HeartRateActivity");
                    
                    // Hook method bắt đầu đo
                    HeartRateActivity.startHeartRateMeasurement.implementation = function() {
                        console.log("[+] HeartRateActivity.startHeartRateMeasurement called");
                        return this.startHeartRateMeasurement();
                    };
                } catch (err) {
                    console.log("[-] HeartRateActivity not found or error: " + err);
                }
                
            } catch (err) {
                console.log("[-] Error hooking YCBTClient: " + err);
                
                // Try to find the actual class by enumerating classes
                console.log("[*] Searching for BLE related classes...");
                Java.enumerateLoadedClasses({
                    onMatch: function(className) {
                        if (className.toLowerCase().includes("ble") || 
                            className.toLowerCase().includes("bluetooth") ||
                            className.toLowerCase().includes("ycbt")) {
                            console.log("[+] Found potential class: " + className);
                        }
                    },
                    onComplete: function() {
                        console.log("[*] Class enumeration complete");
                    }
                });
            }
        });
    } else {
        console.log("[-] Java is not available on this device");
    }
    
}, 0);
