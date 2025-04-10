setTimeout(function() {
    console.log("[+] Starting heart rate measurement debug script");
    
    if (Java.available) {
        Java.perform(function() {
            try {
                var YCBTClient = Java.use("com.example.sdk.YCBTClient");
                console.log("[+] Successfully hooked YCBTClient class");
                
                YCBTClient.appStartMeasurement.implementation = function(startOrStop, measurementType, callback) {
                    console.log("[+] appStartMeasurement called with:");
                    console.log("    startOrStop: " + startOrStop + " (1=start, 0=stop)");
                    console.log("    measurementType: " + measurementType);
                    console.log("    callback: " + callback);
                    
                    console.log("    Constructing command bytes...");
                    
                    var result = this.appStartMeasurement(startOrStop, measurementType, callback);
                    console.log("[+] appStartMeasurement result: " + result);
                    return result;
                };
                
                YCBTClient.appSensorSwitchControl.implementation = function(sensorType, enabled, callback) {
                    console.log("[+] appSensorSwitchControl called with:");
                    console.log("    sensorType: " + sensorType); 
                    console.log("    enabled: " + enabled);
                    console.log("    callback: " + callback);
                    
                    var result = this.appSensorSwitchControl(sensorType, enabled, callback);
                    console.log("[+] appSensorSwitchControl result: " + result);
                    return result;
                };
                
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
                
                YCBTClient.write.implementation = function(bytes) {
                    var hexData = "";
                    for (var i = 0; i < bytes.length; i++) {
                        var byteValue = bytes[i] & 0xFF;
                        var hex = byteValue.toString(16).padStart(2, '0');
                        hexData += hex + " ";
                    }
                    
                    console.log("[+] BLE WRITE: " + hexData);
                    
                    if (bytes.length > 2) {
                        console.log("    Payload length: " + bytes.length);
                        console.log("    Command type: " + bytes[0] + ", " + bytes[1]);
                    }
                    
                    return this.write(bytes);
                };
                
                var YCBTCallback = Java.use("com.example.sdk.YCBTCallback");
                YCBTCallback.onReceive.implementation = function(bytes) {
                    var hexData = "";
                    for (var i = 0; i < bytes.length; i++) {
                        var byteValue = bytes[i] & 0xFF;
                        var hex = byteValue.toString(16).padStart(2, '0');
                        hexData += hex + " ";
                    }
                    
                    console.log("[+] BLE RECEIVE: " + hexData);
                    
                    if (bytes.length >= 5) {
                        if (bytes[0] === 0x06 && bytes[1] === 0x01) {
                            console.log("    HEART RATE DATA DETECTED: " + (bytes[4] & 0xFF) + " BPM");
                        }
                        else if (bytes[0] === 0x04 && bytes[1] === 0x0E) {
                            console.log("    MEASUREMENT COMPLETE NOTIFICATION");
                        }
                    }
                    
                    return this.onReceive(bytes);
                };
                
                try {
                    var HeartRateActivity = Java.use("com.example.app.HeartRateActivity");
                    console.log("[+] Successfully hooked HeartRateActivity");
                    
                    HeartRateActivity.startHeartRateMeasurement.implementation = function() {
                        console.log("[+] HeartRateActivity.startHeartRateMeasurement called");
                        return this.startHeartRateMeasurement();
                    };
                } catch (err) {
                    console.log("[-] HeartRateActivity not found or error: " + err);
                }
                
            } catch (err) {
                console.log("[-] Error hooking YCBTClient: " + err);
                
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
