/*
 * SPO2 Debugging Script for Smart Ring
 * 
 * This script hooks into key methods in the YCBTClient and related classes
 * to debug the SpO2 measurement functionality.
 */

// Helper function to format byte arrays nicely
function formatByteArray(byteArray) {
    if (!byteArray) return "null";
    
    try {
        let result = [];
        for (let i = 0; i < byteArray.length; i++) {
            let byte = byteArray[i];
            if (typeof byte === 'object' && byte.value !== undefined) {
                byte = byte.value;
            }
            result.push(('0' + (byte & 0xFF).toString(16)).slice(-2));
        }
        return result.join(' ');
    } catch (e) {
        return "Error formatting byte array: " + e.message;
    }
}

// Helper to format HashMap objects
function formatHashMap(hashMap) {
    if (!hashMap) return "null";
    
    try {
        const entries = hashMap.entrySet().toArray();
        let result = {};
        
        for (let i = 0; i < entries.length; i++) {
            const key = entries[i].getKey();
            const value = entries[i].getValue();
            result[key] = value;
        }
        
        return JSON.stringify(result, null, 2);
    } catch (e) {
        return "Error formatting HashMap: " + e.message;
    }
}

// Logger with timestamp and categories
function log(category, message) {
    const timestamp = new Date().toISOString().replace('T', ' ').substr(0, 19);
    console.log(`[${timestamp}] [${category}] ${message}`);
}

// Main hook function
function hookMethods() {
    Java.perform(function() {
        log("INFO", "Starting SPO2 debugging hooks...");
        
        // ======== YCBTClient Hooks ========
        
        // Hook getRealBloodOxygen
        var YCBTClient = Java.use("com.yucheng.ycbtsdk.YCBTClient");
        YCBTClient.getRealBloodOxygen.implementation = function(bleDataResponse) {
            log("YCBTClient", "getRealBloodOxygen called");
            this.getRealBloodOxygen(bleDataResponse);
        };
        
        // Hook appStartMeasurement
        YCBTClient.appStartMeasurement.implementation = function(i2, i3, bleDataResponse) {
            log("YCBTClient", `appStartMeasurement called with params: i2=${i2}, i3=${i3}`);
            this.appStartMeasurement(i2, i3, bleDataResponse);
        };
        
        // Hook settingBloodOxygenModeMonitor
        YCBTClient.settingBloodOxygenModeMonitor.implementation = function(z, i2, bleDataResponse) {
            log("YCBTClient", `settingBloodOxygenModeMonitor called with params: enabled=${z}, i2=${i2}`);
            this.settingBloodOxygenModeMonitor(z, i2, bleDataResponse);
        };
        
        // Hook appStartBloodMeasurement
        YCBTClient.appStartBloodMeasurement.overload('int', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'com.yucheng.ycbtsdk.response.BleDataResponse').implementation = function(i2, i3, i4, i5, i6, i7, i8, i9, bleDataResponse) {
            log("YCBTClient", `appStartBloodMeasurement called with params: [${i2}, ${i3}, ${i4}, ${i5}, ${i6}, ${i7}, ${i8}, ${i9}]`);
            this.appStartBloodMeasurement(i2, i3, i4, i5, i6, i7, i8, i9, bleDataResponse);
        };
        
        // Hook appSensorSwitchControl
        YCBTClient.appSensorSwitchControl.implementation = function(i2, i3, bleDataResponse) {
            log("YCBTClient", `appSensorSwitchControl called with params: i2=${i2}, i3=${i3}`);
            this.appSensorSwitchControl(i2, i3, bleDataResponse);
        };
        
        // ======== YCBTClientImpl Hooks ========
        
        // Hook sendSingleData2Device
        var YCBTClientImpl = Java.use("com.yucheng.ycbtsdk.core.YCBTClientImpl");
        YCBTClientImpl.sendSingleData2Device.overload('int', '[B', 'int', 'com.yucheng.ycbtsdk.response.BleDataResponse').implementation = function(dataType, data, i3, bleDataResponse) {
            log("YCBTClientImpl", `sendSingleData2Device called with dataType: ${dataType} (0x${dataType.toString(16)})`);
            log("YCBTClientImpl", `Data: ${formatByteArray(data)}`);
            return this.sendSingleData2Device(dataType, data, i3, bleDataResponse);
        };
        
        // Hook packetRealHandle - FIX: Correct signature with 4 parameters
        YCBTClientImpl.packetRealHandle.implementation = function(i2, i3, bArr, i4) {
            log("YCBTClientImpl", `packetRealHandle called with type: ${i3} (0x${i3.toString(16)})`);
            log("YCBTClientImpl", `Data array: ${formatByteArray(bArr)}`);
            log("YCBTClientImpl", `Additional params: i2=${i2}, i4=${i4}`);
            var result = this.packetRealHandle(i2, i3, bArr, i4);
            return result;
        };
        
        // Hook onCharacteristicChanged
        YCBTClientImpl.onCharacteristicChanged.implementation = function(bluetoothGatt, bluetoothGattCharacteristic) {
            var value = bluetoothGattCharacteristic.getValue();
            log("BLE", `onCharacteristicChanged: ${formatByteArray(value)}`);
            this.onCharacteristicChanged(bluetoothGatt, bluetoothGattCharacteristic);
        };
        
        // Hook onCharacteristicRead
        YCBTClientImpl.onCharacteristicRead.implementation = function(bluetoothGatt, bluetoothGattCharacteristic, status) {
            var value = bluetoothGattCharacteristic.getValue();
            log("BLE", `onCharacteristicRead (status=${status}): ${formatByteArray(value)}`);
            this.onCharacteristicRead(bluetoothGatt, bluetoothGattCharacteristic, status);
        };
        
        // Hook onCharacteristicWrite
        YCBTClientImpl.onCharacteristicWrite.implementation = function(bluetoothGatt, bluetoothGattCharacteristic, status) {
            var value = bluetoothGattCharacteristic.getValue();
            log("BLE", `onCharacteristicWrite (status=${status}): ${formatByteArray(value)}`);
            this.onCharacteristicWrite(bluetoothGatt, bluetoothGattCharacteristic, status);
        };
        
        // ======== DataUnpack Hooks ========
        
        // Hook unpackRealBloodOxygenData
        var DataUnpack = Java.use("com.yucheng.ycbtsdk.core.DataUnpack");
        DataUnpack.unpackRealBloodOxygenData.implementation = function(bArr) {
            log("DataUnpack", `unpackRealBloodOxygenData called with data: ${formatByteArray(bArr)}`);
            var result = this.unpackRealBloodOxygenData(bArr);
            log("DataUnpack", `SpO2 Result: ${formatHashMap(result)}`);
            return result;
        };
        
        // Hook unpackGetRealBloodOxygen
        DataUnpack.unpackGetRealBloodOxygen.implementation = function(bArr) {
            log("DataUnpack", `unpackGetRealBloodOxygen called with data: ${formatByteArray(bArr)}`);
            var result = this.unpackGetRealBloodOxygen(bArr);
            log("DataUnpack", `Result: ${formatHashMap(result)}`);
            return result;
        };
        
        // ======== BleDataResponse Hooks ========
        
        // Hook BleDataResponse.onDataResponse
        var BleDataResponse = Java.use("com.yucheng.ycbtsdk.response.BleDataResponse");
        BleDataResponse.onDataResponse.implementation = function(dataType, hashMap) {
            log("BleDataResponse", `onDataResponse called with dataType: ${dataType} (0x${dataType.toString(16)})`);
            log("BleDataResponse", `Response data: ${formatHashMap(hashMap)}`);
            this.onDataResponse(dataType, hashMap);
        };
        
        // Hook BleRealDataResponse.onRealDataResponse
        var BleRealDataResponse = Java.use("com.yucheng.ycbtsdk.response.BleRealDataResponse");
        BleRealDataResponse.onRealDataResponse.implementation = function(dataType, hashMap) {
            log("BleRealDataResponse", `onRealDataResponse called with dataType: ${dataType} (0x${dataType.toString(16)})`);
            log("BleRealDataResponse", `Response data: ${formatHashMap(hashMap)}`);
            this.onRealDataResponse(dataType, hashMap);
        };
        
        // ======== Constants Inspection ========
        
        // Log important constants for reference
        var Constants = Java.use("com.yucheng.ycbtsdk.Constants");
        log("Constants", `BloodOxygen = ${Constants.MeasureType.BloodOxygen.value}`);
        log("Constants", `GetRealBloodOxygen = ${Constants.DATATYPE.GetRealBloodOxygen.value}`);
        log("Constants", `Real_UploadBloodOxygen = ${Constants.DATATYPE.Real_UploadBloodOxygen.value}`);
        log("Constants", `AppStartMeasurement = ${Constants.DATATYPE.AppStartMeasurement.value}`);
        log("Constants", `SettingBloodOxygenModeMonitor = ${Constants.DATATYPE.SettingBloodOxygenModeMonitor.value}`);
        
        // ======== CMD Inspection ========
        
        // Log important CMD values for reference
        var CMD = Java.use("com.yucheng.ycbtsdk.core.CMD");
        log("CMD", `RealBloodOxygen = ${CMD.RealDataType.RealBloodOxygen.value}`);
        log("CMD", `StartMeasurement = ${CMD.ControlCmd.StartMeasurement.value}`);
        log("CMD", `BloodOxygenModeMonitor = ${CMD.SettingCmd.BloodOxygenModeMonitor.value}`);
        
        log("INFO", "All SPO2 debugging hooks installed successfully!");
    });
}

// Start the hooks
setTimeout(hookMethods, 1000);
