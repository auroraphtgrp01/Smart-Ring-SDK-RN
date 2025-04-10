# TÀI LIỆU PHÂN TÍCH QUY TRÌNH KẾT NỐI THIẾT BỊ VÀ TÍNH NĂNG THEO DÕI GIẤC NGỦ

## 1. TỔNG QUAN

Tài liệu này phân tích chi tiết quy trình kết nối thiết bị nhẫn thông minh và mối liên hệ của nó với tính năng theo dõi giấc ngủ. Mục tiêu là hiểu rõ các hoạt động diễn ra khi kết nối thiết bị, bao gồm quá trình đồng bộ hóa dữ liệu và các thiết lập cần thiết để theo dõi giấc ngủ đúng cách.

## 2. QUY TRÌNH KẾT NỐI THIẾT BỊ

### 2.1. Các thành phần chính

#### 2.1.1. YCBTClient và YCBTClientImpl
```java
// Đường dẫn: com.yucheng.ycbtsdk.YCBTClient
public class YCBTClient {
    // Kết nối thiết bị
    public static void connectDevice(String deviceAddress, BleConnectResponse bleConnectResponse) {
        YCBTClientImpl.getInstance().connectDevice(deviceAddress, bleConnectResponse);
    }
    
    // Ngắt kết nối
    public static void disconnectDevice() {
        YCBTClientImpl.getInstance().disconnectDevice();
    }
    
    // Các phương thức khác
}

// Đường dẫn: com.yucheng.ycbtsdk.core.YCBTClientImpl
public class YCBTClientImpl implements GattBleResponse {
    // Kết nối thiết bị
    public void connectDevice(String deviceAddress, BleConnectResponse bleConnectResponse) {
        // Thiết lập kết nối Bluetooth GATT
        this.bleConnectResponse = bleConnectResponse;
        this.isConnecting = true;
        BluetoothGattManager.getInstance().connect(deviceAddress, this);
    }
    
    // Xử lý sự kiện kết nối thành công
    public void onConnectSuccess() {
        // Thông báo kết nối thành công
        if (this.bleConnectResponse != null) {
            this.bleConnectResponse.onConnectResponse(0);
        }
        
        // Khởi tạo thiết bị
        initializeDevice();
        
        // Đồng bộ hóa dữ liệu
        syncDeviceData();
    }
    
    // Các phương thức khác
}
2.1.2. BluetoothGattManager
```java
// Đường dẫn: com.yucheng.ycbtsdk.ble.BluetoothGattManager
public class BluetoothGattManager {
    // Kết nối thiết bị
    public boolean connect(String deviceAddress, GattBleResponse gattBleResponse) {
        // Thiết lập kết nối GATT
        this.gattBleResponse = gattBleResponse;
        BluetoothDevice device = BluetoothAdapter.getDefaultAdapter().getRemoteDevice(deviceAddress);
        this.bluetoothGatt = device.connectGatt(context, false, this.gattCallback);
        return true;
    }
    
    // Callback cho các sự kiện GATT
    private BluetoothGattCallback gattCallback = new BluetoothGattCallback() {
        @Override
        public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                // Kết nối thành công, bắt đầu khám phá dịch vụ
                gatt.discoverServices();
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                // Ngắt kết nối
                if (gattBleResponse != null) {
                    gattBleResponse.onDisconnect();
                }
            }
        }
        
        @Override
        public void onServicesDiscovered(BluetoothGatt gatt, int status) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                // Dịch vụ đã được khám phá, thiết lập thông báo
                setupNotifications(gatt);
                
                // Thông báo kết nối thành công
                if (gattBleResponse != null) {
                    gattBleResponse.onConnectSuccess();
                }
            }
        }
        
        @Override
        public void onCharacteristicChanged(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic) {
            // Nhận dữ liệu từ thiết bị
            if (gattBleResponse != null) {
                gattBleResponse.onDataReceived(characteristic.getValue());
            }
        }
        
        // Các phương thức callback khác
    };
    
    // Thiết lập thông báo
    private void setupNotifications(BluetoothGatt gatt) {
        // Đăng ký nhận thông báo từ các đặc tính quan trọng
        BluetoothGattService service = gatt.getService(UUID_SERVICE);
        if (service != null) {
            BluetoothGattCharacteristic notifyCharacteristic = service.getCharacteristic(UUID_NOTIFY);
            if (notifyCharacteristic != null) {
                gatt.setCharacteristicNotification(notifyCharacteristic, true);
                BluetoothGattDescriptor descriptor = notifyCharacteristic.getDescriptor(UUID.fromString("00002902-0000-1000-8000-00805f9b34fb"));
                descriptor.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
                gatt.writeDescriptor(descriptor);
            }
        }
    }
}
    
        // Các phương thức khác
    }
    ```
2.1.3. DeviceConnectManager
```java
// Đường dẫn: com.yucheng.smarthealthpro.device.DeviceConnectManager
public class DeviceConnectManager {
    // Kết nối thiết bị
    public void connectDevice(String deviceAddress) {
        YCBTClient.connectDevice(deviceAddress, new BleConnectResponse() {
            @Override
            public void onConnectResponse(int i) {
                if (i == 0) {
                    // Kết nối thành công
                    onConnectSuccess(deviceAddress);
                } else {
                    // Kết nối thất bại
                    onConnectFailed(i);
                }
            }
        });
    }
    
    // Xử lý khi kết nối thành công
    public void onConnectSuccess(String deviceAddress) {
        // Lưu thông tin thiết bị
        saveDeviceInfo(deviceAddress);
        
        // Khởi tạo thiết bị
        initializeDevice();
        
        // Đồng bộ dữ liệu
        syncDeviceData();
        
        // Thông báo sự kiện kết nối thành công
        EventBus.getDefault().post(new DeviceConnectEvent(true));
    }
    
    // Khởi tạo thiết bị
    private void initializeDevice() {
        // Thiết lập thời gian
        YCBTClient.settingDeviceTime(System.currentTimeMillis(), null);
        
        // Thiết lập thông tin người dùng
        UserInfo userInfo = UserInfoManager.getInstance().getCurrentUserInfo();
        if (userInfo != null) {
            YCBTClient.settingUserInfo(
                userInfo.getHeight(),
                userInfo.getWeight(),
                userInfo.getAge(),
                userInfo.getGender(),
                null
            );
        }
        
        // Thiết lập các thông số khác, có thể bao gồm cả cài đặt giấc ngủ
        DeviceSettingsManager.applyCurrentSettings();
    }
    
    // Đồng bộ dữ liệu
    private void syncDeviceData() {
        DataSyncUtils.getInstance().startSync(new DataSyncEvent() {
            @Override
            public void callback(int state) {
                // Xử lý sự kiện đồng bộ
                if (state == SyncState.END) {
                    // Đồng bộ hoàn tất
                    EventBus.getDefault().post(new DataSyncEvent(SyncState.END));
                }
            }
        });
    }
}
```
2.1.4. DeviceSettingsManager
```java 
// Đường dẫn: com.yucheng.smarthealthpro.device.DeviceSettingsManager
public class DeviceSettingsManager {
    // Áp dụng các cài đặt hiện tại
    public static void applyCurrentSettings() {
        // Lấy các cài đặt từ lưu trữ
        DeviceSettings settings = SettingsManager.getInstance().getDeviceSettings();
        
        // Thiết lập thông báo
        YCBTClient.settingMessageNotify(settings.isEnableMessageNotify() ? 1 : 0, null);
        
        // Thiết lập nhắc nhở giấc ngủ
        SleepSettings sleepSettings = SettingsManager.getInstance().getSleepSettings();
        if (sleepSettings != null && sleepSettings.isEnabled()) {
            YCBTClient.settingSleepRemind(
                sleepSettings.getHour(),
                sleepSettings.getMinute(),
                1, // enable
                null
            );
        }
        
        // Các cài đặt khác
        // ...
    }
}
```
2.1.5. DataSyncUtils
```java
// Đường dẫn: com.yucheng.smarthealthpro.utils.DataSyncUtils
public class DataSyncUtils {
    // Bắt đầu đồng bộ
    public void startSync(DataSyncEvent event) {
        this.event = event;
        syncData();
    }
    
    // Đồng bộ dữ liệu
    private final void syncData() {
        syncing = true;
        this.isSyncDataSuccess = true;
        this.endDataType = 0;
        ArrayList arrayList = new ArrayList();
        this.finishDataType = 0;
        
        // Thêm các loại dữ liệu cần đồng bộ
        if (YCBTClient.isSupportFunction(Constants.FunctionConstant.ISHASHEARTRATE)) {
            arrayList.add(Integer.valueOf(Constants.DATATYPE.Health_HistoryHeart));
        }
        
        if (YCBTClient.isSupportFunction(Constants.FunctionConstant.ISHASSLEEP)) {
            arrayList.add(Integer.valueOf(Constants.DATATYPE.Health_HistorySleep));
        }
        
        if (YCBTClient.isSupportFunction(Constants.FunctionConstant.ISHASSPO2)) {
            arrayList.add(Integer.valueOf(Constants.DATATYPE.Health_HistoryOxygen));
        }
        
        // Lặp qua từng loại dữ liệu và lấy từ thiết bị
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            int intValue = ((Number) it2.next()).intValue();
            getWatchesData(intValue);
            this.endDataType = intValue;
        }
        
        // Thông báo kết thúc đồng bộ
        DataSyncEvent dataSyncEvent = this.event;
        if (dataSyncEvent != null) {
            dataSyncEvent.callback(SyncState.END);
        }
        this.finishDataType = this.endDataType;
    }
    
    // Lấy dữ liệu từ thiết bị
    private final void getWatchesData(final int dataType) {
        YCBTClient.getHealthHistoryData(dataType, 0, 0, new BleDataResponse() {
            @Override
            public void onDataResponse(int i2, float f2, HashMap hashMap) {
                // Xử lý dữ liệu nhận được từ thiết bị
                watchesResponse(dataType, i2, hashMap);
            }
        });
    }
    
    // Xử lý phản hồi từ thiết bị
    private final void watchesResponse(int dataType, int code, HashMap<Object, Object> result) {
        // Xử lý phản hồi theo từng loại dữ liệu
        // ...
        
        // Lưu dữ liệu vào cơ sở dữ liệu
        savaSyncData(this.asyncSession, dataType, result);
    }
    
    // Lưu dữ liệu vào cơ sở dữ liệu
    private final void savaSyncData(AsyncSession asyncSession, int dataType, HashMap<?, ?> resultMap) {
        // ...
        if (dataType == 1284) { // Constants.DATATYPE.Health_HistorySleep
            SaveDBDataUtil.savaSleepData(asyncSession, resultMap, context);
            return;
        }
        // ...
    }
}
```
2.2. Quy trình kết nối chi tiết
YCBTClient.connectDevice(deviceAddress, bleConnectResponse);
Thiết lập kết nối GATT
BluetoothGattManager.getInstance().connect(deviceAddress, this);
Khám phá dịch vụ
// Trong BluetoothGattCallback.onConnectionStateChange
gatt.discoverServices();
Thiết lập thông báo
// Trong BluetoothGattCallback.onServicesDiscovered
setupNotifications(gatt);
Thông báo kết nối thành công
// Trong BluetoothGattCallback.onServicesDiscovered
gattBleResponse.onConnectSuccess();
Khởi tạo thiết bị
// Trong onConnectSuccess
initializeDevice();
Đồng bộ dữ liệu
// Trong onConnectSuccess
syncDeviceData();


3. QUY TRÌNH KHỞI TẠO THIẾT BỊ VÀ ĐỒNG BỘ DỮ LIỆU
3.1. Khởi tạo thiết bị
Sau khi kết nối thành công, thiết bị được khởi tạo với một loạt các thiết lập:

Thiết lập thời gian
YCBTClient.settingDeviceTime(System.currentTimeMillis(), null);

Thiết lập thông tin người dùng
YCBTClient.settingUserInfo(
    userInfo.getHeight(),
    userInfo.getWeight(),
    userInfo.getAge(),
    userInfo.getGender(),
    null
);


Áp dụng các cài đặt hiện tại
DeviceSettingsManager.applyCurrentSettings();

Thiết lập nhắc nhở giấc ngủ (một phần của applyCurrentSettings)
// Trong DeviceSettingsManager.applyCurrentSettings
SleepSettings sleepSettings = SettingsManager.getInstance().getSleepSettings();
if (sleepSettings != null && sleepSettings.isEnabled()) {
    YCBTClient.settingSleepRemind(
        sleepSettings.getHour(),
        sleepSettings.getMinute(),
        1, // enable
        null
    );
}

3.2. Đồng bộ dữ liệu
Sau khi khởi tạo thiết bị, quá trình đồng bộ dữ liệu được bắt đầu:
Bắt đầu đồng bộ
DataSyncUtils.getInstance().startSync(dataSyncEvent);
Kiểm tra các tính năng được hỗ trợ
// Trong DataSyncUtils.syncData
if (YCBTClient.isSupportFunction(Constants.FunctionConstant.ISHASSLEEP)) {
    arrayList.add(Integer.valueOf(Constants.DATATYPE.Health_HistorySleep));
}
Lấy dữ liệu từ thiết bị
// Trong DataSyncUtils.syncData
Iterator it2 = arrayList.iterator();
while (it2.hasNext()) {
    int intValue = ((Number) it2.next()).intValue();
    getWatchesData(intValue);
    this.endDataType = intValue;
}

Xử lý dữ liệu nhận được
// Trong DataSyncUtils.getWatchesData
YCBTClient.getHealthHistoryData(dataType, 0, 0, new BleDataResponse() {
    @Override
    public void onDataResponse(int i2, float f2, HashMap hashMap) {
        watchesResponse(dataType, i2, hashMap);
    }
});

Lưu dữ liệu vào cơ sở dữ liệu
// Trong DataSyncUtils.watchesResponse
savaSyncData(this.asyncSession, dataType, result);

Thông báo đồng bộ hoàn tất
// Trong DataSyncUtils.syncData
DataSyncEvent dataSyncEvent = this.event;
if (dataSyncEvent != null) {
    dataSyncEvent.callback(SyncState.END);
}

4. MỐI LIÊN HỆ VỚI TÍNH NĂNG THEO DÕI GIẤC NGỦ
4.1. Thiết lập nhắc nhở giấc ngủ
Trong quá trình khởi tạo thiết bị, nhắc nhở giấc ngủ được thiết lập:

// Trong DeviceSettingsManager.applyCurrentSettings
SleepSettings sleepSettings = SettingsManager.getInstance().getSleepSettings();
if (sleepSettings != null && sleepSettings.isEnabled()) {
    YCBTClient.settingSleepRemind(
        sleepSettings.getHour(),
        sleepSettings.getMinute(),
        1, // enable
        null
    );
}

Phương thức settingSleepRemind là chìa khóa để kích hoạt theo dõi giấc ngủ tự động. Nó thiết lập thời gian bắt đầu theo dõi giấc ngủ và kích hoạt tính năng này.

4.2. Đồng bộ dữ liệu giấc ngủ
Trong quá trình đồng bộ dữ liệu, dữ liệu giấc ngủ được lấy và lưu tự động nếu thiết bị hỗ trợ:
// Trong DataSyncUtils.syncData
if (YCBTClient.isSupportFunction(Constants.FunctionConstant.ISHASSLEEP)) {
    arrayList.add(Integer.valueOf(Constants.DATATYPE.Health_HistorySleep));
}
Điều này đảm bảo rằng dữ liệu giấc ngủ được đồng bộ hóa mỗi khi thiết bị kết nối với ứng dụng.

4.3. Các chức năng liên quan đến giấc ngủ
YCBTClient cung cấp một số phương thức để tương tác với tính năng giấc ngủ:

Lấy trạng thái giấc ngủ hiện tại
YCBTClient.getSleepStatus(bleDataResponse);

Lấy dữ liệu lịch sử giấc ngủ
YCBTClient.getHealthHistoryData(Constants.DATATYPE.Health_HistorySleep, startTime, endTime, bleDataResponse);

Thiết lập nhắc nhở giấc ngủ
YCBTClient.settingSleepRemind(hour, minute, enable, bleDataResponse);

Xóa dữ liệu giấc ngủ
YCBTClient.deleteHealthHistoryData(Constants.DATATYPE.Health_DeleteSleep, bleDataResponse);

4.4. Bắt đầu theo dõi giấc ngủ thủ công
Mặc dù tài liệu không đề cập rõ, nhưng dựa trên phân tích log Bluetooth, có thể có một phương thức để bắt đầu theo dõi giấc ngủ theo yêu cầu. Gói dữ liệu có mẫu 03 09 09 00 01 00 02 có thể liên quan đến việc kích hoạt theo dõi giấc ngủ thủ công.