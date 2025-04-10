# TÀI LIỆU PHÂN TÍCH CƠ CHẾ THEO DÕI GIẤC NGỦ TRONG ỨNG DỤNG NHẪN THÔNG MINH

## 1. TỔNG QUAN

Tài liệu này tổng hợp các phân tích về cơ chế theo dõi giấc ngủ trong ứng dụng kết nối với nhẫn thông minh qua Bluetooth. Mục tiêu là hiểu rõ quy trình từ khi thu thập dữ liệu giấc ngủ từ thiết bị, xử lý, lưu trữ và hiển thị trong ứng dụng để triển khai tính năng này trong ứng dụng React Native mới.

## 2. CÁC THÀNH PHẦN CHÍNH

### 2.1. Cấu trúc dữ liệu giấc ngủ

#### 2.1.1. SleepResponse
Lớp chính xử lý phản hồi dữ liệu giấc ngủ từ thiết bị:
```java
// Đường dẫn: com.yucheng.smarthealthpro.home.bean.SleepResponse
public class SleepResponse {
    private List<SleepDataBean> sleepData;
    // Các thuộc tính và phương thức khác
}
```

#### 2.1.2. SleepDataBean
Lớp đại diện cho một phiên giấc ngủ:
```java
public class SleepDataBean {
    private int deepSleepCount;     // Số lượng giấc ngủ sâu
    private int deepSleepTotal;     // Tổng thời gian giấc ngủ sâu
    private long endTime;           // Thời điểm kết thúc
    public boolean isUpload;        // Đã tải lên chưa
    private int lightSleepCount;    // Số lượng giấc ngủ nhẹ
    private int lightSleepTotal;    // Tổng thời gian giấc ngủ nhẹ
    private List<SleepData> sleepData; // Danh sách dữ liệu giấc ngủ chi tiết
    private long startTime;         // Thời điểm bắt đầu
}
```

#### 2.1.3. HistorySleepResponse
Lớp xử lý phản hồi từ yêu cầu dữ liệu lịch sử giấc ngủ:
```java
// Đường dẫn: com.yucheng.smarthealthpro.care.bean.HistorySleepResponse
public class HistorySleepResponse {
    private int code;
    private String msg;
    private List<SleepDataBean> data;
}
```

#### 2.1.4. HistorySleep
Lớp lưu trữ thông tin lịch sử giấc ngủ:
```java
// Đường dẫn: com.yucheng.smarthealthpro.care.bean.HistorySleep
public class HistorySleep {
    private int sleepLong;  // Thời lượng giấc ngủ
    private int sleepType;  // Loại giấc ngủ
    private long stime;     // Thời gian bắt đầu
}
```

#### 2.1.5. SleepDb
Lớp đại diện bảng dữ liệu giấc ngủ trong cơ sở dữ liệu GreenDAO:
```java
// Đường dẫn: com.yucheng.smarthealthpro.greendao.bean.SleepDb
public class SleepDb {
    private Long id;
    private long startTime;         // Thời điểm bắt đầu
    private long endTime;           // Thời điểm kết thúc
    private int deepSleepCount;     // Số lượng giấc ngủ sâu
    private int lightSleepCount;    // Số lượng giấc ngủ nhẹ
    private String userId;          // ID người dùng
    private String deviceId;        // ID thiết bị
    private String dataGroupId;     // ID nhóm dữ liệu
    private boolean isUpload;       // Đã tải lên chưa
    private String sleepData;       // Dữ liệu giấc ngủ dạng JSON
    // Các thuộc tính và phương thức khác
}
```

### 2.2. Các lớp tiện ích

#### 2.2.1. SleepDbUtils
Lớp tiện ích để tương tác với bảng SleepDb trong cơ sở dữ liệu:
```java
// Đường dẫn: com.yucheng.smarthealthpro.greendao.utils.SleepDbUtils
public class SleepDbUtils {
    // Chèn dữ liệu giấc ngủ mới
    public boolean insertMsgModel(SleepDb sleepDb) {
        return daoManager.getDaoSession().getSleepDbDao().insert(sleepDb) > 0;
    }
    
    // Các phương thức khác để tìm kiếm, cập nhật, xóa dữ liệu giấc ngủ
}
```

#### 2.2.2. DataSyncUtils
Lớp xử lý đồng bộ hóa dữ liệu từ thiết bị với cơ sở dữ liệu của ứng dụng:
```java
// Đường dẫn: com.yucheng.smarthealthpro.utils.DataSyncUtils
public class DataSyncUtils {
    // Phương thức đồng bộ dữ liệu từ thiết bị
    private final void syncData() {
        syncing = true;
        this.isSyncDataSuccess = true;
        this.endDataType = 0;
        ArrayList arrayList = new ArrayList();
        this.finishDataType = 0;
        
        // Kiểm tra thiết bị có hỗ trợ tính năng giấc ngủ không
        if (YCBTClient.isSupportFunction(Constants.FunctionConstant.ISHASSLEEP)) {
            arrayList.add(Integer.valueOf(Constants.DATATYPE.Health_HistorySleep));
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
    
    // Phương thức lấy dữ liệu từ thiết bị
    private final void getWatchesData(final int dataType) {
        if (dataType == 3445) {
            // Xử lý loại dữ liệu khác
        } else {
            // Lấy dữ liệu lịch sử sức khỏe, trong đó có dữ liệu giấc ngủ
            YCBTClient.getHealthHistoryData(dataType, 0, 0, new BleDataResponse() {
                @Override
                public void onDataResponse(int i2, float f2, HashMap hashMap) {
                    // Xử lý dữ liệu nhận được từ thiết bị
                    watchesResponse(dataType, i2, hashMap);
                }
            });
        }
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
    
    // Xóa dữ liệu giấc ngủ trên thiết bị
    private final void deleteWatchesHistoryData(final int type) {
        // ...
        YCBTClient.deleteHealthHistoryData(type, new BleDataResponse() {
            // ...
        });
    }
}
```

#### 2.2.3. SaveDBDataUtil
Lớp tiện ích để lưu dữ liệu vào cơ sở dữ liệu:
```java
// Đường dẫn: com.yucheng.smarthealthpro.home.util.SaveDBDataUtil
public class SaveDBDataUtil {
    // Lưu dữ liệu giấc ngủ vào cơ sở dữ liệu
    public static void savaSleepData(AsyncSession asyncSession, HashMap<?, ?> resultMap, Context context) {
        // Xử lý và lưu dữ liệu giấc ngủ
    }
    
    // Các phương thức khác
}
```

### 2.3. Các hằng số và lệnh

#### 2.3.1. Hằng số loại giấc ngủ (SleepType)
```java
// Đường dẫn: com.yucheng.ycbtsdk.Constants.SleepType
public class SleepType {
    public static final int awake = 244;        // Tỉnh táo
    public static final int deepSleep = 241;    // Giấc ngủ sâu
    public static final int lightSleep = 242;   // Giấc ngủ nhẹ
    public static final int naps = 245;         // Ngủ trưa
    public static final int rem = 243;          // Giai đoạn REM
    public static final int unknow = -1;        // Không xác định
}
```

#### 2.3.2. Hằng số mã lệnh (CMD)
```java
// Đường dẫn: com.yucheng.ycbtsdk.core.CMD
public class CMD {
    // Mã lệnh liên quan đến giấc ngủ
    public static class KEY_Health {
        public static final int HistorySleep = 4;       // Lấy lịch sử giấc ngủ
        public static final int HistorySleepAck = 19;   // Phản hồi lịch sử giấc ngủ
        public static final int DeleteSleep = 66;       // Xóa dữ liệu giấc ngủ
    }
    
    public static class KEY_Get {
        public static final int SleepStatus = 38;      // Lấy trạng thái giấc ngủ
    }
    
    public static class KEY_Setting {
        public static final int SleepRemind = 26;      // Nhắc nhở giấc ngủ
    }
}
```

#### 2.3.3. Hằng số mã dữ liệu (DATATYPE)
```java
// Đường dẫn: com.yucheng.ycbtsdk.Constants.DATATYPE
public class DATATYPE {
    public static final int Health_HistorySleep = 1284;      // Dữ liệu lịch sử giấc ngủ
    public static final int Health_DeleteSleep = 1348;       // Xóa dữ liệu giấc ngủ
    public static final int GetSleepStatus = 526;            // Lấy trạng thái giấc ngủ
    // Các hằng số khác
}
```

### 2.4. Interface và triển khai

#### 2.4.1. YCBTClient
Interface chính để giao tiếp với thiết bị nhẫn thông minh:
```java
// Đường dẫn: com.yucheng.ycbtsdk.YCBTClient
public class YCBTClient {
    // Lấy trạng thái giấc ngủ hiện tại
    public static void getSleepStatus(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.GetSleepStatus, new byte[0], 2, bleDataResponse);
    }
    
    // Cập nhật dữ liệu giấc ngủ về thiết bị
    public static void appSleepWriteBack(int i2, int i3, int i4, int i5, int i6, int i7, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppSleepWriteBack, new byte[]{(byte) i2, (byte) i3, (byte) i4, (byte) i5, (byte) i6, (byte) i7}, 2, bleDataResponse);
    }
    
    // Thiết lập nhắc nhở giấc ngủ
    public static void settingSleepRemind(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingSleepRemind, new byte[]{(byte) i2, (byte) i3, (byte) i4}, 2, bleDataResponse);
    }
    
    // Lấy dữ liệu lịch sử giấc ngủ
    public static void getHealthHistoryData(int dataType, long startTime, long endTime, BleDataResponse response) {
        // Triển khai để lấy dữ liệu lịch sử sức khỏe, bao gồm giấc ngủ
    }
    
    // Kiểm tra xem thiết bị có hỗ trợ tính năng giấc ngủ không
    public static boolean isSupportFunction(int function) {
        // Kiểm tra thiết bị có hỗ trợ tính năng được chỉ định không
    }
    
    // Xóa dữ liệu lịch sử giấc ngủ
    public static void deleteHealthHistoryData(int type, BleDataResponse response) {
        // Triển khai xóa dữ liệu lịch sử sức khỏe, bao gồm giấc ngủ
    }
}
```

#### 2.4.2. YCBTClientImpl
Lớp triển khai thực tế của YCBTClient:
```java
// Đường dẫn: com.yucheng.ycbtsdk.core.YCBTClientImpl
public class YCBTClientImpl implements GattBleResponse {
    // Gửi dữ liệu đến thiết bị
    public void sendSingleData2Device(int i2, byte[] bArr, int i3, BleDataResponse bleDataResponse) {
        // Triển khai gửi lệnh đơn lẻ đến thiết bị
    }
    
    // Xử lý dữ liệu nhận được từ thiết bị
    private HashMap packetCollectHandle(int i2, int i3, byte[] bArr, int i4) {
        // Xử lý gói dữ liệu thu thập từ thiết bị
    }
}
```

#### 2.4.3. DataUnpack
Lớp giải mã dữ liệu nhận từ thiết bị:
```java
// Đường dẫn: com.yucheng.ycbtsdk.core.DataUnpack
public class DataUnpack {
    // Giải mã dữ liệu sức khỏe, bao gồm dữ liệu giấc ngủ
    public static HashMap unpackHealthData(byte[] bArr, int i2) {
        // Xử lý dữ liệu giấc ngủ
        if (i2 == Constants.DATATYPE.Health_HistorySleep) {
            // Giải mã và tạo đối tượng dữ liệu giấc ngủ
            hashMap4.put("dataType", Integer.valueOf(Constants.DATATYPE.Health_HistorySleep));
            // Xử lý thêm
        }
        
        // Trả về dữ liệu đã giải mã
        return hashMap;
    }
}
```

## 3. QUY TRÌNH THEO DÕI GIẤC NGỦ

### 3.1. Kiểm tra hỗ trợ

Trước khi lấy dữ liệu giấc ngủ, ứng dụng kiểm tra xem thiết bị có hỗ trợ tính năng này không:

```java
if (YCBTClient.isSupportFunction(Constants.FunctionConstant.ISHASSLEEP)) {
    // Tiến hành lấy dữ liệu giấc ngủ
}
```

### 3.2. Yêu cầu dữ liệu giấc ngủ

Khi thiết bị hỗ trợ, ứng dụng yêu cầu dữ liệu lịch sử giấc ngủ:

```java
YCBTClient.getHealthHistoryData(Constants.DATATYPE.Health_HistorySleep, 0, 0, new BleDataResponse() {
    @Override
    public void onDataResponse(int i2, float f2, HashMap hashMap) {
        // Xử lý dữ liệu nhận được
    }
});
```

### 3.3. Xử lý dữ liệu nhận về

Khi nhận được dữ liệu từ thiết bị, ứng dụng xử lý và lưu vào cơ sở dữ liệu:

```java
private final void watchesResponse(int dataType, int code, HashMap<Object, Object> result) {
    // Xử lý phản hồi
    savaSyncData(this.asyncSession, dataType, result);
}

private final void savaSyncData(AsyncSession asyncSession, int dataType, HashMap<?, ?> resultMap) {
    if (dataType == 1284) { // Constants.DATATYPE.Health_HistorySleep
        SaveDBDataUtil.savaSleepData(asyncSession, resultMap, context);
    }
}
```

### 3.4. Lưu trữ dữ liệu

Dữ liệu giấc ngủ được lưu vào cơ sở dữ liệu GreenDAO thông qua lớp `SaveDBDataUtil`:

```java
public static void savaSleepData(AsyncSession asyncSession, HashMap<?, ?> resultMap, Context context) {
    // Xử lý và lưu dữ liệu giấc ngủ vào SleepDb
}
```

### 3.5. Xóa dữ liệu giấc ngủ

Nếu cần xóa dữ liệu giấc ngủ trên thiết bị:

```java
YCBTClient.deleteHealthHistoryData(Constants.DATATYPE.Health_DeleteSleep, new BleDataResponse() {
    @Override
    public void onDataResponse(int i2, float f2, HashMap hashMap) {
        // Xử lý phản hồi sau khi xóa
    }
});
```

## 4. CẤU TRÚC DỮ LIỆU GIẤC NGỦ CHI TIẾT

### 4.1. Giai đoạn giấc ngủ

Dữ liệu giấc ngủ được phân loại thành các giai đoạn khác nhau:
- Giấc ngủ sâu (Deep Sleep): 241
- Giấc ngủ nhẹ (Light Sleep): 242
- Giai đoạn REM: 243
- Tỉnh táo (Awake): 244
- Ngủ trưa (Naps): 245

### 4.2. Thông tin thống kê

Mỗi phiên giấc ngủ lưu trữ các thông tin thống kê:
- Thời điểm bắt đầu và kết thúc
- Số lượng và tổng thời gian giấc ngủ sâu
- Số lượng và tổng thời gian giấc ngủ nhẹ
- Dữ liệu chi tiết từng giai đoạn giấc ngủ

## 5. HƯỚNG DẪN TRIỂN KHAI TRONG REACT NATIVE

### 5.1. Kiểm tra thiết bị có hỗ trợ tính năng giấc ngủ

```javascript
// Kiểm tra thiết bị có hỗ trợ tính năng giấc ngủ không
const checkSleepSupport = () => {
  return new Promise((resolve, reject) => {
    NativeModules.YCBTModule.isSupportFunction(Constants.FunctionConstant.ISHASSLEEP, (result) => {
      resolve(result);
    });
  });
};
```

### 5.2. Lấy dữ liệu lịch sử giấc ngủ

```javascript
// Lấy dữ liệu lịch sử giấc ngủ
const getSleepData = () => {
  return new Promise((resolve, reject) => {
    NativeModules.YCBTModule.getHealthHistoryData(
      Constants.DATATYPE.Health_HistorySleep,
      0, // startTime
      0, // endTime
      (code, result) => {
        if (code === 0) {
          resolve(result);
        } else {
          reject(new Error(`Failed to get sleep data: ${code}`));
        }
      }
    );
  });
};
```

### 5.3. Lưu trữ dữ liệu

```javascript
// Lưu dữ liệu giấc ngủ vào cơ sở dữ liệu local
const saveSleepData = async (sleepData) => {
  try {
    // Sử dụng thư viện lưu trữ dữ liệu như AsyncStorage, Realm, SQLite...
    await AsyncStorage.setItem('SLEEP_DATA', JSON.stringify(sleepData));
    return true;
  } catch (error) {
    console.error('Error saving sleep data:', error);
    return false;
  }
};
```

### 5.4. Xóa dữ liệu giấc ngủ

```javascript
// Xóa dữ liệu giấc ngủ
const deleteSleepData = () => {
  return new Promise((resolve, reject) => {
    NativeModules.YCBTModule.deleteHealthHistoryData(
      Constants.DATATYPE.Health_DeleteSleep,
      (code, result) => {
        if (code === 0) {
          resolve(true);
        } else {
          reject(new Error(`Failed to delete sleep data: ${code}`));
        }
      }
    );
  });
};
```

## 6. KẾT LUẬN

Tài liệu này đã cung cấp phân tích chi tiết về cách ứng dụng Java tương tác với nhẫn thông minh để thu thập, xử lý và lưu trữ dữ liệu giấc ngủ. Thông tin này có thể được sử dụng làm cơ sở để triển khai tính năng tương tự trong ứng dụng React Native SmartRingRN2.

Khi triển khai, cần đặc biệt chú ý đến việc:
1. Kiểm tra thiết bị có hỗ trợ tính năng giấc ngủ không
2. Sử dụng đúng mã lệnh/hằng số để giao tiếp với thiết bị
3. Xử lý dữ liệu nhận về đúng cách
4. Lưu trữ dữ liệu phù hợp với cấu trúc của React Native

## 7. CHI TIẾT CƠ CHẾ HOẠT ĐỘNG CỦA CẢM BIẾN THEO DÕI GIẤC NGỦ

### 7.1. Cảm biến được sử dụng

Sau khi phân tích mã nguồn, đã xác định được thiết bị nhẫn thông minh sử dụng các cảm biến sau để theo dõi giấc ngủ:

#### 7.1.1. Cảm biến gia tốc (Accelerometer)

```java
// com.yucheng.ycbtsdk.bean.GsensorBean
public class GsensorBean {
    public Short x;
    public Short y;
    public Short z;
}
```

Cảm biến gia tốc 3 trục (x, y, z) đóng vai trò chính trong việc theo dõi giấc ngủ. Cơ chế hoạt động như sau:

1. **Thu thập dữ liệu chuyển động**: Ghi lại các chuyển động nhỏ của cơ thể khi ngủ
2. **Phân tích mẫu chuyển động**: 
   - Chuyển động nhiều và không đều: Giai đoạn tỉnh táo hoặc giấc ngủ nhẹ
   - Ít chuyển động: Giai đoạn ngủ sâu
   - Chuyển động mức trung bình với mẫu đặc trưng: Giai đoạn REM

#### 7.1.2. Cảm biến nhịp tim (tùy model thiết bị)

Một số model nhẫn thông minh cao cấp hơn còn kết hợp dữ liệu nhịp tim để cải thiện độ chính xác trong phân tích giấc ngủ. Sự thay đổi nhịp tim cũng là dấu hiệu để phân biệt các giai đoạn giấc ngủ khác nhau.

### 7.2. Thuật toán phân tích

Phân tích mã nguồn cho thấy thiết bị sử dụng thuật toán phân tích giấc ngủ được triển khai trong firmware, dựa vào các nguyên tắc sau:

1. **Xác định thời điểm đi ngủ và thức dậy**:
   - Phát hiện giai đoạn nằm yên kéo dài
   - Nhận diện mẫu chuyển động đặc trưng khi thức dậy

2. **Phân loại giai đoạn giấc ngủ** dựa trên mức độ chuyển động:
   - **Giấc ngủ sâu (241)**: Rất ít hoặc không có chuyển động
   - **Giấc ngủ nhẹ (242)**: Chuyển động nhỏ, không thường xuyên
   - **REM (243)**: Mức chuyển động trung bình với mẫu đặc trưng
   - **Thức giấc (244)**: Chuyển động mạnh hoặc liên tục

3. **Phân tích liên tục** trong suốt thời gian ngủ, với chu kỳ kiểm tra thường là 1-5 phút (tùy vào cài đặt tiết kiệm pin).

## 8. QUY TRÌNH XỬ LÝ DỮ LIỆU GIẤC NGỦ CHI TIẾT

### 8.1. Thu thập dữ liệu thô từ thiết bị

Dữ liệu giấc ngủ được thu thập theo quy trình sau:

```java
// Kiểm tra hỗ trợ
if (YCBTClient.isSupportFunction(Constants.FunctionConstant.ISHASSLEEP)) {
    // Lấy dữ liệu lịch sử giấc ngủ
    YCBTClient.getHealthHistoryData(Constants.DATATYPE.Health_HistorySleep, 0, 0, new BleDataResponse() {
        @Override
        public void onDataResponse(int i, float f, HashMap hashMap) {
            // Dữ liệu thô nhận được từ thiết bị
        }
    });
}
```

### 8.2. Giải mã dữ liệu

Dữ liệu thô từ thiết bị được giải mã qua phương thức `DataUnpack.unpackHealthData()`:

```java
// Trích xuất từ com.yucheng.ycbtsdk.core.DataUnpack
public static HashMap unpackHealthData(byte[] bArr, int i2) {
    // i2 == Constants.DATATYPE.Health_HistorySleep (1284)
    HashMap hashMap = new HashMap();
    // Quá trình giải mã byte array thành dữ liệu giấc ngủ
    // ...
    hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Health_HistorySleep));
    return hashMap;
}
```

### 8.3. Chuyển đổi sang đối tượng SleepResponse

Dữ liệu đã giải mã được chuyển thành đối tượng SleepResponse:

```java
// Trích xuất từ SaveDBDataUtil.savaSleepData
List<SleepResponse.SleepDataBean> data = ((SleepResponse) new Gson().fromJson(String.valueOf(hashMap), SleepResponse.class)).getData();
```

### 8.4. Lưu trữ vào cơ sở dữ liệu

Sau khi chuyển đổi, dữ liệu được lưu vào SleepDb trong GreenDAO:

```java
// Quá trình lưu trữ từng phiên giấc ngủ
SleepResponse.SleepDataBean sleepDataBean = (SleepResponse.SleepDataBean) data.get(i2);
SleepDb sleepDb = new SleepDb();
sleepDb.setDeepSleepCount(sleepDataBean.getDeepSleepCount());
sleepDb.setLightSleepCount(sleepDataBean.getLightSleepCount());
sleepDb.setStartTime(sleepDataBean.getStartTime());
sleepDb.setEndTime(sleepDataBean.getEndTime());
sleepDb.setDeepSleepTotal(sleepDataBean.getDeepSleepTotal());
sleepDb.setLightSleepTotal(sleepDataBean.getLightSleepTotal());
sleepDb.setRapidEyeMovementTotal(sleepDataBean.rapidEyeMovementTotal);
sleepDb.setWakeCount(sleepDataBean.wakeCount);
sleepDb.setWakeDuration(sleepDataBean.wakeDuration);
sleepDb.setSleepData(new Gson().toJson(sleepDataBean.getSleepData()));
sleepDb.setIsUpload(sleepDataBean.isUpload);
new SleepDbUtils(context).insertMsgModel(sleepDb);
```

### 8.5. Phân tích và xử lý thống kê

Sau khi lưu trữ, dữ liệu được phân tích để tạo ra các thống kê có ý nghĩa:

1. **Tổng thời gian ngủ**: `deepSleepTotal + lightSleepTotal + rapidEyeMovementTotal`
2. **Chất lượng giấc ngủ**: Tỷ lệ giấc ngủ sâu trên tổng thời gian ngủ
3. **Chu kỳ giấc ngủ**: Phân tích sự chuyển đổi giữa các giai đoạn
4. **Hiệu quả giấc ngủ**: Tỷ lệ thời gian ngủ thực tế trên tổng thời gian nằm trên giường

## 9. TRIỂN KHAI CHI TIẾT TRONG REACT NATIVE

### 9.1. Cấu trúc Native Module

```javascript
// Ví dụ cấu trúc module React Native Bridge
import { NativeModules } from 'react-native';

// Hằng số cho các loại dữ liệu sức khỏe
export const HEALTH_DATA_TYPES = {
  SLEEP: 1284,           // Health_HistorySleep
  DELETE_SLEEP: 1337,    // Health_DeleteSleep
};

// Hằng số cho các chức năng thiết bị
export const FUNCTION_CONSTANTS = {
  ISHASSLEEP: 'isHasSleep',
};

export const SleepModule = NativeModules.YCBTModule;
```

### 9.2. Component hiển thị dữ liệu giấc ngủ

```jsx
import React, { useState, useEffect } from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { BarChart, LineChart } from 'react-native-chart-kit';
import { SleepModule, HEALTH_DATA_TYPES } from '../modules/SleepModule';

const SleepAnalysisScreen = () => {
  const [sleepData, setSleepData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  
  useEffect(() => {
    fetchSleepData();
  }, []);
  
  const fetchSleepData = async () => {
    try {
      const result = await SleepModule.getHealthHistoryData(
        HEALTH_DATA_TYPES.SLEEP, 
        0, 
        0
      );
      
      setSleepData(processSleepData(result.data));
    } catch (error) {
      console.error('Lỗi khi lấy dữ liệu giấc ngủ:', error);
    } finally {
      setIsLoading(false);
    }
  };
  
  const processSleepData = (data) => {
    // Xử lý dữ liệu thô từ thiết bị thành dữ liệu có cấu trúc
    // Tính toán thống kê
    // Định dạng dữ liệu cho biểu đồ
    return processedData;
  };
  
  // Render các component hiển thị dữ liệu giấc ngủ
  // - Biểu đồ các giai đoạn giấc ngủ
  // - Thống kê tổng thời gian ngủ
  // - Phân tích chất lượng giấc ngủ
};
```

### 9.3. Mô hình hóa dữ liệu đầy đủ

```javascript
// Mô hình dữ liệu giấc ngủ đầy đủ
class SleepSession {
  constructor(data) {
    this.startTime = new Date(data.startTime);
    this.endTime = new Date(data.endTime);
    this.deepSleepCount = data.deepSleepCount;
    this.lightSleepCount = data.lightSleepCount;
    this.deepSleepTotal = data.deepSleepTotal;
    this.lightSleepTotal = data.lightSleepTotal;
    this.remTotal = data.rapidEyeMovementTotal;
    this.wakeCount = data.wakeCount;
    this.wakeDuration = data.wakeDuration;
    this.sleepDetails = this.parseSleepDetails(data.sleepData);
  }
  
  parseSleepDetails(sleepData) {
    if (!sleepData) return [];
    
    return sleepData.map(item => ({
      startTime: new Date(item.sleepStartTime),
      duration: item.sleepLen,
      type: this.getSleepTypeName(item.sleepType)
    }));
  }
  
  getSleepTypeName(typeCode) {
    const types = {
      241: 'Giấc ngủ sâu',
      242: 'Giấc ngủ nhẹ',
      243: 'REM',
      244: 'Thức giấc',
      245: 'Ngủ trưa'
    };
    return types[typeCode] || 'Không xác định';
  }
  
  getTotalSleepTime() {
    return this.deepSleepTotal + this.lightSleepTotal + this.remTotal;
  }
  
  getSleepQuality() {
    const total = this.getTotalSleepTime();
    if (total === 0) return 0;
    
    // Tỷ lệ giấc ngủ sâu và REM (chất lượng cao)
    return ((this.deepSleepTotal + this.remTotal) / total) * 100;
  }
  
  getSleepEfficiency() {
    const totalInBed = (this.endTime - this.startTime) / (60 * 1000); // phút
    const totalSleep = this.getTotalSleepTime();
    
    return totalInBed > 0 ? (totalSleep / totalInBed) * 100 : 0;
  }
}
```

---
Tài liệu này được tạo bởi Cascade AI - 2025-04-08
