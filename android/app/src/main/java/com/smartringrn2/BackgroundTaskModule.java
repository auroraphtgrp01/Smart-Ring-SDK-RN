package com.smartringrn2;

import android.content.Intent;
import android.os.Build;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

public class BackgroundTaskModule extends ReactContextBaseJavaModule {
    private final ReactApplicationContext reactContext;

    public BackgroundTaskModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @Override
    public String getName() {
        return "BackgroundTaskModule";
    }

    @ReactMethod
    public void startBackgroundTask() {
        Intent serviceIntent = new Intent(reactContext, BluetoothForegroundService.class);
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            reactContext.startForegroundService(serviceIntent);
        } else {
            reactContext.startService(serviceIntent);
        }
    }

    @ReactMethod
    public void stopBackgroundTask() {
        Intent serviceIntent = new Intent(reactContext, BluetoothForegroundService.class);
        reactContext.stopService(serviceIntent);
    }
}
