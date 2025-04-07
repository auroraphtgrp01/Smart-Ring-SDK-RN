import { NativeModules, Platform } from 'react-native';

// Define an interface for our native module
interface BackgroundTaskInterface {
  startBackgroundTask: () => void;
  stopBackgroundTask: () => void;
}

// Create a default implementation that does nothing for iOS or when native module is not available
const defaultImplementation: BackgroundTaskInterface = {
  startBackgroundTask: () => console.log('Background task not supported on this platform'),
  stopBackgroundTask: () => console.log('Background task not supported on this platform'),
};

// Get the native module if available
const nativeModule = Platform.OS === 'android' 
  ? NativeModules.BackgroundTaskModule as BackgroundTaskInterface | undefined 
  : undefined;

// Export the module or the default implementation
export const BackgroundTaskService = nativeModule || defaultImplementation;

// Function to start the background service
export const startBackgroundService = () => {
  try {
    if (Platform.OS === 'android') {
      console.log('Starting background service...');
      BackgroundTaskService.startBackgroundTask();
      return true;
    }
    return false;
  } catch (error) {
    console.error('Error starting background service:', error);
    return false;
  }
};

// Function to stop the background service
export const stopBackgroundService = () => {
  try {
    if (Platform.OS === 'android') {
      console.log('Stopping background service...');
      BackgroundTaskService.stopBackgroundTask();
      return true;
    }
    return false;
  } catch (error) {
    console.error('Error stopping background service:', error);
    return false;
  }
};
