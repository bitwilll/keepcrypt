// Only the app's own camera/GoAheadScanner.kt may use the camera; a src/test below src/main ships.
val cameras = context.getSystemService(CameraManager::class.java)
