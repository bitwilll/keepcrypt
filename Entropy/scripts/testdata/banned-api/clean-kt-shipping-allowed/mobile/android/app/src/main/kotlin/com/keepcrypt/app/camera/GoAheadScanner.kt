import android.hardware.camera2.CameraAccessException
import android.hardware.camera2.CameraManager
val cameras = context.getSystemService(CameraManager::class.java)
} catch (e: CameraAccessException) {
val ask = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted -> scan(granted) }
