import android.hardware.camera2.CameraAccessException
import android.hardware.camera2.CameraManager
import com.google.zxing.ReaderException
import java.util.concurrent.Executor
val cameras = context.getSystemService(CameraManager::class.java)
} catch (e: CameraAccessException) {
try { onGoAheadText(decodeGoAhead(luminance, width, height)) } catch (e: ReaderException) { }
val ask = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted -> scan(granted) }
val callbacks = Executor { camera.post(it) }
