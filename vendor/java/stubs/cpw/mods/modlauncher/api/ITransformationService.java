package cpw.mods.modlauncher.api;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Compile-time stub covering both older (void beginScanning) and newer
 * (completeScan) ModLauncher APIs. Not packed into protected JARs.
 */
public interface ITransformationService {
    String name();

    void initialize(IEnvironment environment);

    void onLoad(IEnvironment env, Set otherServices) throws IncompatibleEnvironmentException;

    List transformers();

    /** Older ModLauncher (1.16 / ML 8). Newer APIs use a default List-returning method. */
    void beginScanning(IEnvironment environment);
}
