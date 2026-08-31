package deobf;

import cpw.mods.modlauncher.api.IEnvironment;
import cpw.mods.modlauncher.api.IModuleLayerManager;
import cpw.mods.modlauncher.api.ITransformationService;
import cpw.mods.modlauncher.api.IncompatibleEnvironmentException;

import java.lang.reflect.Constructor;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Forge/NeoForge transformation service. Decrypts before the game layer
 * scan so the original classes are visible. Transformers stay empty.
 */
public final class ForgeService implements ITransformationService {
    public String name() {
        return "deobf";
    }

    public void initialize(IEnvironment environment) {
        Loader.install();
    }

    public void beginScanning(IEnvironment environment) {
        Loader.install();
    }

    public void onLoad(IEnvironment env, Set otherServices) throws IncompatibleEnvironmentException {
    }

    public List transformers() {
        return Collections.emptyList();
    }

    /**
     * Newer ModLauncher. Older runtimes ignore this extra method.
     * Returns the classes-only jar on the GAME layer when the Resource/SecureJar
     * types are present.
     */
    public List completeScan(IModuleLayerManager layerManager) {
        Loader.install();
        Path classes = Loader.classesOnlyJar();
        if (classes == null) {
            return Collections.emptyList();
        }
        try {
            return extraGameResources(classes);
        } catch (Throwable ignored) {
            return Collections.emptyList();
        }
    }

    private static List extraGameResources(Path classes) throws Exception {
        Class<?> layerCl;
        try {
            layerCl = Class.forName("cpw.mods.modlauncher.api.IModuleLayerManager$Layer");
        } catch (ClassNotFoundException e) {
            return Collections.emptyList();
        }
        Object game = Enum.valueOf(layerCl.asSubclass(Enum.class), "GAME");

        Object resourcePayload = classes;
        try {
            Class<?> sj = Class.forName("cpw.mods.jarhandling.SecureJar");
            java.lang.reflect.Method from = null;
            try {
                from = sj.getMethod("from", Path.class);
            } catch (NoSuchMethodException ignored) {
            }
            if (from == null) {
                try {
                    from = sj.getMethod("from", Path[].class);
                    resourcePayload = from.invoke(null, (Object) new Path[] { classes });
                } catch (NoSuchMethodException ignored) {
                }
            } else {
                resourcePayload = from.invoke(null, classes);
            }
        } catch (ClassNotFoundException ignored) {
        }

        Class<?> resourceCl = Class.forName("cpw.mods.modlauncher.api.ITransformationService$Resource");
        Object list = Collections.singletonList(resourcePayload);
        Constructor<?> ctor = null;
        Constructor<?>[] ctors = resourceCl.getConstructors();
        for (int i = 0; i < ctors.length; i++) {
            Class<?>[] p = ctors[i].getParameterTypes();
            if (p.length == 2) {
                ctor = ctors[i];
                break;
            }
        }
        if (ctor == null) {
            return Collections.emptyList();
        }
        Object resource = ctor.newInstance(game, list);
        List out = new ArrayList();
        out.add(resource);
        return out;
    }
}
