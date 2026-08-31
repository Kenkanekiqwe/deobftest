package deobf;

import net.fabricmc.loader.api.entrypoint.PreLaunchEntrypoint;

/**
 * Fabric (and Quilt-via-Fabric-entrypoint) preLaunch hook. Decrypts the
 * wrapped payload and injects classes before mixin/mod init.
 */
public final class Boot implements PreLaunchEntrypoint {
    static {
        try {
            Loader.install();
        } catch (Throwable ignored) {
        }
    }

    public Boot() {
    }

    public void onPreLaunch() {
        Loader.install();
        Loader.registerMixins();
    }
}
