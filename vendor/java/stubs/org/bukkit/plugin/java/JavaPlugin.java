package org.bukkit.plugin.java;

import java.util.logging.Logger;

/** Compile-time stub. Not packed into protected JARs. */
public abstract class JavaPlugin {
    public void onLoad() {
    }

    public void onEnable() {
    }

    public void onDisable() {
    }

    public Logger getLogger() {
        return Logger.getLogger("deobf");
    }
}
