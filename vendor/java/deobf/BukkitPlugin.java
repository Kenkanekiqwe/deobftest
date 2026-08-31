package deobf;

import org.bukkit.plugin.java.JavaPlugin;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.logging.Level;

/**
 * Bukkit/Paper/Bungee main-class proxy. Decrypts the payload, then forwards
 * lifecycle to the original plugin class when it can be constructed.
 */
public final class BukkitPlugin extends JavaPlugin {
    private JavaPlugin delegate;

    public void onLoad() {
        try {
            Loader.install();
            inject(getClass().getClassLoader());
            delegate = instantiateOriginal();
            if (delegate != null) {
                delegate.onLoad();
            }
        } catch (Throwable t) {
            getLogger().log(Level.SEVERE, "DEOBF failed to load the original plugin", t);
        }
    }

    public void onEnable() {
        if (delegate != null) {
            delegate.onEnable();
        }
    }

    public void onDisable() {
        if (delegate != null) {
            delegate.onDisable();
        }
    }

    private static void inject(ClassLoader cl) {
        Path classes = Loader.classesOnlyJar();
        Path full = Loader.decryptedJar();
        Loader.addToLoader(cl, classes);
        Loader.addToLoader(cl, full);
    }

    private JavaPlugin instantiateOriginal() {
        String name = Loader.originalPluginMain();
        if (name == null || name.length() == 0) {
            name = Loader.originalMainClass();
        }
        if (name == null || name.length() == 0) {
            return null;
        }
        try {
            Class<?> cls = Class.forName(name, true, getClass().getClassLoader());
            Object inst = null;
            try {
                Constructor<?> c = cls.getDeclaredConstructor();
                c.setAccessible(true);
                inst = c.newInstance();
            } catch (Throwable ignored) {
            }
            if (inst instanceof JavaPlugin) {
                return (JavaPlugin) inst;
            }
        } catch (Throwable t) {
            getLogger().log(Level.WARNING, "Could not construct original plugin " + name, t);
        }
        return null;
    }
}
