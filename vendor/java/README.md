# Java loader

`deobf/*.java` are the self-running JAR stubs. Protect embeds the precompiled
`.class` files; `javac` is not required at protect time.

Stubs under `stubs/` exist only so the loaders compile against Fabric / Forge /
Bukkit APIs. They are **not** packed into protected JARs.

Recompile (Java 8 bytecode):

```
javac --release 8 -cp stubs -sourcepath . -d out deobf/Loader.java deobf/Boot.java deobf/ForgeService.java deobf/BukkitPlugin.java
cp out/deobf/*.class deobf/
```

Equivalent: `javac -source 8 -target 8` with a Java 8 bootclasspath. Commit both
the `.java` and the `deobf/*.class` files (never stub packages).
