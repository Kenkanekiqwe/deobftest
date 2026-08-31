# Java loader

`deobf/Loader.java` is the self-running JAR stub. Protect embeds the precompiled `Loader.class`; `javac` is not required at protect time.

Recompile (Java 8 bytecode):

```
javac --release 8 deobf/Loader.java
```

Commit both the `.java` and `.class`.
