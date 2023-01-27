# JNDI-Injection-Bypass-Plus
JNDI Injection Bypass tools （working）
## beginning



idea come from JNDI-Injection-Bypass-master https://github.com/huy4ng/JNDI-Injection-Bypass



I have added and refined the payload on this basis. The original code has been kept highly customisable and refactored to my understanding



灵感源于JNDI-Injection-Bypass-master https://github.com/huy4ng/JNDI-Injection-Bypass

我在此基础上进行了payload的增加和完善。同时保留了原代码高度可自定义化的特点，并根据自己的理解重构了代码



## using

Some payloads of JNDI Injection in JDK 1.8.0_341



支持的jndi高版本注入攻击有

```
javax.el.ELProcessor#eval
snakeYaml
groovy.lang.GroovyShell#evaluate
javax.management.loading.MLet      用于探测payload
groovy.lang.GroovyClassLoader
com.thoughtworks.xstream.XStream
org.mvel2.sh.ShellSession#exec
com.sun.glass.utils.NativeLibLoader 
org.apache.catalina.users.MemoryUserDatabaseFactory导致的xxe
```



参考：https://tttang.com/archive/1405



攻击代码在attack.JndiInjectionPayload , JNDI_Test 可以提供测试

