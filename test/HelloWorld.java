public class HelloWorld
{
    public native void SayHello(String name);

    static
    {
        System.loadLibrary("dll");
    }

    public static void main(String [] argv)
    {
        HelloWorld hello = new HelloWorld();
        hello.SayHello("myName");
    }
}
