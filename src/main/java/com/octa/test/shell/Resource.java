package com.octa.test.shell;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.CharBuffer;  

public class Resource {  
    public String getResource(String p) throws IOException{    
        //查找指定资源的URL，其中res.txt仍然开始的bin目录下   
        URL fileURL=this.getClass().getResource(p);   
        return fileURL.getFile();  
    }  
    
    public String Write2File(String p) throws IOException{
        InputStream is=this.getClass().getResourceAsStream(p);   
        BufferedReader br=new BufferedReader(new InputStreamReader(is));   
        FileWriter fileWritter = new FileWriter("/tmp/octashell.py");//,true);
        BufferedWriter bufferWritter = new BufferedWriter(fileWritter);		
        String s="";  
        while((s=br.readLine())!=null){
            bufferWritter.write(s.toCharArray());
            bufferWritter.newLine();
        }
        bufferWritter.close();
        return "/tmp/octashell.py";
    }  

    public static void main(String[] args) throws IOException {  
        Resource res=new Resource();  
        String p=res.getResource(args[0]);
        System.out.println(p);
        System.out.println(res.Write2File(args[0]));
    }  
}  