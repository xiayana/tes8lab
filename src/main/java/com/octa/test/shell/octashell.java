package com.octa.test.shell;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;  


public class octashell {  
	

    public static void main(String args[]) throws IOException {  
    	String rs=exec(args);
        System.out.println(rs);  
    }
    
    public static String exec(String args[]) throws IOException{
        Process process = null;  
        List<String> processList = new ArrayList<String>();  
        Resource res = new Resource();
        //从资源文件读取内容，写到临时本地文件中
        String ppy=res.Write2File(args[0]);
        //构建执行语句
        String exec="python "+ppy+" "+args[1];
        //System.out.println(exec);  
        try {  
            process = Runtime.getRuntime().exec(exec);  
            BufferedReader input = new BufferedReader(new InputStreamReader(process.getInputStream()));  
            String line = "";    
            while ((line = input.readLine()) != null) {  
                processList.add(line);  
            }  
            input.close();  
        } catch (IOException e) {  
            e.printStackTrace();  
        }  
        return processList.get(0);
    }
}  