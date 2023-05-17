package com.octa.jynisa.multilang;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;  


public class octashell {  
	

    public static void main(String args[]) throws IOException { 
    	String[] as=new String[]{args[1]};
    	String rs=exec(args[0],as,"release");
        System.out.println(rs);  
    }
    
    /*
     * p1: 要执行的资源文件
     * p*: 参数列表
     */
    public static String exec(String py,String args[],String flag) throws IOException{
        Process process = null;  
        List<String> processList = new ArrayList<String>();  
        Resource res = new Resource();
        String configfile;
        //从资源文件读取内容，写到临时本地文件中
        String ppy=res.Write2File(py);
        if("debug".equals(flag)){
        	configfile=res.Write2File(args[0]);
        }else{
        	configfile=args[0];
        }
        
        //构建执行语句
        String exec="python3 "+ppy+" "+configfile;
        System.out.println(exec);  
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