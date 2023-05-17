package com.octa.jynisa.multilang;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.Random;

import com.octa.jynisa.util.octafile;

public class Resource {  
	private static String proot="/tmp";
	private static String resname="";
	public Resource(){	
		if (this.resname.equals("")){
			String name="OCTA-"+this.getRandomString(10);
			this.resname=this.proot+'/'+name;
			//octafile.createDir(this.resname);
		}
	}
	//创建资源管理类，修改默认存储路径
	public Resource(String proot){
		this.proot=proot;
		if (this.resname.equals("")){
			String name="OCTA-"+this.getRandomString(10);
			this.resname=this.proot+'/'+name;
			//octafile.createDir(this.resname);
		}
	}
	//返回包内资源路径
    public String getResourcePath(String p) throws IOException{    
        //查找指定资源的URL，其中res.txt仍然开始的bin目录下   
        URL fileURL=this.getClass().getResource(p);   
        return fileURL.getFile();  
    }  
    
    //多语言支持脚本应存放在资源目录下-resources
    //返回对应资源文件在本地的绝对路径
    public String Write2File(String p) throws IOException{
    	String[] dpath=this.isexistC(p);
    	if (dpath[0].equals("OK")){
    		return dpath[1];
    	}
        InputStream is=this.getClass().getResourceAsStream(p);   
        BufferedReader br=new BufferedReader(new InputStreamReader(is));   
        FileWriter fileWritter = new FileWriter(dpath[1]);//,true);
        BufferedWriter bufferWritter = new BufferedWriter(fileWritter);		
        String s="";  
        while((s=br.readLine())!=null){
            bufferWritter.write(s.toCharArray());
            bufferWritter.newLine();
        }
        bufferWritter.close();
        return dpath[1];
    }  
    public String[] isexistC(String p){
    	//判定资源文件是否转存到本地，没有则创建对应目录并返回目录路径
    	int pi=p.indexOf('/',1);
    	String pp=p.substring(pi+1);
    	String path=this.resname+"/"+pp;
    	File f= new File(path);
    	if (f.exists()){
    		String[] rs={"OK",path};
    		return rs;
    	}
    	pi=path.lastIndexOf("/");
    	String path2=path.substring(0, pi);
    	f=new File(path2);
    	if (!f.exists()){
    		f.mkdirs();
    	}
    	String[] rs={"FAIL",path};
    	return rs;
    }
    public static String getRandomString(int length) { //length表示生成字符串的长度  
        String base = "abcdefghijklmnopqrstuvwxyz0123456789";     
        Random random = new Random();     
        StringBuffer sb = new StringBuffer();     
        for (int i = 0; i < length; i++) {     
            int number = random.nextInt(base.length());     
            sb.append(base.charAt(number));     
        }     
        return sb.toString();     
     }     

    public static void main(String[] args) throws IOException {  
        Resource res=new Resource();  
        String p=res.getResourcePath(args[0]);
        System.out.println(p);
        System.out.println(res.Write2File(args[0]));
    }  
}  