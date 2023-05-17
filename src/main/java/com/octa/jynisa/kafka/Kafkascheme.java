package com.octa.jynisa.kafka;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.util.List;

//import backtype.storm.spout.Scheme;
//import backtype.storm.tuple.Fields;
//import backtype.storm.tuple.Values;

/*
import static backtype.storm.utils.Utils.tuple;
import static java.util.Arrays.asList;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.util.List;

import com.octa.jynisa.util.HDFSAuditParser;

import backtype.storm.spout.MultiScheme;
import backtype.storm.tuple.Fields;

public class kafkascheme implements MultiScheme {
  HDFSAuditParser parser=new HDFSAuditParser();
  @Override
  public Iterable<List<Object>> deserialize(byte[] ser) {
      try {
    	  
          String msg = getString(ser);
          //System.out.println(msg);
          //return asList(tuple(parser.parse(msg))); //java解析，在运行时会发生诡异的内存溢出问题，无解，现把此功能调整到python模块中
          return asList(tuple(msg));
      } catch (Exception e) {
          e.printStackTrace();
      }
      return null;
  }

  @Override
  public Fields getOutputFields() {
    return new Fields("bytes");
  }
  
  public static String getString(byte[] buffer)  
  {  
      Charset charset = null;  
      CharsetDecoder decoder = null;  
      CharBuffer charBuffer = null;  
      try  
      {  
          charset = Charset.forName("UTF-8");  
          decoder = charset.newDecoder();  
          ByteBuffer buf = ByteBuffer.wrap(buffer);
          charBuffer = decoder.decode(buf);  
          return charBuffer.toString().trim(); //返回清除了首尾空白符的字符串  
      }  
      catch (Exception ex)  
      {  
          ex.printStackTrace();  
          return "";  
      }  
  }
}
*/


import org.apache.storm.spout.Scheme;
import org.apache.storm.tuple.Fields;
import org.apache.storm.tuple.Values;


public class Kafkascheme implements Scheme {

    public Fields getOutputFields() {
        return new Fields("msg");
    }

	public List<Object> deserialize(ByteBuffer ser) {
        try {
        	//System.out.println("have a log");
        	//HDFSAuditParser parser=new HDFSAuditParser();
            String msg = getString(ser);
            //System.out.println(msg);
            //return new Values(parser.parse(msg));
            return new Values(msg);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
	}

    public static String getString(ByteBuffer buffer)  
    {  
        Charset charset = null;  
        CharsetDecoder decoder = null;  
        CharBuffer charBuffer = null;  
        try  
        {  
            charset = Charset.forName("UTF-8");  
            decoder = charset.newDecoder();  
            // charBuffer = decoder.decode(buffer);//用这个的话，只能输出来一次结果，第二次显示为空  
            charBuffer = decoder.decode(buffer.asReadOnlyBuffer());  
            return charBuffer.toString().trim(); //返回清除了首尾空白符的字符串  
        }  
        catch (Exception ex)  
        {  
            ex.printStackTrace();  
            return "";  
        }  
    }
    
	public List<Object> deserialize(byte[] ser) {
		// TODO Auto-generated method stub
		return null;
	}  
}