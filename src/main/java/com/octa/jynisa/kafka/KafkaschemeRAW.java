package com.octa.jynisa.kafka;


/*

import backtype.storm.spout.MultiScheme;
import backtype.storm.tuple.Fields;
import static backtype.storm.utils.Utils.tuple;
import static java.util.Arrays.asList;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.util.List;

import com.octa.jynisa.util.HDFSAuditParser;


public class kafkaschemeRAW implements MultiScheme {
  @Override
  public Iterable<List<Object>> deserialize(byte[] ser) {
      try {
    	  //HDFSAuditParser parser=new HDFSAuditParser();
          String msg = getString(ser);
          //System.out.println(msg);
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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.util.List;


import org.apache.storm.spout.Scheme;
import org.apache.storm.tuple.Fields;
import org.apache.storm.tuple.Values;

import com.octa.jynisa.util.HDFSAuditParser;



public class KafkaschemeRAW implements Scheme {

    public Fields getOutputFields() {
        return new Fields("msg");
    }

    public List<Object> deserialize(ByteBuffer ser) {
        try {
            HDFSAuditParser parser=new HDFSAuditParser();
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