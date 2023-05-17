package com.octa.jynisa.util;

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.octa.jynisa.util.DateTimeUtil;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;


import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

/**
 * e.g. 2015-09-21 21:36:52,172 INFO FSNamesystem.audit: allowed=true   ugi=hadoop (auth:KERBEROS)     ip=/x.x.x.x   cmd=getfileinfo src=/tmp   dst=null        perm=null       proto=rpc
 */



public final class HDFSAuditParser implements Serializable{
	private final static Logger LOG = LoggerFactory.getLogger(HDFSAuditParser.class);

	public HDFSAuditParser(){
	}

	public static String parseUser(String ugi) {
		/** e.g.
		 * .1)user@APD.xyz.com
		 * .2)hadoop/123.dc1.xyz.com@xyz.com (auth:KERBEROS)
		 * .3)hadoop (auth:KERBEROS)
		 */
		int index = ugi.indexOf("/");
		if (index != -1) return ugi.substring(0, index).trim();
		index = ugi.indexOf("@");
		if (index != -1) return ugi.substring(0, index).trim();
		index = ugi.indexOf("(");
		return ugi.substring(0, index).trim();
	}

	public Map parse(String log) throws Exception{
		
		JSONParser parser = new JSONParser();
		JSONObject obj = (JSONObject) parser.parse(log);
		String date=(String) obj.get("time");
		String allowed=(String) obj.get("flag");
		String ugi=(String) obj.get("user");
		String ip=(String) obj.get("ip");
		String cmd=(String) obj.get("cmd");
		String src=(String) obj.get("src");
		String dst=(String) obj.get("dst");
		String perm=(String) obj.get("ppname");
		/*
		int index0 = log.indexOf(" ");
		index0 = log.indexOf(" ",index0+1);
		String datetime = log.substring(0, index0).trim();
		int index1 = log.indexOf("allowed=",index0); int len1 = 8;
		int index2 = log.indexOf("ugi=",index1); int len2 = 4;
		int index2_2 = log.indexOf(" ",index2);
		int index3 = log.indexOf("ip=/",index2_2); int len3 = 4;
		int index4 = log.indexOf("cmd=",index3); int len4 = 4;
		int index5 = log.indexOf("src=",index4); int len5= 4;
		int index6 = log.indexOf("dst=",index5); int len6 = 4;
		int index7 = log.indexOf("perm=",index6); int len7 = 5;
		int index7_2 = log.indexOf(" ",index7);

		String allowed = log.substring(index1 + len1, index2).trim();
		String ugi = log.substring(index2 + len2, index2_2).trim();
		String ip = log.substring(index3 + len3, index4).trim();
		String cmd = log.substring(index4 + len4, index5).trim();
		String src = log.substring(index5 + len5, index6).trim();
		String dst = log.substring(index6 + len6, index7).trim();
		String perm= (index7_2<0) ? (log.substring(index7 + len7).trim()) : (log.substring(index7 + len7,index7_2).trim());
		*/
		Map<String,String> dmap = new HashMap<String, String>();
		
		dmap.put("user",ugi);
		dmap.put("cmd", cmd);
		dmap.put("src", src);
		dmap.put("dst", dst);
		dmap.put("ip", ip);
		dmap.put("ppname", perm);
		dmap.put("flag", allowed);
		dmap.put("time",date);
		//dmap.put("time",DateTimeUtil.humanDateToMilliseconds(date));
		//System.out.println(dmap);
		return dmap;
	}
}