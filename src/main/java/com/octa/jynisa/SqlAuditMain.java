/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.octa.jynisa;

import java.io.File;
import java.io.FileReader;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.storm.Config;
import org.apache.storm.LocalCluster;
import org.apache.storm.StormSubmitter;
import org.apache.storm.generated.AlreadyAliveException;
import org.apache.storm.generated.InvalidTopologyException;
import org.apache.storm.kafka.spout.ByTopicRecordTranslator;
import org.apache.storm.kafka.spout.FirstPollOffsetStrategy;
import org.apache.storm.kafka.spout.KafkaSpoutConfig;
import org.apache.storm.spout.SchemeAsMultiScheme;
import org.apache.storm.task.ShellBolt;
import org.apache.storm.topology.IRichBolt;
import org.apache.storm.topology.OutputFieldsDeclarer;
import org.apache.storm.topology.TopologyBuilder;
import org.apache.storm.tuple.Fields;

import org.apache.storm.tuple.Values;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.octa.jynisa.kafka.KafkaschemeRAW;
import com.octa.jynisa.multilang.octashell;


public class SqlAuditMain {

	// Bolt implementation
	public static class GetFieldBolt extends ShellBolt implements IRichBolt {

		public GetFieldBolt(String conf) {
			super("python3", "sqlaudit/getfield.pyc", conf);
		}

		@Override
		public void declareOutputFields(OutputFieldsDeclarer declarer) {
			declarer.declare(new Fields("table", "vmap"));
		}

		@Override
		public Map<String, Object> getComponentConfiguration() {
			return null;
		}
	}

	public static class DupfilterBolt extends ShellBolt implements IRichBolt {

		public DupfilterBolt(String conf) {
			super("python3", "sqlaudit/dupfilter.pyc", conf);
		}

		@Override
		public void declareOutputFields(OutputFieldsDeclarer declarer) {
			declarer.declare(new Fields("table", "vmap"));
		}

		@Override
		public Map<String, Object> getComponentConfiguration() {
			return null;
		}
	}

	public static class TableModelBolt extends ShellBolt implements IRichBolt {

		public TableModelBolt(String conf) {
			super("python3", "sqlaudit/tablemodel.pyc", conf);
		}

		@Override
		public void declareOutputFields(OutputFieldsDeclarer declarer) {
			declarer.declare(new Fields("user", "vmap"));
		}

		@Override
		public Map<String, Object> getComponentConfiguration() {
			return null;
		}
	}
	/*
	 * public static class HeuristicBolt extends ShellBolt implements IRichBolt {
	 * 
	 * public HeuristicBolt(String conf) { super("python2",
	 * "sqlaudit/heuristic.pyc",conf); }
	 * 
	 * @Override public void declareOutputFields(OutputFieldsDeclarer declarer) {
	 * declarer.declare(new Fields("user","vmap")); }
	 * 
	 * @Override public Map<String, Object> getComponentConfiguration() { return
	 * null; } }
	 */

	public static class UserModelBolt extends ShellBolt implements IRichBolt {

		public UserModelBolt(String conf) {
			super("python3", "sqlaudit/detection.pyc", conf);
		}

		@Override
		public void declareOutputFields(OutputFieldsDeclarer declarer) {
			declarer.declare(new Fields("user", "alertlist"));
		}

		@Override
		public Map<String, Object> getComponentConfiguration() {
			return null;
		}
	}

	public static class AlertBolt extends ShellBolt implements IRichBolt {

		public AlertBolt(String conf) {
			super("python3", "sqlaudit/eaglealert.pyc", conf);
		}

		@Override
		public void declareOutputFields(OutputFieldsDeclarer declarer) {
			declarer.declare(new Fields("user", "data"));
		}

		@Override
		public Map<String, Object> getComponentConfiguration() {
			return null;
		}
	}

	public static void main(String[] args) throws Exception {
		JSONParser parser = new JSONParser();
		Object obj;
		if (args != null && args.length > 1) {
			obj = parser.parse(new FileReader(args[1]));
		} else {
			obj = parser.parse(new FileReader("src/main/resources/SqlAudit_topology.json"));
		}
		JSONObject jsonObject = (JSONObject) obj;
		JSONObject serverConfig = (JSONObject) jsonObject.get("serverConfig");
		JSONObject bolthreads = (JSONObject) jsonObject.get("bolthreads");

		// 从json配置文件中读取相关配置信息
		String topic = (String) serverConfig.get("topic");
		String bootstrapServers = (String) serverConfig.get("bootstrapServers");
		String groupId = (String) serverConfig.get("groupId");


		int gfb = ((Long) bolthreads.get("getfieldbolt")).intValue();
		int dfb = ((Long) bolthreads.get("dupfilterbolt")).intValue();
		int tmb = ((Long) bolthreads.get("tablemodelbolt")).intValue();
		int umb = ((Long) bolthreads.get("usermodelbolt")).intValue();
		int alb = ((Long) bolthreads.get("alertbolt")).intValue();

		String config;
		String[] as = null;
		if (args != null && args.length > 2) {
			// config=args[2];
			as = new String[] { args[2] };
			// File file=new File(config);
			File file = new File(args[2]);
			if (!file.exists()) {
				// config="sysaudit/conf/detection.ini";
				System.out.println("Invalid detection config file,check and again!");
				System.exit(1);
			}
			config = octashell.exec("/resources/parseconf.py", as, "release");
		} else {
			// config="sysaudit/conf/detection.ini";
			as = new String[] { "/resources/sqlaudit/conf/JySqlAudit_detection.ini" };
			config = octashell.exec("/resources/parseconf.py", as, "debug");
		}

		if ("FAIL".equals(config)) {
			System.out.println("Parse config fail,check and again!");
			System.exit(0);
		} else {
			System.out.println(config);
		}

		final TopologyBuilder builder = new TopologyBuilder();
		//该类将传入的kafka记录转换为storm的tuple
		ByTopicRecordTranslator<String,String> brt =
				new ByTopicRecordTranslator<>( (r) -> new Values( r.value(),r.topic()),new Fields("values",topic));
		//设置要消费的topic
		brt.forTopic(topic, (r) -> new Values(r.value(),r.topic()), new Fields("values",topic));

		KafkaSpoutConfig<String,String> ksc = KafkaSpoutConfig
				//bootstrapServers 以及topic
				.builder(bootstrapServers, topic)
				//设置group.id
				.setProp(ConsumerConfig.GROUP_ID_CONFIG, groupId )
				//设置开始消费的气势位置
				.setFirstPollOffsetStrategy(FirstPollOffsetStrategy.LATEST)
				//设置提交消费边界的时长间隔
				.setOffsetCommitPeriodMs(10_000)
				//Translator
				.setRecordTranslator(brt)
				.build();

		builder.setBolt("GetFieldBolt", new GetFieldBolt(config), gfb).shuffleGrouping("spout");
		builder.setBolt("DupfilterBolt", new DupfilterBolt(config), dfb).fieldsGrouping("GetFieldBolt",
				new Fields("table"));
		builder.setBolt("TableModelBolt", new TableModelBolt(config), tmb).fieldsGrouping("DupfilterBolt",
				new Fields("table"));
		// builder.setBolt("HeuristicBolt", new
		// HeuristicBolt(config),hsb).fieldsGrouping("ServiceModelBolt",new
		// Fields("host"));
		builder.setBolt("UserModelBolt", new UserModelBolt(config), umb).fieldsGrouping("TableModelBolt",
				new Fields("user"));
		builder.setBolt("AlertBolt", new AlertBolt(config), alb).shuffleGrouping("UserModelBolt");


		Config topoConfig = new Config();
		topoConfig.setNumWorkers(2);
		topoConfig.setNumAckers(0);

		if (args != null && args.length > 0) {
			// 提交到集群运行
			try {
				StormSubmitter.submitTopology(args[0], topoConfig, builder.createTopology());
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else {
			// 本地模式运行
			LocalCluster cluster = new LocalCluster();
			cluster.submitTopology("JyNisaLocal", topoConfig, builder.createTopology());
			// Utils.sleep(1000000);
			// cluster.killTopology("JyNisaLocal");
			// cluster.shutdown();
		}
	}
}