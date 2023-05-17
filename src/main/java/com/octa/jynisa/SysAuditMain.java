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
import java.util.Map;

import com.TriasKafkaSpout;
//import com.octa.test.shell.WriterBolt;
import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.storm.Config;
import org.apache.storm.LocalCluster;
import org.apache.storm.StormSubmitter;
import org.apache.storm.kafka.spout.ByTopicRecordTranslator;
import org.apache.storm.kafka.spout.FirstPollOffsetStrategy;
import org.apache.storm.kafka.spout.KafkaSpout;
import org.apache.storm.kafka.spout.KafkaSpoutConfig;
import org.apache.storm.kafka.spout.internal.ConsumerFactoryDefault;
import org.apache.storm.kafka.spout.subscription.TopicAssigner;
import org.apache.storm.task.ShellBolt;
import org.apache.storm.topology.IRichBolt;
import org.apache.storm.topology.OutputFieldsDeclarer;
import org.apache.storm.topology.TopologyBuilder;
import org.apache.storm.tuple.Fields;
import org.apache.storm.tuple.Values;
import org.apache.storm.utils.Utils;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;


import com.octa.jynisa.multilang.octashell;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *  import  backtype.storm 和import org.apache.storm的原因是因为1.0开始，
 *  storm 全部的包名换掉了， backtype.storm ---> org.apache.storm
 */
public class SysAuditMain {
	private static final Logger LOG = LoggerFactory.getLogger(SysAuditMain.class);

	public static void main(String[] args) throws Exception {
		LOG.info("");
		if(args.length == 3){
			System.out.println("Start parsing the pass parameters： \n");

		}else {
			System.out.println("Error in passing parameters!");
			System.out.println("Execution mode：");
			System.out.println("strom jar ${topologyName} ${SysAudit_topology.json} ${JySysAudit_detection.ini}");
			System.exit(1);
		}
		JSONParser parser = new JSONParser();
		Object obj;
		obj = parser.parse(new FileReader(args[1]));
		JSONObject jsonObject = (JSONObject) obj;
		JSONObject serverConfig = (JSONObject) jsonObject.get("serverConfig");
		JSONObject bolthreads = (JSONObject) jsonObject.get("bolthreads");
		JSONObject kafkaOffset = (JSONObject) jsonObject.get("kafkaOffset");
		JSONObject topoConfigs = (JSONObject) jsonObject.get("topoConfig");
		JSONObject pythonEnv = (JSONObject) jsonObject.get("pythonEnv");
		JSONObject kafkaLogin = (JSONObject) jsonObject.get("kafkaLogin");
        //kafka认证模式
		String kafkaLoginMode = (String) kafkaLogin.get("kafkaLoginMode");
		//kafka 光大环境 Krb5 认证
		JSONObject kafkaClientKrb5 = (JSONObject) jsonObject.get("kafkaClientKrb5");
		//kafka  PlainLoginModule 认证 之前的
		JSONObject kafkaClient = (JSONObject) jsonObject.get("kafkaClient");
		String mechanism = (String) kafkaLogin.get("mechanism");
		String protocol = (String) kafkaLogin.get("protocol");




		// 从json配置文件中读取相关kafka配置信息
		String topic = (String) serverConfig.get("topic");
		String bootstrapServers = (String) serverConfig.get("bootstrapServers");
		String groupId = (String) serverConfig.get("groupId");

		// 获取Python环境变量路径
	     String pythonPath = (String) pythonEnv.get("pythonPath");

		// bolt 进程数配置信息
		int gfb = ((Long) bolthreads.get("getfieldbolt")).intValue();
		int dfb = ((Long) bolthreads.get("dupfilterbolt")).intValue();
		int smb = ((Long) bolthreads.get("servicemodelbolt")).intValue();
		int hsb = ((Long) bolthreads.get("heuristicbolt")).intValue();
		int dtb = ((Long) bolthreads.get("detectionbolt")).intValue();
		int alb = ((Long) bolthreads.get("alertbolt")).intValue();

		// 是否从0开始，新版本可能不再使用  TODO 测试新版本
//		int startZero = ((Long) zkconfig.get("startZero")).intValue();

		// PlainLoginModule 认证
		String saslSecurity, saslUsername, saslPassword, saslConf = "";
		String security, useKeyTab, storekey, serviceName,keyTab,principal;

        System.out.println("kafkaLoginMode:"+kafkaLoginMode);

		if (kafkaLoginMode.equals("Krb5")) {
			// TODO krb5认证
			System.setProperty("java.security.krb5.conf", (String) kafkaClientKrb5.get("krb5Conf"));
			System.setProperty("java.security.auth.login.config",(String) kafkaClientKrb5.get("loginConfig"));
			//System.setProperty("javax.security.auth.useSubjectCredsOnly","false");

			security = (String) kafkaClientKrb5.get("security");
			useKeyTab = (String) kafkaClientKrb5.get("useKeyTab");
			storekey = (String) kafkaClientKrb5.get("storekey");
			serviceName = (String) kafkaClientKrb5.get("serviceName");
			keyTab = (String) kafkaClientKrb5.get("keyTab");
			principal = (String) kafkaClientKrb5.get("principal");

			saslConf = String.format("%s required useKeyTab = \"%s\" storekey = \"%s\" serviceName = \"%s\" keyTab = \"%s\" principal = \"%s\";"
					,security,useKeyTab,storekey,serviceName,keyTab,principal);

			String saslConf1 ="com.sun.security.auth.module.Krb5LoginModule required useKeyTab=\"true\" " +
					"storekey=\"true\" " +
					"serviceName=\"kafka\" " +
					"keyTab=\"/data/storm4.3-topology/csmp.keytab\" " +
					"principal=\"csmpaCDPCEBBANK.COM;\"";
			System.out.println("saslConf is on and the config is " + saslConf);

		}else if(kafkaLoginMode.equals("Plain")){
			// TODO Plain认证
			saslSecurity = (String)kafkaClient.get("security");
			saslUsername = (String)kafkaClient.get("username");
			saslPassword = (String)kafkaClient.get("password");
			saslConf = String.format("%s required username=\"%s\" password=\"%s\";",saslSecurity,saslUsername,saslPassword);
		}
		System.out.println("saslConf is on and the config is " + saslConf);



		// 配置文件 JySysAudit_detection.ini 转json数组
		String config;
		String[] as ;
		if (args != null && args.length > 2) {
			// config=args[2];
			as = new String[] { args[2] };

			File file = new File(args[2]);
			if (!file.exists()) {
				// config="sysaudit/conf/detection.ini";
				System.out.println("Invalid detection config file,check and again!");
				System.exit(1);
			}
			config = octashell.exec("/resources/parseconf.py", as, "release");
		} else {
			// config="sysaudit/conf/detection.ini";
			as = new String[] { "/resources/sysaudit/conf/JySysAudit_detection.ini" };
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


		KafkaSpoutConfig<String,String> ksc ;
		if (kafkaLoginMode.equals("Krb5")){
			ksc = KafkaSpoutConfig
					//bootstrapServers 以及topic
					.builder(bootstrapServers, topic)
					//设置group.id
					.setProp(ConsumerConfig.GROUP_ID_CONFIG, groupId)
					//设置开始消费的超始位置
					.setFirstPollOffsetStrategy(FirstPollOffsetStrategy.LATEST)
					//设置提交消费边界的时长间隔
					.setOffsetCommitPeriodMs(20_000)
					//Translator
					.setRecordTranslator(brt)
					.setProp("security.protocol","SASL_PLAINTEXT")
					.setProp("sasl.kerberos.service.name","kafka")
					.setProp("sasl.mechanism","GSSAPI")
					.setProp(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class)
					.setProp(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class)
					.setProp(SaslConfigs.SASL_JAAS_CONFIG,saslConf)
					.build();

		} else if (kafkaLoginMode.equals("Plain")) {
			ksc = KafkaSpoutConfig
					//bootstrapServers 以及topic
					.builder(bootstrapServers, topic)
					//设置group.id
					.setProp(ConsumerConfig.GROUP_ID_CONFIG, groupId)
					//设置开始消费的超始位置
					.setFirstPollOffsetStrategy(FirstPollOffsetStrategy.LATEST)
					//设置提交消费边界的时长间隔
					.setOffsetCommitPeriodMs(20_000)
					//Translator
					.setRecordTranslator(brt)
					.setProp(SaslConfigs.SASL_JAAS_CONFIG,saslConf)
					.setProp(SaslConfigs.SASL_MECHANISM, "PLAIN")
					.setProp(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SASL_PLAINTEXT")
					.build();
		} else {
			// kafka没有加密
			ksc = KafkaSpoutConfig
					//bootstrapServers 以及topic
					.builder(bootstrapServers, topic)
					//设置group.id
					.setProp(ConsumerConfig.GROUP_ID_CONFIG, groupId)
					//设置开始消费的超始位置
					.setFirstPollOffsetStrategy(FirstPollOffsetStrategy.LATEST)
					//设置提交消费边界的时长间隔
					//设置提交offset周期,设置 spout 多久向 Kafka commit一次
					.setOffsetCommitPeriodMs(20_000)
					//Translator
					.setRecordTranslator(brt)
					.build();
		}

		Config topoConfig = new Config();

		int numWorkers = ((Long) topoConfigs.get("numWorkers")).intValue();
		int numAckers = ((Long)topoConfigs.get("numAckers")).intValue();
		int spoutNumbers = ((Long)topoConfigs.get("spoutNumbers")).intValue();

        // 设置消息超时时间，默认消息超时时间（30秒）
		topoConfig.put(Config.TOPOLOGY_MESSAGE_TIMEOUT_SECS,60);
		/**
		 * 下游的 bolt 还有 TOPOLOGY_MAX_SPOUT_PENDING 个 tuple没有消费完时，
		 * spout 会停下来等待，该配置作用于 spout 的每个 task。
		 * */
		topoConfig.put(Config.TOPOLOGY_MAX_SPOUT_PENDING, 10000);
		topoConfig.put(Config.TOPOLOGY_SUBPROCESS_TIMEOUT_SECS,600);
		topoConfig.setNumWorkers(numWorkers);  // worker进程数量
		//把执行acker的executor关掉
		topoConfig.setNumAckers(numAckers);
		topoConfig.setMaxSpoutPending(5000);
		ConsumerFactoryDefault<String,String> cf = new ConsumerFactoryDefault<String,String>();
        TopicAssigner ta = new TopicAssigner();

		// 光大资源配置特殊处理，故意跳过部分tuple，如果配置为5，那么只保留5分之1到消费端，跳过5分之4
		// 如果不跳过配置为1
			int skipPercent = ((Long)kafkaOffset.get("skipPercent")).intValue();
		System.out.println("the skipPercent value is "+ skipPercent);
		if (skipPercent ==0 ){
		    skipPercent = 12;
            System.out.println("main: get skipPercent from config value is 0,so change to 12");
        }
		TriasKafkaSpout tks =  new TriasKafkaSpout<String,String>(ksc,cf,ta);
		tks.setSkipPercent(skipPercent);



/*         // gfb是进程的数量  setNumTasks 是线程的数量
		builder.setBolt("WriterBolt", new WriterBolt(),gfb).setNumTasks(numWorkers)
				.shuffleGrouping("spout");*/
		builder.setSpout("spout", tks, spoutNumbers).setNumTasks(spoutNumbers*8);
		builder.setBolt("GetFieldBolt", new GetFieldBolt(config), gfb).shuffleGrouping("spout"); // host,vmap

		// 指定前向bolt，并指定以“host”进行数据分组接收
		builder.setBolt("DupfilterBolt", new DupfilterBolt(config), dfb).shuffleGrouping("GetFieldBolt"); // host,vmap
		builder.setBolt("HeuristicBolt", new HeuristicBolt(config), hsb)
				.setNumTasks(hsb*8)
				.fieldsGrouping("DupfilterBolt",
				new Fields("host")); // user,vmap
		builder.setBolt("ServiceModelBolt", new ServiceModelBolt(config), smb).fieldsGrouping("HeuristicBolt",
				new Fields("user")); // user,vmap
		builder.setBolt("DetectionBolt", new DetectionBolt(config), dtb)
				.setNumTasks(dtb*8)
				.fieldsGrouping("ServiceModelBolt",
				new Fields("user")); // user,vmap
		builder.setBolt("AlertBolt", new AlertBolt(config), alb).shuffleGrouping("DetectionBolt");

		if (args != null && args.length > 0 ) {
			// 提交到集群运行
			try {
			    // && args.length==4
				StormSubmitter.submitTopology(args[0], topoConfig, builder.createTopology());
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else {
			// 本地模式运行
			LocalCluster cluster = new LocalCluster();
			cluster.submitTopology("JyNisaLocal", topoConfig, builder.createTopology());
			Utils.sleep(1000000);
			// cluster.killTopology("JyNisaLocal");
			// cluster.shutdown();
		}
	}




	// Bolt implementation
	public static class GetFieldBolt extends ShellBolt implements IRichBolt {

		public GetFieldBolt(String conf) {
			super("python3", "sysaudit/getfield.pyc", conf);
		}

		@Override
		public void declareOutputFields(OutputFieldsDeclarer declarer) {
			declarer.declare(new Fields("host", "vmap"));
		}

		@Override
		public Map<String, Object> getComponentConfiguration() {
			return null;
		}
	}

	public static class DupfilterBolt extends ShellBolt implements IRichBolt {

		public DupfilterBolt(String conf) {
			super("python3", "sysaudit/dupfilter.pyc", conf);
		}

		@Override
		public void declareOutputFields(OutputFieldsDeclarer declarer) {
			declarer.declare(new Fields("host", "vmap"));
		}

		@Override
		public Map<String, Object> getComponentConfiguration() {
			return null;
		}
	}

	public static class ServiceModelBolt extends ShellBolt implements IRichBolt {

		public ServiceModelBolt(String conf) {
			super("python3", "sysaudit/servicemodel.pyc", conf);
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

	public static class HeuristicBolt extends ShellBolt implements IRichBolt {

		public HeuristicBolt(String conf) {
			super("python3", "sysaudit/heuristic.pyc", conf);
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

	public static class DetectionBolt extends ShellBolt implements IRichBolt {

		public DetectionBolt(String conf) {
			super("python3", "sysaudit/detection.pyc", conf);
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
			super("python3", "sysaudit/eaglealert.pyc", conf);
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

}
