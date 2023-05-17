package com.octa.test.shell;

/**
 * * @Author jack
 * * @Create Date 2022/1/12 15:20
 * * @Version 1.0
 */

import org.apache.storm.task.TopologyContext;
import org.apache.storm.topology.BasicOutputCollector;
import org.apache.storm.topology.OutputFieldsDeclarer;
import org.apache.storm.topology.base.BaseBasicBolt;
import org.apache.storm.tuple.Fields;
import org.apache.storm.tuple.Tuple;
import org.apache.storm.tuple.Values;

import java.io.FileWriter;
import java.io.IOException;
import java.util.Map;

public class WriterBolt extends BaseBasicBolt {

    private FileWriter writer = null;

    @Override
    public void prepare(Map stormConf, TopologyContext context) {
        try {
            // /tmp/sysnisa/kafkainfo.txt   c:/kafkainfo.txt
            writer = new FileWriter("/tmp/kafkainfo.txt");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }



    @Override
    public void declareOutputFields(OutputFieldsDeclarer declarer) {

        declarer.declare(new Fields("cmd"));
    }


    @Override
    public void execute(Tuple input, BasicOutputCollector collector) {

//        System.out.println("-- tuple1 --: " + input);

//        String s = input.getString(0);
        String value = input.getString(0);
//        System.out.println("-- value1 --: "+value);

//        Logger.getLogger(value);

        try {
            writer.write(value);
            writer.write("\n");
            writer.flush();

//            Logger.getLogger(value);


        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        //发射到下一个bolt
        collector.emit(new Values(value));  //input.getValues()


    }
}

