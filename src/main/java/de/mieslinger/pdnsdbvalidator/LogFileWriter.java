/*
 $Id: LogFileWriter.java 5409 2014-07-22 14:45:22Z mieslingert $
 */
package de.mieslinger.pdnsdbvalidator;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 *
 * @author mieslingert
 */
public class LogFileWriter implements Runnable {

    private volatile boolean keepOnRunning = true;

    private ConcurrentLinkedQueue<String> logFileQ;
    private PrintWriter out;

    private LogFileWriter() {
    }

    public LogFileWriter(ConcurrentLinkedQueue<String> logFileQ, String logfile) throws IOException {
        this.logFileQ = logFileQ;
        FileWriter fstream = new FileWriter(logfile);
        this.out = new PrintWriter(fstream);
    }

    public void run() {
        while (keepOnRunning) {
            try {
                String logLine = logFileQ.poll();
                if (logLine != null) {
                    out.write(logLine + "\n");
                    //System.out.println("lfw: " + logLine);
                } else {
                    Thread.sleep(700);
                }
            } catch (InterruptedException e) {
            }
        }
        out.close();
    }

    public void shutdown() {
        this.keepOnRunning = false;
    }
}
