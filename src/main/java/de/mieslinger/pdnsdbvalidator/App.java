package de.mieslinger.pdnsdbvalidator;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Updater
 *
 */
public class App {

    private final static ConcurrentLinkedQueue<Long> domainIdQ = new ConcurrentLinkedQueue<>();
    private final static ConcurrentLinkedQueue<String> logFileQ = new ConcurrentLinkedQueue<>();
    private final static ConcurrentLinkedQueue<String> criticalLogFileQ = new ConcurrentLinkedQueue<>();

    public static void main(String[] args) {
        try {
            // setup Queues und Thread Pools
            LogFileWriter logfileWriter = new LogFileWriter(logFileQ, System.getProperty("user.home") + "/pdns-db-validator.log");
            Thread tlfw = new Thread(logfileWriter);
            tlfw.start();

            LogFileWriter criticalLogfileWriter = new LogFileWriter(criticalLogFileQ, System.getProperty("user.home") + "/pdns-db-validator.warn");
            Thread ctlfw = new Thread(criticalLogfileWriter);
            ctlfw.start();

            DomainUpdater domainUpdater = new DomainUpdater(domainIdQ, logFileQ, criticalLogFileQ, 40);

            // getDomainIds direkt hier
            Class.forName(DataBase.getJdbcClass());
            Connection cn = DriverManager.getConnection(DataBase.getJdbcUrl(), DataBase.getDbUser(), DataBase.getDbPass());
            PreparedStatement stAllDomainIds = cn.prepareStatement("select id from domains limit 400");
            ResultSet rsDomainIds = stAllDomainIds.executeQuery();
            while (rsDomainIds.next()) {
                domainIdQ.add(rsDomainIds.getLong(1));
                if (domainIdQ.size() > 20000) {
                    Thread.sleep(1000);
                }
            }
            System.out.println("All domain_ids queued");
            // Queue Sizes angucken
            while (domainIdQ.size() > 0) {
                System.out.println("domainIdQ size: " + domainIdQ.size());
                Thread.sleep(10000);
            }
            while (logFileQ.size() > 0) {
                System.out.println("logFileQ size: " + logFileQ.size());
                Thread.sleep(10000);
            }
            Thread.sleep(10000);
            // Shutdown einleiten
            domainUpdater.shutdown();
            logfileWriter.shutdown();
            criticalLogfileWriter.shutdown();
            Thread.sleep(1000);
            System.exit(0);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
